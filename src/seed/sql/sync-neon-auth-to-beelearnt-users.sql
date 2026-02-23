-- Sync users from Neon Auth -> BeeLearnt users table
-- Source:  neon_auth."user"
-- Target:  public.users
--
-- Matches all compatible fields:
--   id, name, email, image, created_at, updated_at, role_id
--
-- Notes:
-- 1) public.users.last_login_at is derived from neon_auth.session
--    as the latest createdAt/updatedAt per user.
-- 2) role_id is resolved from public.roles using neon_auth."user".role.
--    Missing/invalid roles default to STUDENT.
-- 3) If the same email exists under a different id, the script aborts before upsert.

BEGIN;

-- Ensure expected roles exist.
INSERT INTO public.roles (name, description)
VALUES
  ('STUDENT', 'Student role'),
  ('PARENT',  'Parent role'),
  ('ADMIN',   'Admin role'),
  ('TUTOR',   'Tutor role')
ON CONFLICT (name) DO NOTHING;

-- Abort if a source email points to a different existing user id.
DO $$
DECLARE
  conflict_count integer;
BEGIN
  WITH source_users AS (
    SELECT
      u.id::uuid AS id,
      lower(trim(u.email)) AS email
    FROM neon_auth."user" u
    WHERE u.email IS NOT NULL
  ),
  conflicts AS (
    SELECT
      s.id AS source_id,
      s.email AS source_email,
      b.id AS target_id
    FROM source_users s
    JOIN public.users b
      ON lower(b.email) = s.email
     AND b.id <> s.id
  )
  SELECT COUNT(*) INTO conflict_count
  FROM conflicts;

  IF conflict_count > 0 THEN
    RAISE EXCEPTION
      'Sync aborted: % email conflict(s) found where email maps to a different user id.',
      conflict_count;
  END IF;
END $$;

WITH source_users AS (
  SELECT
    u.id::uuid AS id,
    COALESCE(NULLIF(trim(u.name), ''), split_part(lower(trim(u.email)), '@', 1)) AS name,
    lower(trim(u.email)) AS email,
    u.image AS image,
    COALESCE(NULLIF(upper(trim(u.role)), ''), 'STUDENT') AS role_name,
    COALESCE(u."createdAt", now()) AS created_at,
    COALESCE(u."updatedAt", u."createdAt", now()) AS updated_at
  FROM neon_auth."user" u
  WHERE u.email IS NOT NULL
),
role_lookup AS (
  SELECT
    r.id,
    r.name::text AS role_name
  FROM public.roles r
),
last_logins AS (
  SELECT
    s."userId"::uuid AS id,
    MAX(COALESCE(s."updatedAt", s."createdAt")) AS last_login_at
  FROM neon_auth.session s
  GROUP BY s."userId"::uuid
),
prepared AS (
  SELECT
    s.id,
    s.name,
    s.email,
    s.image,
    COALESCE(rl.id, student_role.id) AS role_id,
    s.created_at,
    GREATEST(s.updated_at, s.created_at) AS updated_at,
    ll.last_login_at
  FROM source_users s
  LEFT JOIN role_lookup rl
    ON rl.role_name = s.role_name
  LEFT JOIN last_logins ll
    ON ll.id = s.id
  CROSS JOIN LATERAL (
    SELECT id
    FROM public.roles
    WHERE name = 'STUDENT'
    LIMIT 1
  ) AS student_role
),
upserted AS (
  INSERT INTO public.users AS b (
    id,
    name,
    email,
    image,
    role_id,
    created_at,
    updated_at,
    last_login_at
  )
  SELECT
    p.id,
    p.name,
    p.email,
    p.image,
    p.role_id,
    p.created_at,
    p.updated_at,
    p.last_login_at
  FROM prepared p
  ON CONFLICT (id) DO UPDATE
  SET
    name = EXCLUDED.name,
    email = EXCLUDED.email,
    image = EXCLUDED.image,
    role_id = EXCLUDED.role_id,
    created_at = LEAST(b.created_at, EXCLUDED.created_at),
    updated_at = GREATEST(b.updated_at, EXCLUDED.updated_at),
    last_login_at = COALESCE(
      GREATEST(b.last_login_at, EXCLUDED.last_login_at),
      b.last_login_at,
      EXCLUDED.last_login_at
    )
  RETURNING 1
)
SELECT COUNT(*) AS affected_rows
FROM upserted;

COMMIT;
