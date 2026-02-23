-- Sync users from BeeLearnt -> Neon Auth users table
-- Source:  public.users (+ public.roles)
-- Target:  neon_auth."user"
--
-- Matches all compatible fields:
--   id, name, email, image, role, "createdAt", "updatedAt"
--
-- Notes:
-- 1) neon_auth."user" has fields not present in public.users
--    ("emailVerified", banned, "banReason", "banExpires").
--    On existing users, those fields are preserved.
-- 2) public.users.last_login_at has no direct column in neon_auth."user".
-- 3) If the same email exists under a different id, the script aborts before upsert.

BEGIN;

-- Abort if a source email points to a different existing Neon Auth user id.
DO $$
DECLARE
  conflict_count integer;
BEGIN
  WITH source_users AS (
    SELECT
      u.id::uuid AS id,
      lower(trim(u.email)) AS email
    FROM public.users u
    WHERE u.email IS NOT NULL
  ),
  conflicts AS (
    SELECT
      s.id AS source_id,
      s.email AS source_email,
      n.id AS target_id
    FROM source_users s
    JOIN neon_auth."user" n
      ON lower(n.email) = s.email
     AND n.id <> s.id
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
    CASE
      WHEN upper(trim(COALESCE(r.name::text, ''))) IN ('STUDENT', 'PARENT', 'ADMIN', 'TUTOR')
        THEN upper(trim(r.name::text))
      ELSE 'STUDENT'
    END AS role_name,
    COALESCE(u.created_at, now()) AS created_at,
    GREATEST(
      COALESCE(u.updated_at, u.created_at, now()),
      COALESCE(u.created_at, now())
    ) AS updated_at
  FROM public.users u
  LEFT JOIN public.roles r
    ON r.id = u.role_id
  WHERE u.email IS NOT NULL
),
upserted AS (
  INSERT INTO neon_auth."user" AS n (
    id,
    name,
    email,
    image,
    role,
    "createdAt",
    "updatedAt",
    "emailVerified",
    banned,
    "banReason",
    "banExpires"
  )
  SELECT
    s.id,
    s.name,
    s.email,
    s.image,
    s.role_name,
    s.created_at,
    s.updated_at,
    false,
    false,
    NULL,
    NULL
  FROM source_users s
  ON CONFLICT (id) DO UPDATE
  SET
    name = EXCLUDED.name,
    email = EXCLUDED.email,
    image = EXCLUDED.image,
    role = EXCLUDED.role,
    "createdAt" = LEAST(n."createdAt", EXCLUDED."createdAt"),
    "updatedAt" = GREATEST(n."updatedAt", EXCLUDED."updatedAt")
  RETURNING 1
)
SELECT COUNT(*) AS affected_rows
FROM upserted;

COMMIT;
