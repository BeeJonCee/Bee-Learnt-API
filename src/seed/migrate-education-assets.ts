import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

/**
 * Migration script for normalized education assets.
 * Adds canonical Education-folder asset tables and backfills
 * NSC/subject-resource records with education_asset_id links.
 */
export async function migrate() {
  console.log("Starting education-assets migration...");

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE education_asset_kind AS ENUM (
        'teacher_guide',
        'theory_chapter',
        'practical_guide',
        'caps_document',
        'past_paper',
        'memorandum',
        'marking_guideline',
        'answer_book',
        'data_files',
        'workbook',
        'revision_guide',
        'tutoring_guide',
        'other'
      );
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE education_asset_category AS ENUM (
        'core_content',
        'assessment',
        'supporting'
      );
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE education_asset_link_role AS ENUM (
        'teacher_guide',
        'theory_doc',
        'practical_doc',
        'worksheet',
        'past_paper',
        'memo',
        'data_files',
        'reference'
      );
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS education_chapters (
      id SERIAL PRIMARY KEY,
      subject_id INTEGER NOT NULL REFERENCES subjects(id),
      grade_id INTEGER REFERENCES grades(id),
      chapter_number INTEGER NOT NULL,
      title VARCHAR(200) NOT NULL,
      summary TEXT,
      "order" INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(subject_id, grade_id, chapter_number, title)
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS education_assets (
      id SERIAL PRIMARY KEY,
      subject_id INTEGER NOT NULL REFERENCES subjects(id),
      grade_id INTEGER REFERENCES grades(id),
      chapter_id INTEGER REFERENCES education_chapters(id),
      kind education_asset_kind NOT NULL,
      category education_asset_category NOT NULL,
      source_rel_path TEXT NOT NULL,
      source_abs_path TEXT,
      title VARCHAR(300) NOT NULL,
      mime_type VARCHAR(60),
      file_size INTEGER,
      language VARCHAR(20) NOT NULL DEFAULT 'English',
      year INTEGER,
      session exam_session,
      paper_number INTEGER,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      is_available BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(source_rel_path)
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS education_asset_links (
      id SERIAL PRIMARY KEY,
      asset_id INTEGER NOT NULL REFERENCES education_assets(id) ON DELETE CASCADE,
      chapter_id INTEGER REFERENCES education_chapters(id),
      module_id INTEGER REFERENCES modules(id),
      lesson_id INTEGER REFERENCES lessons(id),
      role education_asset_link_role NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_education_assets_subject_grade
    ON education_assets(subject_id, grade_id, category, kind);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_education_assets_year_session
    ON education_assets(year, session, paper_number);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_education_asset_links_asset
    ON education_asset_links(asset_id);
  `);

  await db.execute(sql`
    ALTER TABLE nsc_paper_documents
    ADD COLUMN IF NOT EXISTS education_asset_id INTEGER REFERENCES education_assets(id);
  `);

  await db.execute(sql`
    ALTER TABLE subject_resources
    ADD COLUMN IF NOT EXISTS education_asset_id INTEGER REFERENCES education_assets(id);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_nsc_paper_documents_education_asset
    ON nsc_paper_documents(education_asset_id);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_subject_resources_education_asset
    ON subject_resources(education_asset_id);
  `);

  await db.execute(sql`
    INSERT INTO education_assets (
      subject_id,
      grade_id,
      kind,
      category,
      source_rel_path,
      source_abs_path,
      title,
      mime_type,
      file_size,
      language,
      is_available
    )
    SELECT
      sr.subject_id,
      sr.grade_id,
      CASE sr.type::text
        WHEN 'teacher_guide' THEN 'teacher_guide'
        WHEN 'practical_guide' THEN 'practical_guide'
        WHEN 'caps_document' THEN 'caps_document'
        WHEN 'learner_data' THEN 'data_files'
        WHEN 'revision_guide' THEN 'revision_guide'
        WHEN 'workbook' THEN 'workbook'
        WHEN 'tutoring_guide' THEN 'tutoring_guide'
        ELSE 'other'
      END::education_asset_kind,
      CASE sr.type::text
        WHEN 'textbook' THEN 'core_content'
        WHEN 'teacher_guide' THEN 'core_content'
        WHEN 'practical_guide' THEN 'core_content'
        WHEN 'caps_document' THEN 'core_content'
        WHEN 'revision_guide' THEN 'supporting'
        WHEN 'workbook' THEN 'supporting'
        WHEN 'tutoring_guide' THEN 'supporting'
        ELSE 'supporting'
      END::education_asset_category,
      CASE
        WHEN sr.file_path IS NOT NULL
          AND position('/Education/' IN replace(sr.file_path, '\\', '/')) > 0
          THEN split_part(replace(sr.file_path, '\\', '/'), '/Education/', 2)
        WHEN sr.file_url IS NOT NULL THEN sr.file_url
        ELSE NULL
      END AS source_rel_path,
      sr.file_path,
      sr.title,
      sr.mime_type,
      sr.file_size,
      sr.language,
      TRUE
    FROM subject_resources sr
    WHERE
      CASE
        WHEN sr.file_path IS NOT NULL
          AND position('/Education/' IN replace(sr.file_path, '\\', '/')) > 0
          THEN split_part(replace(sr.file_path, '\\', '/'), '/Education/', 2)
        WHEN sr.file_url IS NOT NULL THEN sr.file_url
        ELSE NULL
      END IS NOT NULL
    ON CONFLICT (source_rel_path) DO NOTHING;
  `);

  await db.execute(sql`
    UPDATE subject_resources sr
    SET education_asset_id = ea.id
    FROM education_assets ea
    WHERE sr.education_asset_id IS NULL
      AND ea.source_rel_path = CASE
        WHEN sr.file_path IS NOT NULL
          AND position('/Education/' IN replace(sr.file_path, '\\', '/')) > 0
          THEN split_part(replace(sr.file_path, '\\', '/'), '/Education/', 2)
        WHEN sr.file_url IS NOT NULL THEN sr.file_url
        ELSE NULL
      END;
  `);

  await db.execute(sql`
    INSERT INTO education_assets (
      subject_id,
      grade_id,
      kind,
      category,
      source_rel_path,
      source_abs_path,
      title,
      mime_type,
      file_size,
      language,
      year,
      session,
      paper_number,
      is_available
    )
    SELECT
      p.subject_id,
      p.grade_id,
      CASE d.doc_type::text
        WHEN 'question_paper' THEN 'past_paper'
        WHEN 'memorandum' THEN 'memorandum'
        WHEN 'marking_guideline' THEN 'marking_guideline'
        WHEN 'answer_book' THEN 'answer_book'
        WHEN 'data_files' THEN 'data_files'
        ELSE 'other'
      END::education_asset_kind,
      CASE d.doc_type::text
        WHEN 'question_paper' THEN 'assessment'
        WHEN 'memorandum' THEN 'assessment'
        WHEN 'marking_guideline' THEN 'assessment'
        WHEN 'answer_book' THEN 'assessment'
        WHEN 'data_files' THEN 'assessment'
        ELSE 'supporting'
      END::education_asset_category,
      CASE
        WHEN d.file_path IS NOT NULL
          AND position('/Education/' IN replace(d.file_path, '\\', '/')) > 0
          THEN split_part(replace(d.file_path, '\\', '/'), '/Education/', 2)
        WHEN d.file_url IS NOT NULL THEN d.file_url
        ELSE NULL
      END AS source_rel_path,
      d.file_path,
      d.title,
      d.mime_type,
      d.file_size,
      d.language,
      p.year,
      p.session,
      p.paper_number,
      TRUE
    FROM nsc_paper_documents d
    INNER JOIN nsc_papers p ON p.id = d.nsc_paper_id
    WHERE
      CASE
        WHEN d.file_path IS NOT NULL
          AND position('/Education/' IN replace(d.file_path, '\\', '/')) > 0
          THEN split_part(replace(d.file_path, '\\', '/'), '/Education/', 2)
        WHEN d.file_url IS NOT NULL THEN d.file_url
        ELSE NULL
      END IS NOT NULL
    ON CONFLICT (source_rel_path) DO NOTHING;
  `);

  await db.execute(sql`
    UPDATE nsc_paper_documents d
    SET education_asset_id = ea.id
    FROM education_assets ea
    WHERE d.education_asset_id IS NULL
      AND ea.source_rel_path = CASE
        WHEN d.file_path IS NOT NULL
          AND position('/Education/' IN replace(d.file_path, '\\', '/')) > 0
          THEN split_part(replace(d.file_path, '\\', '/'), '/Education/', 2)
        WHEN d.file_url IS NOT NULL THEN d.file_url
        ELSE NULL
      END;
  `);

  console.log("education-assets migration complete!");
}

// Auto-run when executed directly (e.g. `tsx src/seed/migrate-education-assets.ts`)
const isMain = process.argv[1]?.replace(/\\/g, "/").includes("seed/migrate-");
if (isMain) {
  migrate().catch((error) => {
    console.error("Migration failed:", error);
    process.exit(1);
  });
}
