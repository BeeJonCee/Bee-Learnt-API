import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

/**
 * Migration script to create curriculum hierarchy and NSC past papers tables.
 * This sets up the foundation for organizing content by curriculum, grades, topics,
 * and NSC past paper documents.
 */
async function migrate() {
  console.log("Starting curriculum and NSC papers migration...");

  // ============ ENUMS ============

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE exam_session AS ENUM (
        'november',
        'may_june',
        'february_march',
        'supplementary',
        'exemplar'
      );
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE paper_doc_type AS ENUM (
        'question_paper',
        'memorandum',
        'marking_guideline',
        'answer_book',
        'data_files',
        'addendum',
        'formula_sheet'
      );
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE day_of_week AS ENUM (
        'monday',
        'tuesday',
        'wednesday',
        'thursday',
        'friday',
        'saturday',
        'sunday'
      );
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  // ============ CURRICULUM HIERARCHY ============

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS curricula (
      id serial PRIMARY KEY,
      name varchar(120) NOT NULL,
      country varchar(60) NOT NULL,
      description text,
      is_active boolean NOT NULL DEFAULT true,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(name, country)
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS grades (
      id serial PRIMARY KEY,
      curriculum_id integer NOT NULL REFERENCES curricula(id),
      level integer NOT NULL,
      label varchar(40) NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(curriculum_id, level)
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS topics (
      id serial PRIMARY KEY,
      subject_id integer NOT NULL REFERENCES subjects(id),
      grade_id integer NOT NULL REFERENCES grades(id),
      parent_topic_id integer REFERENCES topics(id),
      title varchar(200) NOT NULL,
      description text,
      term_number integer,
      caps_reference varchar(80),
      "order" integer NOT NULL DEFAULT 0,
      weighting integer,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_topics_subject_grade
    ON topics(subject_id, grade_id, term_number);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_topics_parent
    ON topics(parent_topic_id);
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS learning_outcomes (
      id serial PRIMARY KEY,
      topic_id integer NOT NULL REFERENCES topics(id),
      code varchar(40),
      description text NOT NULL,
      blooms_level varchar(20),
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_learning_outcomes_topic
    ON learning_outcomes(topic_id);
  `);

  // ============ NSC PAST PAPERS ============

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS nsc_papers (
      id serial PRIMARY KEY,
      subject_id integer NOT NULL REFERENCES subjects(id),
      grade_id integer REFERENCES grades(id),
      year integer NOT NULL,
      session exam_session NOT NULL,
      paper_number integer NOT NULL,
      language varchar(20) NOT NULL DEFAULT 'English',
      total_marks integer,
      duration_minutes integer,
      is_processed boolean NOT NULL DEFAULT false,
      metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(subject_id, year, session, paper_number, language)
    );
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_nsc_papers_subject_year
    ON nsc_papers(subject_id, year, session, paper_number);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_nsc_papers_year_desc
    ON nsc_papers(year DESC);
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS nsc_paper_documents (
      id serial PRIMARY KEY,
      nsc_paper_id integer NOT NULL REFERENCES nsc_papers(id) ON DELETE CASCADE,
      doc_type paper_doc_type NOT NULL,
      title varchar(300) NOT NULL,
      file_url text NOT NULL,
      file_path text,
      file_size integer,
      mime_type varchar(60),
      language varchar(20) NOT NULL DEFAULT 'English',
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_nsc_paper_documents_paper
    ON nsc_paper_documents(nsc_paper_id, doc_type);
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS nsc_paper_questions (
      id serial PRIMARY KEY,
      nsc_paper_id integer NOT NULL REFERENCES nsc_papers(id) ON DELETE CASCADE,
      question_number varchar(20) NOT NULL,
      question_text text NOT NULL,
      marks integer NOT NULL,
      topic_id integer REFERENCES topics(id),
      section_label varchar(60),
      image_url text,
      memo_text text,
      metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_nsc_paper_questions_paper
    ON nsc_paper_questions(nsc_paper_id, question_number);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_nsc_paper_questions_topic
    ON nsc_paper_questions(topic_id);
  `);

  // ============ MESSAGING ============

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS direct_messages (
      id serial PRIMARY KEY,
      sender_id uuid NOT NULL REFERENCES users(id),
      recipient_id uuid NOT NULL REFERENCES users(id),
      subject varchar(200),
      content text NOT NULL,
      read_at timestamptz,
      deleted_by_sender boolean NOT NULL DEFAULT false,
      deleted_by_recipient boolean NOT NULL DEFAULT false,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_direct_messages_recipient
    ON direct_messages(recipient_id, read_at);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_direct_messages_sender
    ON direct_messages(sender_id, created_at);
  `);

  // ============ TIMETABLE ============

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS timetable_entries (
      id serial PRIMARY KEY,
      user_id uuid NOT NULL REFERENCES users(id),
      subject_id integer REFERENCES subjects(id),
      title varchar(160) NOT NULL,
      day_of_week day_of_week NOT NULL,
      start_time varchar(5) NOT NULL,
      end_time varchar(5) NOT NULL,
      location varchar(120),
      color varchar(7),
      is_recurring boolean NOT NULL DEFAULT true,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_timetable_entries_user
    ON timetable_entries(user_id, day_of_week);
  `);

  // ============ TOPIC MASTERY ============

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS topic_mastery (
      id serial PRIMARY KEY,
      user_id uuid NOT NULL REFERENCES users(id),
      topic_id integer NOT NULL REFERENCES topics(id),
      total_questions integer NOT NULL DEFAULT 0,
      correct_answers integer NOT NULL DEFAULT 0,
      mastery_percent integer NOT NULL DEFAULT 0,
      last_attempt_at timestamptz,
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(user_id, topic_id)
    );
  `);

  // ============ RUBRICS ============

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS rubrics (
      id serial PRIMARY KEY,
      title varchar(200) NOT NULL,
      subject_id integer REFERENCES subjects(id),
      criteria jsonb NOT NULL,
      created_by uuid REFERENCES users(id),
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  // Add foreign key constraints to question_bank_items now that topics and learning_outcomes exist
  await db.execute(sql`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE constraint_name = 'question_bank_items_topic_id_fkey'
      ) THEN
        ALTER TABLE question_bank_items
          ADD CONSTRAINT question_bank_items_topic_id_fkey
          FOREIGN KEY (topic_id) REFERENCES topics(id);
      END IF;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE constraint_name = 'question_bank_items_learning_outcome_id_fkey'
      ) THEN
        ALTER TABLE question_bank_items
          ADD CONSTRAINT question_bank_items_learning_outcome_id_fkey
          FOREIGN KEY (learning_outcome_id) REFERENCES learning_outcomes(id);
      END IF;
    END $$;
  `);

  console.log("Migration complete: curriculum hierarchy and NSC papers tables created.");
}

migrate().catch((error) => {
  console.error("Migration failed", error);
  process.exit(1);
});
