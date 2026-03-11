import "dotenv/config";
import { and, eq, sql } from "drizzle-orm";
import { db } from "../core/database/index.js";
import {
  announcements,
  assignments,
  assessmentQuestions,
  assessmentSections,
  assessments,
  badges,
  educationChapters,
  events,
  grades,
  questionBankItems,
  lessons,
  moduleChecklistItems,
  modules,
  quizQuestions,
  quizzes,
  roles,
  subjects,
} from "../core/database/schema/index.js";
import { subject as itSubject, allModules as itModules } from "./data/information-technology.js";
import { subject as mathSubject, allModules as mathModules } from "./data/mathematics.js";
import type {
  AssignmentTemplateSeed,
  LessonSeed,
  ModuleSeed,
  QuizSeed,
  SubjectSeed,
} from "./types.js";

const MIN_QUIZ_QUESTION_COUNT = 20;
type ContentAudience = "ALL" | "STUDENT" | "PARENT" | "ADMIN" | "TUTOR";

const moduleSeedBySubjectAndTitle = new Map<string, ModuleSeed>([
  ...itModules.map((seed) => [`${itSubject.name}::${seed.title}`, seed] as const),
  ...mathModules.map((seed) => [`${mathSubject.name}::${seed.title}`, seed] as const),
]);

function buildDefaultAssignmentTemplates(moduleTitle: string): AssignmentTemplateSeed[] {
  return [
    {
      title: `${moduleTitle} Practical Task`,
      description: "Complete the practical task and submit your working files.",
      priority: "high",
    },
    {
      title: `${moduleTitle} Revision Worksheet`,
      description: "Revise core concepts and answer the worksheet questions.",
      priority: "medium",
    },
    {
      title: `${moduleTitle} Exam-Style Coding Drill`,
      description: "Complete a timed code drill and annotate your logic in short steps.",
      priority: "high",
    },
    {
      title: `${moduleTitle} Memo Reflection`,
      description: "Review memo-style solutions and write corrections for your top 3 mistakes.",
      priority: "medium",
    },
  ];
}

function offsetDate(daysOffset: number, hour: number, minute = 0) {
  const value = new Date();
  value.setDate(value.getDate() + daysOffset);
  value.setHours(hour, minute, 0, 0);
  return value;
}

async function upsertSubject(seed: SubjectSeed) {
  const [existing] = await db
    .select()
    .from(subjects)
    .where(eq(subjects.name, seed.name));
  if (existing) return existing;

  const [created] = await db
    .insert(subjects)
    .values({
      name: seed.name,
      description: seed.description,
      minGrade: seed.minGrade,
      maxGrade: seed.maxGrade,
    })
    .returning();

  return created;
}

async function upsertModule(subjectId: number, seed: ModuleSeed) {
  const [existing] = await db
    .select()
    .from(modules)
    .where(and(eq(modules.subjectId, subjectId), eq(modules.title, seed.title)));
  if (existing) return existing;

  const [created] = await db
    .insert(modules)
    .values({
      subjectId,
      title: seed.title,
      description: seed.description,
      grade: seed.grade,
      order: seed.order,
      capsTags: seed.capsTags ?? [],
    })
    .returning();

  return created;
}

async function upsertLesson(moduleId: number, seed: LessonSeed) {
  const [existing] = await db
    .select()
    .from(lessons)
    .where(and(eq(lessons.moduleId, moduleId), eq(lessons.title, seed.title)));
  if (existing) return existing;

  const [created] = await db
    .insert(lessons)
    .values({
      moduleId,
      title: seed.title,
      content: seed.content,
      type: seed.type,
      videoUrl: seed.videoUrl ?? null,
      diagramUrl: seed.diagramUrl ?? null,
      pdfUrl: seed.pdfUrl ?? null,
      order: seed.order,
    })
    .returning();

  return created;
}

async function upsertQuiz(moduleId: number, seed: QuizSeed) {
  const [existing] = await db
    .select()
    .from(quizzes)
    .where(and(eq(quizzes.moduleId, moduleId), eq(quizzes.title, seed.title)));
  const quizRow =
    existing ??
    (
      await db
        .insert(quizzes)
        .values({
          moduleId,
          title: seed.title,
          description: seed.description,
          difficulty: seed.difficulty ?? "medium",
          source: "manual",
        })
        .returning()
    )[0];

  if (seed.questions.length === 0) return quizRow;

  const currentQuestions = await db
    .select({ id: quizQuestions.id })
    .from(quizQuestions)
    .where(eq(quizQuestions.quizId, quizRow.id));

  const currentCount = currentQuestions.length;
  const targetCount = Math.max(MIN_QUIZ_QUESTION_COUNT, seed.questions.length);
  const missingCount = targetCount - currentCount;

  if (missingCount <= 0) return quizRow;

  await db.insert(quizQuestions).values(
    Array.from({ length: missingCount }, (_, offset) => {
      const source = seed.questions[(currentCount + offset) % seed.questions.length];
      const sequence = currentCount + offset + 1;
      return {
        quizId: quizRow.id,
        type: source.type,
        questionText:
          sequence <= seed.questions.length
            ? source.questionText
            : `${source.questionText} (Practice ${sequence})`,
        options: source.options ?? null,
        correctAnswer: source.correctAnswer ?? null,
        explanation: source.explanation ?? null,
        points: source.points ?? 1,
      };
    })
  );

  return quizRow;
}

async function seedSubject(subjectSeed: SubjectSeed, moduleSeeds: ModuleSeed[]) {
  const subjectRow = await upsertSubject(subjectSeed);

  for (const moduleSeed of moduleSeeds) {
    const moduleRow = await upsertModule(subjectRow.id, moduleSeed);

    for (const lessonSeed of moduleSeed.lessons) {
      await upsertLesson(moduleRow.id, lessonSeed);
    }

    if (moduleSeed.quiz) {
      await upsertQuiz(moduleRow.id, moduleSeed.quiz);
    }
  }
}

async function ensureRoles() {
  const roleSeeds = [
    { name: "STUDENT", description: "Student role - learners accessing CAPS-aligned content" },
    { name: "PARENT", description: "Parent role - monitors child progress and receives insights" },
    { name: "TUTOR", description: "Tutor role - manages tutoring sessions and supports learners" },
    { name: "ADMIN", description: "Admin role - manages platform content and users" },
  ];

  for (const seed of roleSeeds) {
    const [existing] = await db.select().from(roles).where(eq(roles.name, seed.name as any));
    if (!existing) {
      await db.insert(roles).values({
        name: seed.name as any,
        description: seed.description,
      });
    }
  }
}

async function ensureBadges() {
  const badgeSeeds = [
    {
      name: "Focus Streak",
      description: "Maintain a 5-day learning streak.",
      ruleKey: "lesson_streak",
      criteria: { streak: 5 },
    },
    {
      name: "Quiz Accelerator",
      description: "Score 80% or higher on three quizzes.",
      ruleKey: "quiz_mastery",
      criteria: { score: 80, attempts: 3 },
    },
    {
      name: "Assignment Finisher",
      description: "Submit 5 assignments on time.",
      ruleKey: "assignment_finisher",
      criteria: { assignments: 5 },
    },
    {
      name: "Study Marathon",
      description: "Accumulate 300 minutes of study time.",
      ruleKey: "study_time",
      criteria: { minutes: 300 },
    },
  ];

  for (const seed of badgeSeeds) {
    const [existing] = await db.select().from(badges).where(eq(badges.name, seed.name));
    if (!existing) {
      await db.insert(badges).values({
        name: seed.name,
        description: seed.description,
        ruleKey: seed.ruleKey as any,
        criteria: seed.criteria,
      });
    }
  }
}

async function ensureEducationChapters() {
  const [itRow] = await db.select().from(subjects).where(eq(subjects.name, "Information Technology")).limit(1);
  if (!itRow) return;

  const gradeRows = await db
    .select({ id: grades.id, level: grades.level })
    .from(grades)
    .where(sql`${grades.level} IN (10, 11, 12)`);

  const gradeIdByLevel = new Map(gradeRows.map((row) => [row.level, row.id]));
  if (!gradeIdByLevel.size) return;

  const chapters = [
    {
      gradeLevel: 10,
      chapterNumber: 1,
      title: "Basic Concepts of Computing",
      summary: "General computer model, hardware/software, computer types, and IPO fundamentals.",
      order: 1,
    },
    {
      gradeLevel: 10,
      chapterNumber: 2,
      title: "Data Representation, Storage and Social Implications",
      summary: "Data-information-knowledge, number systems, file handling basics, and digital ethics.",
      order: 2,
    },
    {
      gradeLevel: 11,
      chapterNumber: 1,
      title: "Hardware",
      summary: "Motherboard architecture, memory/cache, and performance optimization.",
      order: 1,
    },
    {
      gradeLevel: 11,
      chapterNumber: 2,
      title: "Software",
      summary: "OS types, compiler/interpreter flow, processing models, and virtualization.",
      order: 2,
    },
    {
      gradeLevel: 12,
      chapterNumber: 1,
      title: "Database Management",
      summary: "Data collection, warehousing, mining, and data-quality controls.",
      order: 1,
    },
    {
      gradeLevel: 12,
      chapterNumber: 2,
      title: "Database Design Concepts",
      summary: "Good database characteristics, anomalies, normalization, and key structures.",
      order: 2,
    },
  ] as const;

  for (const chapter of chapters) {
    const gradeId = gradeIdByLevel.get(chapter.gradeLevel);
    if (!gradeId) continue;

    const [existing] = await db
      .select({ id: educationChapters.id })
      .from(educationChapters)
      .where(
        and(
          eq(educationChapters.subjectId, itRow.id),
          eq(educationChapters.gradeId, gradeId),
          eq(educationChapters.chapterNumber, chapter.chapterNumber),
        ),
      )
      .limit(1);

    if (existing) {
      await db
        .update(educationChapters)
        .set({
          title: chapter.title,
          summary: chapter.summary,
          order: chapter.order,
          updatedAt: new Date(),
        })
        .where(eq(educationChapters.id, existing.id));
      continue;
    }

    await db.insert(educationChapters).values({
      subjectId: itRow.id,
      gradeId,
      chapterNumber: chapter.chapterNumber,
      title: chapter.title,
      summary: chapter.summary,
      order: chapter.order,
    });
  }
}

export async function seedAnnouncementsAndEvents() {
  const announcementSeeds: Array<{
    title: string;
    body: string;
    audience: ContentAudience;
    pinned?: boolean;
    publishedAt: Date;
  }> = [
    {
      title: "Welcome to BeeLearnt",
      body: "Your dashboards now include role-specific updates, events, and study prompts.",
      audience: "ALL",
      pinned: true,
      publishedAt: offsetDate(-1, 7),
    },
    {
      title: "Weekly focus: consistency beats cramming",
      body: "Plan 30-45 minute sessions each day this week and track your progress in the dashboard.",
      audience: "ALL",
      publishedAt: offsetDate(-2, 8),
    },
    {
      title: "Student challenge: score 80%+ in your next quiz",
      body: "Complete one module quiz and review explanations for every missed question.",
      audience: "STUDENT",
      publishedAt: offsetDate(-1, 15),
    },
    {
      title: "Parent snapshot is live",
      body: "Open the Parent dashboard for recent activity, assignment status, and study streak summaries.",
      audience: "PARENT",
      publishedAt: offsetDate(-1, 14),
    },
    {
      title: "Tutor planning checklist updated",
      body: "Use weekly scheduling tools to group learners by topic mastery before your next session.",
      audience: "TUTOR",
      publishedAt: offsetDate(-1, 13),
    },
    {
      title: "Admin review queue refreshed",
      body: "New moderation and content review items are ready in Admin analytics and reports.",
      audience: "ADMIN",
      publishedAt: offsetDate(-1, 12),
    },
  ];

  for (const seed of announcementSeeds) {
    const [existing] = await db
      .select({ id: announcements.id })
      .from(announcements)
      .where(and(eq(announcements.title, seed.title), eq(announcements.audience, seed.audience)))
      .limit(1);

    if (existing) {
      await db
        .update(announcements)
        .set({
          body: seed.body,
          pinned: seed.pinned ?? false,
          publishedAt: seed.publishedAt,
          updatedAt: new Date(),
        })
        .where(eq(announcements.id, existing.id));
      continue;
    }

    await db.insert(announcements).values({
      title: seed.title,
      body: seed.body,
      audience: seed.audience,
      pinned: seed.pinned ?? false,
      publishedAt: seed.publishedAt,
    });
  }

  const eventSeeds: Array<{
    title: string;
    description: string;
    startAt: Date;
    endAt?: Date | null;
    allDay?: boolean;
    location?: string | null;
    audience: ContentAudience;
  }> = [
    {
      title: "Live study sprint kickoff",
      description: "Join a focused 60-minute session with quick revision prompts and Q&A.",
      startAt: offsetDate(1, 18, 0),
      endAt: offsetDate(1, 19, 0),
      location: "Online classroom",
      audience: "ALL",
    },
    {
      title: "Exam readiness clinic",
      description: "Strategies for pacing, question selection, and reducing common exam mistakes.",
      startAt: offsetDate(3, 16, 30),
      endAt: offsetDate(3, 17, 45),
      location: "Main campus hall",
      audience: "STUDENT",
    },
    {
      title: "Parent progress check-in",
      description: "Walkthrough of weekly performance insights and how to support home study routines.",
      startAt: offsetDate(4, 19, 0),
      endAt: offsetDate(4, 20, 0),
      location: "Virtual webinar",
      audience: "PARENT",
    },
    {
      title: "Tutor planning huddle",
      description: "Align tutoring plans with upcoming assessments and identify learners at risk.",
      startAt: offsetDate(5, 15, 0),
      endAt: offsetDate(5, 16, 0),
      location: "Staff room 2",
      audience: "TUTOR",
    },
    {
      title: "Admin operations sync",
      description: "Review platform activity, announcements performance, and system health actions.",
      startAt: offsetDate(6, 10, 0),
      endAt: offsetDate(6, 10, 45),
      location: "Admin board room",
      audience: "ADMIN",
    },
  ];

  for (const seed of eventSeeds) {
    const [existing] = await db
      .select({ id: events.id })
      .from(events)
      .where(and(eq(events.title, seed.title), eq(events.audience, seed.audience)))
      .limit(1);

    if (existing) {
      await db
        .update(events)
        .set({
          description: seed.description,
          startAt: seed.startAt,
          endAt: seed.endAt ?? null,
          allDay: seed.allDay ?? false,
          location: seed.location ?? null,
          updatedAt: new Date(),
        })
        .where(eq(events.id, existing.id));
      continue;
    }

    await db.insert(events).values({
      title: seed.title,
      description: seed.description,
      startAt: seed.startAt,
      endAt: seed.endAt ?? null,
      allDay: seed.allDay ?? false,
      location: seed.location ?? null,
      audience: seed.audience,
    });
  }
}

async function seedAssignmentsAndChecklists() {
  const allModules = await db
    .select({
      id: modules.id,
      title: modules.title,
      grade: modules.grade,
      subjectName: subjects.name,
    })
    .from(modules)
    .innerJoin(subjects, eq(modules.subjectId, subjects.id));
  const dueDate = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000);

  for (const moduleRow of allModules) {
    const moduleSeed = moduleSeedBySubjectAndTitle.get(
      `${moduleRow.subjectName}::${moduleRow.title}`
    );
    const assignmentSeeds =
      moduleSeed?.assignmentTemplates?.length
        ? moduleSeed.assignmentTemplates
        : buildDefaultAssignmentTemplates(moduleRow.title);

    for (const seed of assignmentSeeds) {
      const [existing] = await db
        .select()
        .from(assignments)
        .where(
          and(eq(assignments.moduleId, moduleRow.id), eq(assignments.title, seed.title))
        );
      if (!existing) {
        await db.insert(assignments).values({
          moduleId: moduleRow.id,
          lessonId: null,
          title: seed.title,
          description: seed.description,
          dueDate,
          priority: seed.priority as any,
          status: "todo",
          grade: moduleRow.grade,
          reminders: [],
          createdBy: null,
        });
      }
    }

    const checklistSeeds = [
      { title: "Review lesson notes", order: 1 },
      { title: "Complete practice activity", order: 2 },
      { title: "Attempt the module quiz", order: 3 },
    ];

    for (const seed of checklistSeeds) {
      const [existing] = await db
        .select()
        .from(moduleChecklistItems)
        .where(
          and(
            eq(moduleChecklistItems.moduleId, moduleRow.id),
            eq(moduleChecklistItems.title, seed.title)
          )
        );
      if (!existing) {
        await db.insert(moduleChecklistItems).values({
          moduleId: moduleRow.id,
          title: seed.title,
          order: seed.order,
          required: true,
        });
      }
    }
  }
}

async function seedQuestionBankAndAssessmentsFromQuizzes() {
  // Build a stable mapping from existing quiz questions into question_bank_items.
  // This makes the new assessment engine usable immediately with existing seed data.
  const quizRows = await db
    .select({
      quizId: quizzes.id,
      quizTitle: quizzes.title,
      quizDescription: quizzes.description,
      moduleId: quizzes.moduleId,
      subjectId: modules.subjectId,
      grade: modules.grade,
    })
    .from(quizzes)
    .innerJoin(modules, eq(quizzes.moduleId, modules.id));

  for (const quiz of quizRows) {
    const questions = await db
      .select()
      .from(quizQuestions)
      .where(eq(quizQuestions.quizId, quiz.quizId))
      .orderBy(quizQuestions.id);

    if (questions.length === 0) continue;

    const qbIdsByQuizQuestionId = new Map<number, number>();

    for (const question of questions) {
      const sourceRef = `quiz:${quiz.quizId}:question:${question.id}`;

      const [existingQb] = await db
        .select({ id: questionBankItems.id })
        .from(questionBankItems)
        .where(
          and(
            eq(questionBankItems.source, "imported"),
            eq(questionBankItems.sourceReference, sourceRef)
          )
        )
        .limit(1);

      if (existingQb) {
        qbIdsByQuizQuestionId.set(question.id, existingQb.id);
        continue;
      }

      const [createdQb] = await db
        .insert(questionBankItems)
        .values({
          subjectId: quiz.subjectId,
          moduleId: quiz.moduleId,
          type: question.type,
          difficulty: "medium",
          questionText: question.questionText,
          options: question.options ?? null,
          correctAnswer: question.correctAnswer ?? null,
          explanation: question.explanation ?? null,
          points: question.points ?? 1,
          source: "imported",
          sourceReference: sourceRef,
          tags: [],
          language: "en",
          isActive: true,
        })
        .returning();

      qbIdsByQuizQuestionId.set(question.id, createdQb.id);
    }

    const [existingAssessment] = await db
      .select({ id: assessments.id })
      .from(assessments)
      .where(
        and(
          eq(assessments.type, "quiz"),
          eq(assessments.moduleId, quiz.moduleId),
          eq(assessments.title, quiz.quizTitle)
        )
      )
      .limit(1);

    if (existingAssessment) continue;

    const [createdAssessment] = await db
      .insert(assessments)
      .values({
        title: quiz.quizTitle,
        description: quiz.quizDescription ?? null,
        type: "quiz",
        status: "published",
        subjectId: quiz.subjectId,
        grade: quiz.grade ?? null,
        moduleId: quiz.moduleId,
        showResultsImmediately: true,
        showCorrectAnswers: true,
        showExplanations: true,
      })
      .returning();

    const [createdSection] = await db
      .insert(assessmentSections)
      .values({
        assessmentId: createdAssessment.id,
        title: "Questions",
        instructions: null,
        order: 1,
      })
      .returning();

    await db.insert(assessmentQuestions).values(
      questions.map((question, index) => ({
        assessmentId: createdAssessment.id,
        sectionId: createdSection.id,
        questionBankItemId: qbIdsByQuizQuestionId.get(question.id)!,
        order: index + 1,
        overridePoints: question.points ?? 1,
      }))
    );
  }
}

export async function seed() {
  await ensureRoles();
  await ensureBadges();
  await seedAnnouncementsAndEvents();
  await seedSubject(itSubject, itModules);
  await seedSubject(mathSubject, mathModules);
  await ensureEducationChapters();
  await seedAssignmentsAndChecklists();
  await seedQuestionBankAndAssessmentsFromQuizzes();
}

// Auto-run when executed directly (e.g. `tsx src/seed/seed.ts`)
const entrypoint = process.argv[1]?.replace(/\\/g, "/") ?? "";
const isMain = /\/seed\/seed(\.js|\.ts)?$/.test(entrypoint);
if (isMain) {
  seed()
    .then(() => {
      console.log("Seed complete");
    })
    .catch((error) => {
      console.error("Seed failed", error);
      process.exit(1);
    });
}
