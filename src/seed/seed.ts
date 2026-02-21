import "dotenv/config";
import { and, eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import {
  assignments,
  assessmentQuestions,
  assessmentSections,
  assessments,
  badges,
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

async function runSeed() {
  await ensureRoles();
  await ensureBadges();
  await seedSubject(itSubject, itModules);
  await seedSubject(mathSubject, mathModules);
  await seedAssignmentsAndChecklists();
  await seedQuestionBankAndAssessmentsFromQuizzes();
}

runSeed()
  .then(() => {
    console.log("Seed complete");
  })
  .catch((error) => {
    console.error("Seed failed", error);
    process.exit(1);
  });
