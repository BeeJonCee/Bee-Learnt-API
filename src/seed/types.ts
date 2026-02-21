export type LessonSeed = {
  title: string;
  content: string;
  type: "text" | "video" | "diagram" | "pdf";
  order: number;
  videoUrl?: string | null;
  diagramUrl?: string | null;
  pdfUrl?: string | null;
};

export type QuizQuestionSeed = {
  questionText: string;
  type: "multiple_choice" | "short_answer" | "essay";
  options?: string[] | null;
  correctAnswer?: string | null;
  explanation?: string | null;
  points?: number;
};

export type QuizSeed = {
  title: string;
  description: string;
  difficulty?: "easy" | "medium" | "hard" | "adaptive";
  questions: QuizQuestionSeed[];
};

export type AssignmentTemplateSeed = {
  title: string;
  description: string;
  priority?: "low" | "medium" | "high";
};

export type ModuleSeed = {
  key: string;
  title: string;
  description: string;
  grade: number;
  order: number;
  capsTags?: string[];
  lessons: LessonSeed[];
  assignmentTemplates?: AssignmentTemplateSeed[];
  quiz?: QuizSeed;
};

export type SubjectSeed = {
  name: string;
  description: string;
  minGrade: number;
  maxGrade: number;
};
