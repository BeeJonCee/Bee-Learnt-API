import { z } from "zod";

export const subjectResourceQuerySchema = z.object({
  subjectId: z.coerce.number().int().positive().optional(),
  gradeId: z.coerce.number().int().positive().optional(),
  type: z
    .enum([
      "textbook",
      "teacher_guide",
      "practical_guide",
      "pat_document",
      "caps_document",
      "learner_data",
      "revision_guide",
      "workbook",
      "tutoring_guide",
    ])
    .optional(),
});

export const subjectResourceCreateSchema = z.object({
  subjectId: z.number().int().positive(),
  gradeId: z.number().int().positive().optional().nullable(),
  title: z.string().min(1).max(300),
  type: z.enum([
    "textbook",
    "teacher_guide",
    "practical_guide",
    "pat_document",
    "caps_document",
    "learner_data",
    "revision_guide",
    "workbook",
    "tutoring_guide",
  ]),
  fileUrl: z.string().min(1),
  filePath: z.string().optional().nullable(),
  fileSize: z.number().int().optional().nullable(),
  mimeType: z.string().max(60).optional().nullable(),
  language: z.string().max(20).default("English"),
  description: z.string().optional().nullable(),
});
