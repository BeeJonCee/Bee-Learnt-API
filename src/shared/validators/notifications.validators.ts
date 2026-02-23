import { z } from "zod";

const contentAudienceSchema = z.enum([
  "ALL",
  "STUDENT",
  "PARENT",
  "ADMIN",
  "TUTOR",
]);

export const announcementCreateSchema = z.object({
  title: z.string().min(1).max(160),
  body: z.string().min(1),
  audience: contentAudienceSchema.default("ALL"),
  pinned: z.boolean().optional().default(false),
  publishedAt: z.string().datetime().optional(),
});

export const eventCreateSchema = z
  .object({
    title: z.string().min(1).max(160),
    description: z.string().min(1),
    startAt: z.string().datetime(),
    endAt: z.string().datetime().nullable().optional(),
    allDay: z.boolean().optional().default(false),
    location: z.string().min(1).nullable().optional(),
    audience: contentAudienceSchema.default("ALL"),
  })
  .superRefine((value, ctx) => {
    if (!value.endAt) return;

    const start = new Date(value.startAt).getTime();
    const end = new Date(value.endAt).getTime();

    if (Number.isNaN(start) || Number.isNaN(end)) return;
    if (end >= start) return;

    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["endAt"],
      message: "endAt must be after startAt",
    });
  });

export type AnnouncementCreateInput = z.infer<typeof announcementCreateSchema>;
export type EventCreateInput = z.infer<typeof eventCreateSchema>;
