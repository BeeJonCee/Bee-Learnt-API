import type { Request, Response } from "express";
import * as path from "path";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { parseNumber } from "../shared/utils/parse.js";
import { getNscDocumentFile, getSubjectResourceFile } from "../services/education.service.js";

export const downloadNscDocument = asyncHandler(async (req: Request, res: Response) => {
  const documentId = parseNumber(req.params.documentId as string);
  if (!documentId) {
    res.status(400).json({ message: "Invalid document id" });
    return;
  }

  const file = await getNscDocumentFile(documentId);
  if (!file) {
    res.status(404).json({ message: "Document not found" });
    return;
  }

  const ext = path.extname(file.absolutePath);
  const safeFileName = file.fileName.endsWith(ext)
    ? file.fileName
    : `${file.fileName}${ext}`;

  res.setHeader("Content-Type", file.mimeType);
  res.setHeader("Content-Disposition", `inline; filename="${safeFileName}"`);
  res.sendFile(file.absolutePath);
});

export const downloadSubjectResource = asyncHandler(async (req: Request, res: Response) => {
  const resourceId = parseNumber(req.params.resourceId as string);
  if (!resourceId) {
    res.status(400).json({ message: "Invalid resource id" });
    return;
  }

  const file = await getSubjectResourceFile(resourceId);
  if (!file) {
    res.status(404).json({ message: "Resource not found" });
    return;
  }

  const ext = path.extname(file.absolutePath);
  const safeFileName = file.fileName.endsWith(ext)
    ? file.fileName
    : `${file.fileName}${ext}`;

  res.setHeader("Content-Type", file.mimeType);
  res.setHeader("Content-Disposition", `inline; filename="${safeFileName}"`);
  res.sendFile(file.absolutePath);
});
