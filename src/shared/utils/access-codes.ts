import crypto from "crypto";

const DEFAULT_PREFIX = "BEE";

function getDateStamp(date: Date) {
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  const day = String(date.getUTCDate()).padStart(2, "0");
  return `${year}${month}${day}`;
}

export function getDailyAccessCode(params: {
  moduleId: number;
  grade: number;
  order: number;
  date?: Date;
  secret?: string;
}) {
  const { moduleId, grade, order, date = new Date(), secret } = params;
  const key = secret || process.env.DAILY_ACCESS_CODE_SECRET || "beelearn-demo-secret";
  const stamp = getDateStamp(date);
  const payload = `${moduleId}:${stamp}`;
  const digest = crypto.createHmac("sha256", key).update(payload).digest("hex");
  const pin = digest.slice(0, 6).toUpperCase();
  return `${DEFAULT_PREFIX}-${grade}-${order}-${pin}`;
}

export function isDailyAccessCodeMatch(params: {
  code: string;
  moduleId: number;
  grade: number;
  order: number;
  date?: Date;
  secret?: string;
}) {
  const expected = getDailyAccessCode(params);
  return expected.toLowerCase() === params.code.trim().toLowerCase();
}
