const toNumber = (value: string | undefined, fallback: number) => {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

export const env = {
  nodeEnv: process.env.NODE_ENV ?? "development",
  port: toNumber(process.env.PORT, 4000),
  // Application database (beelearnt)
  databaseUrl: process.env.DATABASE_URL ?? "",
  // Neon Auth database (neondb - separate database)
  neonAuthDatabaseUrl: process.env.NEON_AUTH_DATABASE_URL ?? "",
  neonFetchTimeoutMs: toNumber(process.env.NEON_FETCH_TIMEOUT_MS, 30000),
  betterAuthSecret: process.env.BETTER_AUTH_SECRET ?? "",
  betterAuthUrl: process.env.BETTER_AUTH_URL ?? "http://localhost:3000",
  googleClientId: process.env.GOOGLE_CLIENT_ID ?? "",
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET ?? "",
  facebookClientId: process.env.FACEBOOK_CLIENT_ID ?? "",
  facebookClientSecret: process.env.FACEBOOK_CLIENT_SECRET ?? "",
  jwtSecret: process.env.JWT_SECRET ?? "",
  openAiApiKey: process.env.OPENAI_API_KEY ?? "",
  corsOrigin: process.env.CORS_ORIGIN ?? "http://localhost:3000",
  dailyAccessCodeSecret: process.env.DAILY_ACCESS_CODE_SECRET ?? "",
  newsApiKey: process.env.NEWS_API_KEY ?? "",
  smtpHost: process.env.SMTP_HOST ?? "smtp.gmail.com",
  smtpPort: toNumber(process.env.SMTP_PORT, 587),
  smtpSecure: process.env.SMTP_SECURE === "true",
  smtpUser: process.env.SMTP_USER ?? "",
  smtpPassword: process.env.SMTP_PASSWORD ?? "",
  adminEmail: process.env.ADMIN_EMAIL ?? "admin@beelearnt.com",
  fromEmail: process.env.FROM_EMAIL ?? "auth@mail.myneon.app",
  appUrl: process.env.APP_URL ?? "http://localhost:3000",
  neonAuthBaseUrl: process.env.NEON_AUTH_BASE_URL ?? "",
};
