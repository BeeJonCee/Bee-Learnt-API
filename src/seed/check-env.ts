import "dotenv/config";
import { env } from "../config/env.js";

console.log("Environment Configuration\n");
console.log("============================");
console.log(`NODE_ENV: ${env.nodeEnv}`);
console.log(`PORT: ${env.port}`);
console.log(`DATABASE_URL: ${env.databaseUrl ? "Set" : "Missing"}`);
console.log(`NEON_FETCH_TIMEOUT_MS: ${env.neonFetchTimeoutMs}ms`);
console.log(`JWT_SECRET: ${env.jwtSecret ? "Set" : "Missing"}`);
console.log(`GOOGLE_CLIENT_ID: ${env.googleClientId ? "Set" : "Missing"}`);
console.log(`GOOGLE_CLIENT_SECRET: ${env.googleClientSecret ? "Set" : "Missing"}`);
console.log(`FACEBOOK_CLIENT_ID: ${env.facebookClientId ? "Set" : "Missing"}`);
console.log(`FACEBOOK_CLIENT_SECRET: ${env.facebookClientSecret ? "Set" : "Missing"}`);
console.log(`NEON_AUTH_BASE_URL: ${env.neonAuthBaseUrl || "Missing"}`);
console.log(`CORS_ORIGIN: ${env.corsOrigin}`);
console.log("\nConfiguration check complete.");

if (!env.databaseUrl) {
  console.error("\nERROR: DATABASE_URL is not set.");
  process.exit(1);
}

if (env.neonFetchTimeoutMs < 30000) {
  console.warn(`\nWARNING: NEON_FETCH_TIMEOUT_MS is ${env.neonFetchTimeoutMs}ms.`);
  console.warn("Recommended minimum is 30000ms (30 seconds) for Neon connections.");
}
