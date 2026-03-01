import { neon } from "@neondatabase/serverless";
import * as dotenv from "dotenv";

dotenv.config();

const sql = neon(process.env.DATABASE_URL!);

async function main() {
  console.log("Adding phone column to users table...");
  await sql`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS phone varchar(30) UNIQUE;
  `;
  console.log("Done.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
