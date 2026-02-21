import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { env } from "../config/env.js";

async function testConnection() {
  console.log("🔌 Testing Neon Database Connection\n");
  console.log("====================================");
  console.log(`Timeout: ${env.neonFetchTimeoutMs}ms`);
  console.log(`Database: ${env.databaseUrl.split('@')[1]?.split('/')[0] || 'unknown'}\n`);
  
  try {
    const startTime = Date.now();
    console.log("Connecting...");
    
    const result = await db.execute(sql`SELECT version(), current_database(), current_user;`);
    
    const elapsed = Date.now() - startTime;
    console.log(`\n✅ Connected successfully in ${elapsed}ms\n`);
    
    if (result.rows[0]) {
      console.log("Database Info:");
      console.log("==============");
      console.log(`Version: ${result.rows[0].version}`);
      console.log(`Database: ${result.rows[0].current_database}`);
      console.log(`User: ${result.rows[0].current_user}`);
    }
    
    // Test a table query
    const tableResult = await db.execute(sql`
      SELECT COUNT(*) as table_count 
      FROM information_schema.tables 
      WHERE table_schema = 'public';
    `);
    
    console.log(`\nPublic Tables: ${tableResult.rows[0]?.table_count || 0}`);
    
  } catch (error: any) {
    console.error("\n❌ Connection Failed\n");
    console.error("Error:", error.message);
    
    if (error.message?.includes('fetch failed')) {
      console.error("\n💡 Troubleshooting:");
      console.error("   1. Check your internet connection");
      console.error("   2. Verify DATABASE_URL is correct");
      console.error("   3. Ensure NEON_FETCH_TIMEOUT_MS is set (recommended: 30000)");
      console.error("   4. Check if Neon service is operational");
    }
    
    process.exit(1);
  }
  
  console.log("\n✅ Connection test complete!");
}

testConnection().catch((error) => {
  console.error("Test failed:", error);
  process.exit(1);
});
