import "dotenv/config";
import { seedAnnouncementsAndEvents } from "./seed.js";

export async function seedAnnouncementsEvents() {
  await seedAnnouncementsAndEvents();
}

const entrypoint = process.argv[1]?.replace(/\\/g, "/") ?? "";
const isMain = /\/seed\/seed-announcements-events(\.js|\.ts)?$/.test(entrypoint);
if (isMain) {
  seedAnnouncementsEvents()
    .then(() => {
      console.log("Announcements/events seed complete");
    })
    .catch((error) => {
      console.error("Announcements/events seed failed", error);
      process.exit(1);
    });
}
