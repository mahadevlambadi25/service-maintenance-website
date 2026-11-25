import { getDb, closeDb } from './database.js';
import { seedDatabase } from './seed.js';

async function main() {
  const db = await getDb(null, undefined, { forceMigrate: true });
  await seedDatabase(db);
  console.log(`Database migration and idempotent seed complete (dialect=${db.dialect}).`);
  await closeDb();
}

main().catch((err) => {
  console.error('Migration failed:', err);
  process.exit(1);
});
