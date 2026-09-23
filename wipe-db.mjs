/**
 * Destructive: empties every collection in the app database.
 *
 * Prints the target and the counts BEFORE touching anything, so the thing being
 * destroyed is visible rather than assumed. Scoped to the database in MONGO_URI
 * — it never drops a database or walks the cluster.
 */
import mongoose from 'mongoose'
import { env } from './src/config/env.js'

await mongoose.connect(env.mongoUri)
const db = mongoose.connection.db
console.log(`database: ${db.databaseName}`)

const collections = await db.listCollections().toArray()
if (!collections.length) console.log('  (no collections)')

const before = []
for (const { name } of collections) {
  before.push([name, await db.collection(name).countDocuments()])
}
for (const [name, n] of before) console.log(`  ${name}: ${n} document(s)`)

if (process.argv[2] !== '--yes') {
  console.log('\nDry run. Re-run with --yes to delete.')
  await mongoose.disconnect()
  process.exit(0)
}

let total = 0
for (const [name] of before) {
  const r = await db.collection(name).deleteMany({})
  total += r.deletedCount
  console.log(`  cleared ${name} (${r.deletedCount})`)
}
console.log(`\ndeleted ${total} document(s) across ${before.length} collection(s)`)
await mongoose.disconnect()
