/**
 * DEVELOPMENT ONLY — boots an ephemeral in-memory MongoDB, then the API.
 *
 * Lets you run the whole backend with no MongoDB install and no Atlas account,
 * which is what makes "just show me the app on my phone" possible in one command.
 *
 * Data is WIPED on every restart. Never use this for anything you want to keep,
 * and never in production (it refuses to run there).
 */
import { MongoMemoryServer } from 'mongodb-memory-server'

if (process.env.NODE_ENV === 'production') {
  console.error('[dev-server] Refusing to run with NODE_ENV=production. Use src/server.js.')
  process.exit(1)
}

const mongo = await MongoMemoryServer.create()
process.env.MONGO_URI = mongo.getUri('vaultapp')

// Imported AFTER MONGO_URI is set, because config/env.js validates at import time.
const { env } = await import('./config/env.js')
const { connectDb } = await import('./config/db.js')
const { createApp } = await import('./app.js')
const { logger } = await import('./utils/logger.js')

await connectDb()

// Binds 0.0.0.0 so a phone on the LAN can reach it (localhost would not).
createApp().listen(env.port, '0.0.0.0', () => {
  logger.info(`listening on 0.0.0.0:${env.port} — ephemeral in-memory mongo`)
})

const stop = async () => { await mongo.stop(); process.exit(0) }
process.on('SIGINT', stop)
process.on('SIGTERM', stop)
