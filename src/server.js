import { env } from './config/env.js'
import { connectDb, disconnectDb } from './config/db.js'
import { createApp } from './app.js'
import { logger } from './utils/logger.js'

async function main() {
  await connectDb()

  const server = createApp().listen(env.port, () => {
    logger.info(`api listening on :${env.port} (${env.nodeEnv})`)
  })

  const shutdown = async (signal) => {
    logger.info(`${signal} received, shutting down`)
    server.close(async () => {
      await disconnectDb()
      process.exit(0)
    })
    setTimeout(() => process.exit(1), 10_000).unref()
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'))
  process.on('SIGINT', () => shutdown('SIGINT'))

  // Never let a crash dump a secret-bearing object to stdout — log the message only.
  process.on('unhandledRejection', (err) => {
    logger.error('unhandled rejection', { msg: err instanceof Error ? err.message : 'unknown' })
  })
  process.on('uncaughtException', (err) => {
    logger.error('uncaught exception', { msg: err.message })
    process.exit(1)
  })
}

main().catch((err) => {
  logger.error('failed to start', { msg: err.message })
  process.exit(1)
})
