import mongoose from 'mongoose'
import { env } from './env.js'
import { logger } from '../utils/logger.js'

export async function connectDb() {
  mongoose.set('strictQuery', true)
  await mongoose.connect(env.mongoUri, { serverSelectionTimeoutMS: 10000 })
  logger.info('mongo connected')

  mongoose.connection.on('error', (err) => logger.error('mongo error', { msg: err.message }))
  mongoose.connection.on('disconnected', () => logger.warn('mongo disconnected'))
}

export async function disconnectDb() {
  await mongoose.connection.close()
}
