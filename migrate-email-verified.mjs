/**
 * One-off: mark accounts created BEFORE email verification existed as verified.
 *
 * `emailVerified` defaults to false, so adding the field retroactively locked out
 * every existing account — they were created when no such requirement existed and
 * cannot be asked to prove something that was never requested of them. New signups
 * are unaffected: they go through OTP from the start.
 *
 * Safe to re-run: it only touches documents where the field is still missing.
 */
import mongoose from 'mongoose'
import { env } from './src/config/env.js'
import { User } from './src/models/user.model.js'

await mongoose.connect(env.mongoUri)

const res = await User.updateMany(
  { emailVerified: { $exists: false } },
  { $set: { emailVerified: true } }
)

console.log(`marked ${res.modifiedCount} pre-existing account(s) as verified`)
await mongoose.disconnect()
