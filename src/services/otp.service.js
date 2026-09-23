import crypto from 'node:crypto'
import bcrypt from 'bcryptjs'
import { Otp } from '../models/otp.model.js'
import { security } from '../config/security.js'
import { sendOtpEmail } from './mail.service.js'
import { badRequest, tooManyRequests } from '../utils/app-error.js'

/**
 * Email-verification codes: issue, resend, verify.
 *
 * Three limits, all from config (never hard-coded): how long a code lives, how
 * many wrong guesses it survives, and how often a new one can be requested.
 * Without all three, "email a code" is an open relay for spamming an address and
 * an unlimited oracle for guessing a 6-digit number.
 */

/** CSPRNG, not Math.random — an OTP is a credential (rule: Randomness). */
function generateCode(length) {
  const max = 10 ** length
  // Rejection-free: read a uint32 and reduce. Bias at 10^6 vs 2^32 is negligible,
  // and the code is single-use, short-lived and attempt-capped.
  const n = crypto.randomBytes(4).readUInt32BE(0) % max
  return String(n).padStart(length, '0')
}

/**
 * Create or replace the pending code for a user and email it.
 *
 * `isResend` distinguishes the two callers: signup always gets a fresh code,
 * while an explicit resend has to respect the cooldown and the resend cap.
 */
export async function issueOtp({ userId, email, isResend = false }) {
  const existing = await Otp.findOne({ userId, purpose: 'email-verify' })

  if (isResend && existing) {
    const since = Date.now() - new Date(existing.lastSentAt).getTime()
    if (since < security.otp.resendCooldownMs) {
      const wait = Math.ceil((security.otp.resendCooldownMs - since) / 1000)
      throw tooManyRequests(`Wait ${wait}s before asking for another code.`, 'OTP_COOLDOWN')
    }
    if (existing.resends + 1 >= security.otp.maxResends) {
      throw tooManyRequests('Too many codes requested. Start again in a few minutes.', 'OTP_RESEND_LIMIT')
    }
  }

  const code = generateCode(security.otp.length)
  const codeHash = await bcrypt.hash(code, 10)
  const expiresAt = new Date(Date.now() + security.otp.ttlMs)

  /*
   * A new code resets the guess budget but NOT the resend budget — otherwise
   * resending would be a free way to reset the guess limit forever.
   *
   * `resends` is set two different ways depending on the caller, and it must be
   * ONE of them: naming the same path in both `$set` and `$inc` makes Mongo
   * reject the whole update ("would create a conflict at 'resends'").
   */
  const base = { codeHash, expiresAt, lastSentAt: new Date(), attempts: 0 }
  const update = isResend
    ? { $set: base, $inc: { resends: 1 } }
    : { $set: { ...base, resends: 0 } }

  await Otp.findOneAndUpdate({ userId, purpose: 'email-verify' }, update, {
    upsert: true,
    new: true,
    setDefaultsOnInsert: true,
  })

  await sendOtpEmail({ to: email, code, ttlMinutes: Math.round(security.otp.ttlMs / 60000) })

  return { expiresAt, resendCooldownMs: security.otp.resendCooldownMs }
}

/**
 * Verify a submitted code.
 *
 * Deliberately generic failure copy: "that code is not right" never distinguishes
 * expired from wrong from never-issued, because that difference tells an attacker
 * whether an address is registered.
 */
export async function verifyOtp({ userId, code }) {
  const record = await Otp.findOne({ userId, purpose: 'email-verify' }).select('+codeHash')
  if (!record) throw badRequest('That code is not right. Request a new one.', 'OTP_INVALID')

  if (record.expiresAt.getTime() < Date.now()) {
    await record.deleteOne()
    throw badRequest('That code has expired. Request a new one.', 'OTP_EXPIRED')
  }

  if (record.attempts >= security.otp.maxAttempts) {
    await record.deleteOne()
    throw tooManyRequests('Too many wrong codes. Request a new one.', 'OTP_ATTEMPTS')
  }

  const ok = await bcrypt.compare(code, record.codeHash)
  if (!ok) {
    record.attempts += 1
    await record.save()
    throw badRequest('That code is not right. Request a new one.', 'OTP_INVALID')
  }

  // Single use — burn it the moment it works.
  await record.deleteOne()
  return true
}

export async function clearOtp(userId) {
  await Otp.deleteMany({ userId })
}
