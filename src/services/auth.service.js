import crypto from 'node:crypto'
import bcrypt from 'bcryptjs'
import { User } from '../models/user.model.js'
import { AppError, conflict, unauthorized, badRequest } from '../utils/app-error.js'
import { issueTokens, verifyRefreshToken, hashToken } from './token.service.js'
import { issueOtp, verifyOtp } from './otp.service.js'
import { security } from '../config/security.js'

const BCRYPT_COST = 12

/**
 * Security rule 5 — this file deals ONLY with the login password.
 * The master password never arrives here, is never hashed here, and is never
 * compared here. Vault unlock happens entirely client-side.
 */

/** CSPRNG, unique per user. Not a secret, but must never be derived from the email. */
function generateKdfSalt() {
  return crypto.randomBytes(16).toString('hex')
}

/**
 * Step 1 of signup: park the account and email a code. NO tokens are issued here.
 *
 * An unverified duplicate is replayed rather than rejected, so someone who closed
 * the app mid-signup can start again — and so this endpoint does not become an
 * account-existence oracle for addresses that never finished verifying.
 */
export async function signup({ email, password }) {
  // No longer selects +passwordHash: the re-signup path does not read or
  // rewrite it, and pulling a bcrypt hash into memory for nothing is free risk.
  const existing = await User.findOne({ email })

  if (existing?.emailVerified) {
    throw conflict('An account with that email already exists.', 'EMAIL_TAKEN')
  }

  const user =
    existing ||
    (await User.create({
      email,
      passwordHash: await bcrypt.hash(password, BCRYPT_COST),
      kdfSalt: generateKdfSalt(),
    }))

  /*
   * NEVER overwrite the password of a pending account.
   *
   * This used to re-hash whatever the latest signup call supplied, reasoning
   * that an unverified account had nothing to protect. It had: the address.
   * An attacker could POST signup for someone else's pending email, replace the
   * hash with their own password, and the victim — who then receives the newest
   * code and enters it — verifies an account the attacker controls. Whoever
   * called signup last before verification won the account.
   *
   * Re-signup now only re-sends the code. Someone who mistyped their password
   * before verifying can verify and then change it, or let the unverified row
   * expire; neither outcome hands the account to a stranger.
   */

  const { expiresAt, resendCooldownMs } = await issueOtp({ userId: user._id, email: user.email })

  return {
    pendingVerification: true,
    email: user.email,
    otpExpiresAt: expiresAt,
    resendCooldownMs,
  }
}

/** Step 2: a correct code is what turns a parked account into a session. */
export async function verifyEmail({ email, code }) {
  const user = await User.findOne({ email }).select('+kdfSalt +verifierCiphertext +verifierIv')
  if (!user) throw badRequest('That code is not right. Request a new one.', 'OTP_INVALID')

  await verifyOtp({ userId: user._id, code })

  const { accessToken, refreshToken, refreshTokenHash } = issueTokens(user._id)
  user.emailVerified = true
  user.refreshTokenHash = refreshTokenHash
  user.lastLoginAt = new Date()
  await user.save()

  return {
    user: { id: user._id, email: user.email, vaultInitialized: user.vaultInitialized },
    kdfSalt: user.kdfSalt,
    verifier:
      user.verifierCiphertext && user.verifierIv
        ? { ciphertext: user.verifierCiphertext, iv: user.verifierIv }
        : null,
    accessToken,
    refreshToken,
  }
}

/** Step 1 again, on demand. The cooldown and cap live in otp.service. */
export async function resendCode({ email }) {
  const user = await User.findOne({ email })
  // Silent success for unknown or already-verified addresses: replying "no such
  // account" here would undo the enumeration protection on signup and login.
  if (!user || user.emailVerified) {
    return { sent: true, resendCooldownMs: security.otp.resendCooldownMs }
  }
  const { expiresAt, resendCooldownMs } = await issueOtp({
    userId: user._id,
    email: user.email,
    isResend: true,
  })
  return { sent: true, otpExpiresAt: expiresAt, resendCooldownMs }
}

/* ------------------------------------------------------------- PIN reset */

/**
 * Email a code so a signed-in user can set a new PIN without their old one.
 *
 * ---------------------------------------------------------------------------
 * THIS RELEASES NOTHING. It cannot, and must never be changed so that it can.
 * ---------------------------------------------------------------------------
 * The PIN does not derive the vault key — it only unwraps a copy of it that is
 * already on the device (rule 5). So a PIN reset is a LOCAL re-wrap, and the
 * server's only job here is to confirm the person still controls the verified
 * address. It returns no key, no salt and no ciphertext.
 *
 * That boundary is the whole reason email is safe to use for this. If this
 * endpoint ever returned key material, email would become a way into the
 * vault itself, and a mailbox compromise would equal a vault compromise —
 * exactly what rule 1 exists to prevent.
 *
 * Authenticated on purpose: the caller is a device that already holds a valid
 * session, so there is no address to submit and therefore no way to probe which
 * addresses exist. The OTP routes for signup need enumeration protection; this
 * one is immune to the question by construction.
 */
export async function requestPinReset({ userId }) {
  const user = await User.findById(userId)
  if (!user) throw unauthorized('Please sign in again.', 'SESSION_EXPIRED')
  // An unverified address cannot be a recovery channel for anything.
  if (!user.emailVerified) {
    throw badRequest('Verify your email address first.', 'EMAIL_UNVERIFIED')
  }

  const { expiresAt, resendCooldownMs } = await issueOtp({
    userId: user._id,
    email: user.email,
    purpose: 'pin-reset',
    // Every request here is deliberate and user-initiated, so each one obeys the
    // cooldown and the cap — there is no "first one is free" step like signup.
    isResend: true,
  })
  return { sent: true, email: user.email, otpExpiresAt: expiresAt, resendCooldownMs }
}

/**
 * Confirm the code. Returns ok and nothing else — see the note above.
 *
 * The client then re-wraps the vault key it already holds in memory under the
 * new PIN. The server never learns that the PIN changed, because from its side
 * nothing did.
 */
export async function confirmPinReset({ userId, code }) {
  const user = await User.findById(userId)
  if (!user) throw unauthorized('Please sign in again.', 'SESSION_EXPIRED')
  await verifyOtp({ userId: user._id, code, purpose: 'pin-reset' })
  return { ok: true }
}

export async function login({ email, password }) {
  const user = await User.findOne({ email }).select(
    '+passwordHash +kdfSalt +verifierCiphertext +verifierIv'
  )

  // Uniform failure: a wrong email and a wrong password are indistinguishable, so
  // this endpoint cannot be used to enumerate accounts. Compare against a dummy
  // hash when the user is absent to keep timing roughly constant too.
  const hash = user?.passwordHash || '$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidinv'
  const ok = await bcrypt.compare(password, hash)
  if (!user || !ok) throw unauthorized('Invalid email or password.', 'BAD_CREDENTIALS')

  // Correct credentials but never verified: send a fresh code and route the
  // client back to the OTP step rather than issuing a session.
  if (!user.emailVerified) {
    const { expiresAt, resendCooldownMs } = await issueOtp({ userId: user._id, email: user.email })
    throw new AppError(403, 'Verify your email to finish signing in.', 'EMAIL_UNVERIFIED', {
      email: user.email,
      otpExpiresAt: expiresAt,
      resendCooldownMs,
    })
  }

  const { accessToken, refreshToken, refreshTokenHash } = issueTokens(user._id)
  await User.updateOne({ _id: user._id }, { refreshTokenHash, lastLoginAt: new Date() })

  // Everything the client needs to derive the key and self-check the master
  // password — all of it useless to anyone who cannot supply that password.
  return {
    user: { id: user._id, email: user.email, vaultInitialized: user.vaultInitialized },
    kdfSalt: user.kdfSalt,
    verifier: user.vaultInitialized
      ? { ciphertext: user.verifierCiphertext, iv: user.verifierIv }
      : null,
    accessToken,
    refreshToken,
  }
}

/**
 * Stores the encrypted master-password canary. Called once, right after signup,
 * by a client that has just derived its vault key.
 *
 * The two values are opaque ciphertext. The server cannot decrypt them and so
 * still knows nothing about the master password (rule 1).
 */
export async function initializeVault(userId, { verifierCiphertext, verifierIv }) {
  const user = await User.findById(userId).select('+verifierCiphertext')
  if (!user) throw unauthorized()
  if (user.vaultInitialized) {
    // Overwriting the canary would orphan every existing item's key. Refuse.
    throw badRequest('Vault is already initialized.', 'VAULT_ALREADY_INIT')
  }

  await User.updateOne(
    { _id: userId },
    { verifierCiphertext, verifierIv, vaultInitialized: true }
  )
  return { vaultInitialized: true }
}

/**
 * Session restore on cold start.
 *
 * MUST include `vaultInitialized`: the client's navigator uses it to decide
 * between vault setup and unlock. Returning only an id sends a returning user
 * back to first-time setup.
 */
export async function getMe(userId) {
  const user = await User.findById(userId).lean()
  if (!user) throw unauthorized()
  return { id: user._id, email: user.email, vaultInitialized: Boolean(user.vaultInitialized) }
}

/** Returns the salt + canary needed to unlock. Requires a valid session. */
export async function getVaultParams(userId) {
  const user = await User.findById(userId).select('+kdfSalt +verifierCiphertext +verifierIv')
  if (!user) throw unauthorized()
  return {
    kdfSalt: user.kdfSalt,
    vaultInitialized: user.vaultInitialized,
    verifier: user.vaultInitialized
      ? { ciphertext: user.verifierCiphertext, iv: user.verifierIv }
      : null,
  }
}

export async function refresh({ refreshToken }) {
  let payload
  try {
    payload = verifyRefreshToken(refreshToken)
  } catch {
    throw unauthorized('Session expired. Please log in again.', 'BAD_REFRESH')
  }

  const user = await User.findById(payload.sub).select('+refreshTokenHash')
  // Reject a token that isn't the currently-issued one (rotation / revocation).
  if (!user || user.refreshTokenHash !== hashToken(refreshToken)) {
    throw unauthorized('Session expired. Please log in again.', 'BAD_REFRESH')
  }

  const tokens = issueTokens(user._id)
  await User.updateOne({ _id: user._id }, { refreshTokenHash: tokens.refreshTokenHash })
  return { accessToken: tokens.accessToken, refreshToken: tokens.refreshToken }
}

export async function logout(userId) {
  await User.updateOne({ _id: userId }, { $unset: { refreshTokenHash: 1 } })
  return { ok: true }
}
