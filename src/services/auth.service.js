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
/**
 * What a client needs to open its vault: the public salt and the sealed key.
 *
 * Useless without the password — the blob is AEAD, so a wrong password fails
 * the tag instead of yielding a key (rule 1). Returned as one shape from every
 * entry point so the three of them cannot drift apart.
 */
function vaultEnvelope(user) {
  return {
    kdfSalt: user.kdfSalt,
    wrappedKey:
      user.wrappedKeyCiphertext && user.wrappedKeyNonce
        ? { ciphertext: user.wrappedKeyCiphertext, nonce: user.wrappedKeyNonce }
        : null,
  }
}

export async function verifyEmail({ email, code }) {
  const user = await User.findOne({ email }).select('+kdfSalt +wrappedKeyCiphertext +wrappedKeyNonce')
  if (!user) throw badRequest('That code is not right. Request a new one.', 'OTP_INVALID')

  await verifyOtp({ userId: user._id, code })

  const { accessToken, refreshToken, refreshTokenHash } = issueTokens(user._id)
  user.emailVerified = true
  user.refreshTokenHash = refreshTokenHash
  user.lastLoginAt = new Date()
  await user.save()

  return {
    user: { id: user._id, email: user.email, vaultInitialized: user.vaultInitialized },
    ...vaultEnvelope(user),
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
    '+passwordHash +kdfSalt +wrappedKeyCiphertext +wrappedKeyNonce'
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

  // Everything the client needs to UNWRAP its key — useless to anyone who
  // cannot supply the password that seals it.
  return {
    user: { id: user._id, email: user.email, vaultInitialized: user.vaultInitialized },
    ...vaultEnvelope(user),
    accessToken,
    refreshToken,
  }
}

/**
 * Stores the sealed vault key, once, right after signup.
 *
 * Both blobs are opaque ciphertext and both salts are public: the server learns
 * nothing about the password or the recovery code, and cannot open either
 * wrapping (rule 1). It is a locker, not a keyholder.
 */
export async function initializeVault(
  userId,
  { wrappedKeyCiphertext, wrappedKeyNonce, recoverySalt, recoveryCiphertext, recoveryNonce }
) {
  const user = await User.findById(userId)
  if (!user) throw unauthorized()
  if (user.vaultInitialized) {
    // Overwriting the wrapping would orphan every item encrypted under the key
    // it seals. There is no undo for that, so refuse rather than merge.
    throw badRequest('Vault is already initialized.', 'VAULT_ALREADY_INIT')
  }

  await User.updateOne(
    { _id: userId },
    {
      wrappedKeyCiphertext,
      wrappedKeyNonce,
      recoverySalt,
      recoveryCiphertext,
      recoveryNonce,
      vaultInitialized: true,
    }
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

/** The salt + sealed key needed to unlock. Requires a valid session. */
export async function getVaultParams(userId) {
  const user = await User.findById(userId).select('+kdfSalt +wrappedKeyCiphertext +wrappedKeyNonce')
  if (!user) throw unauthorized()
  return { ...vaultEnvelope(user), vaultInitialized: user.vaultInitialized }
}

export async function refresh({ refreshToken }) {
  let payload
  try {
    payload = verifyRefreshToken(refreshToken)
  } catch {
    throw unauthorized('Session expired. Please log in again.', 'BAD_REFRESH')
  }

  const user = await User.findById(payload.sub).select(
    '+refreshTokenHash +prevRefreshTokenHash +prevRefreshAt'
  )
  const presented = hashToken(refreshToken)
  const isCurrent = Boolean(user) && user.refreshTokenHash === presented

  /*
   * The one just replaced is still accepted, briefly.
   *
   * Rotation is single-use, which is correct — but with no grace window a LOST
   * RESPONSE looks exactly like a stolen token. If the client never received
   * the rotated pair (the app was killed mid-flight by an update or a
   * force-stop, or the connection dropped), it retries with a token the server
   * has already retired and gets signed out for it. On this app that also wipes
   * the device PIN, so a single dropped packet cost the user their whole
   * device setup and a password re-entry. That is not a security win; it is a
   * reliability bug wearing security's clothes.
   *
   * The window is small and the replay still ROTATES, so the real device and a
   * thief cannot both keep refreshing — whoever comes second is out.
   */
  const isRecentlyRotated =
    Boolean(user) &&
    user.prevRefreshTokenHash === presented &&
    user.prevRefreshAt &&
    Date.now() - new Date(user.prevRefreshAt).getTime() < security.refreshGraceMs

  if (!user || (!isCurrent && !isRecentlyRotated)) {
    throw unauthorized('Session expired. Please log in again.', 'BAD_REFRESH')
  }

  const tokens = issueTokens(user._id)
  await User.updateOne(
    { _id: user._id },
    {
      refreshTokenHash: tokens.refreshTokenHash,
      prevRefreshTokenHash: user.refreshTokenHash,
      prevRefreshAt: new Date(),
    }
  )
  return { accessToken: tokens.accessToken, refreshToken: tokens.refreshToken }
}

export async function logout(userId) {
  // The previous hash goes too. Leaving it behind would keep a retired token
  // working for the rest of the grace window AFTER an explicit sign-out — the
  // one moment the user has said, out loud, that this device is done.
  await User.updateOne(
    { _id: userId },
    { $unset: { refreshTokenHash: 1, prevRefreshTokenHash: 1, prevRefreshAt: 1 } }
  )
  return { ok: true }
}
