/**
 * Every authentication limit in one place, overridable by env.
 *
 * These are policy, not implementation detail: tightening a lockout after an
 * incident, or loosening an OTP window because a mail provider is slow, must not
 * mean hunting for magic numbers across the codebase. The mobile app has a
 * matching file for the limits it owns (mobile/src/config/security.js).
 */
const num = (key, fallback) => {
  const v = Number(process.env[key])
  return Number.isFinite(v) && v > 0 ? v : fallback
}

export const security = {
  otp: {
    /** 6 digits is the norm users expect; length is here so it can change. */
    length: num('OTP_LENGTH', 6),
    /** Long enough to switch apps and read the mail, short enough to be useless later. */
    ttlMs: num('OTP_TTL_MINUTES', 10) * 60 * 1000,
    /** Wrong guesses before the code is burned and a new one must be requested. */
    maxAttempts: num('OTP_MAX_ATTEMPTS', 5),
    /** Resends allowed per code lifetime — caps both spam and mail-bill abuse. */
    maxResends: num('OTP_MAX_RESENDS', 3),
    /** Minimum gap between sends, so a held button cannot mail-bomb an address. */
    resendCooldownMs: num('OTP_RESEND_COOLDOWN_SECONDS', 60) * 1000,
  },
}
