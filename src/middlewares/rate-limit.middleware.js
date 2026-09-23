import rateLimit from 'express-rate-limit'

const message = { error: { message: 'Too many attempts. Please try again later.', code: 'RATE_LIMITED' } }

/**
 * Security rule 8. TRD §10.6: max 5 login attempts / 15 min per IP.
 */
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message,
  skipSuccessfulRequests: true, // only failed attempts burn the budget
})

/**
 * Surfaces that SEND MAIL need their own budget, counted on success.
 *
 * `authLimiter` skips successful requests, and signup returns 201 — so signup
 * never burned any budget at all. An attacker could loop it against someone
 * else's address for 300 verification emails per window (the global cap),
 * bypassing the OTP cooldown and resend cap entirely, and costing two bcrypt
 * cost-12 hashes per request as a bonus CPU lever.
 *
 * TWO limiters, because one composite key bounds neither dimension.
 *
 * Keying on `ip:email` allows 5 mails per pair — so N source addresses still get
 * 5N emails to a single victim. The per-address limiter below is what actually
 * protects a person's inbox; the per-IP one stops a single host spraying many
 * addresses.
 *
 * `ipKeyGenerator` rather than `req.ip`: a raw IPv6 address gives every client
 * in a /64 its own bucket, which is 2^64 buckets and no limit at all. The email
 * is guarded for type because the limiter runs BEFORE validation — a non-string
 * `email` used to throw inside the key generator and return 500 instead of 400.
 */
/**
 * Collapse an IPv6 address to its /64 prefix.
 *
 * A single client is routinely handed a whole /64, so keying on the full address
 * gives one attacker 2^64 buckets and no limit at all. The /64 is the smallest
 * unit that is actually assigned to one subscriber, which makes it the honest
 * thing to count. IPv4 is returned unchanged.
 *
 * (express-rate-limit ships an `ipKeyGenerator` helper in some versions; the one
 * installed here exports only `rateLimit` and `MemoryStore`, so this is local.)
 */
const ipKey = (req) => {
  const ip = req.ip || ''
  if (!ip.includes(':')) return ip // IPv4, or empty
  const groups = ip.replace(/^::ffff:/, '').split(':')
  if (groups.length < 4) return ip // already short, or IPv4-mapped
  return groups.slice(0, 4).join(':') + '::/64'
}

const emailKey = (req) => {
  const email = req.body?.email
  return typeof email === 'string' ? email.toLowerCase() : '<none>'
}

export const mailLimiterPerIp = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message,
  skipSuccessfulRequests: false, // success is exactly what costs us an email
  keyGenerator: ipKey,
})

/**
 * Mail limiter for routes that already require a session.
 *
 * Keyed by USER, not IP. On an authenticated route the IP is the wrong key
 * twice over: it is too coarse, because every customer behind one carrier NAT
 * or one hosting proxy shares a single budget and can exhaust it for the
 * others, and it is unnecessary, because the enumeration attack the IP key
 * defends against needs an email PARAMETER to probe with — and these routes
 * take the account from the token instead.
 *
 * This is a backstop, not the real control. The precise limits live in
 * issueOtp: a per-user cooldown between codes and a hard resend cap, both of
 * which give the caller a specific "wait Ns" rather than a flat refusal.
 */
export const mailLimiterPerUser = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => req.user?.id ?? ipKey(req),
})

export const mailLimiterPerEmail = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message,
  skipSuccessfulRequests: false,
  keyGenerator: emailKey,
})

/**
 * Verifying a code must NOT share a bucket with requesting one.
 *
 * They were both on `authLimiter` at 5/15min, the same number as the OTP guess
 * budget — so a user who used up their five guesses had simultaneously used up
 * their ability to ask for a new code or to log in, and was stuck for 15 minutes
 * with no way forward. The per-code guess cap in otp.service is the real
 * control; this only stops brute force across many codes.
 */
export const otpVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message,
  skipSuccessfulRequests: true,
})

/**
 * Restore is the sneaky one: unlimited restore attempts turn the endpoint into a
 * master-password guessing oracle (the client can tell success from failure).
 * Keep this tight.
 */
export const restoreLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message,
})

/** Broad backstop against scraping the ciphertext store. */
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message,
})
