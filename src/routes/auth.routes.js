import { Router } from 'express'
import { z } from 'zod'
import * as authController from '../controllers/auth.controller.js'
import { validate } from '../middlewares/validate.middleware.js'
import { requireAuth } from '../middlewares/auth.middleware.js'
import {
  authLimiter,
  mailLimiterPerIp,
  mailLimiterPerEmail,
  otpVerifyLimiter,
} from '../middlewares/rate-limit.middleware.js'

const router = Router()

/**
 * Shape-only validation. Note what is NOT here: any schema for a master password.
 * It never reaches this API (rule 1, 5). `password` below is the LOGIN password.
 *
 * Login password minimum is deliberately modest — it is bcrypt-hashed and
 * rate-limited, and it is NOT what protects the vault contents.
 */
const credentials = z
  .object({
    email: z.string().email().max(254).toLowerCase().trim(),
    password: z.string().min(8, 'at least 8 characters').max(200),
  })
  .strict()

/** Opaque ciphertext from the client. Base64 shape only — contents never inspected. */
const b64 = z.string().min(1).max(4096).regex(/^[A-Za-z0-9+/=]+$/, 'base64')

const vaultInit = z.object({ verifierCiphertext: b64, verifierIv: b64 }).strict()
const refreshBody = z.object({ refreshToken: z.string().min(10).max(2048) }).strict()

/** A code is a credential: shape-checked, and rate limited like a password. */
const otpBody = z
  .object({
    email: z.string().email().max(254).toLowerCase().trim(),
    code: z.string().regex(/^\d{4,8}$/, 'numeric code'),
  })
  .strict()

const emailOnly = z
  .object({ email: z.string().email().max(254).toLowerCase().trim() })
  .strict()

/* PIN reset carries only the code: the account comes from the session. */
const codeOnly = z
  .object({ code: z.string().regex(/^\d{4,8}$/, 'numeric code') })
  .strict()

// Rule 8 — rate limit every credential-accepting surface. The OTP routes are
// included deliberately: verify is a guessing oracle and resend costs real mail.
router.post('/signup', mailLimiterPerIp, mailLimiterPerEmail, validate(credentials), authController.signup)
router.post('/verify-email', otpVerifyLimiter, validate(otpBody), authController.verifyEmail)
router.post('/resend-code', mailLimiterPerIp, mailLimiterPerEmail, validate(emailOnly), authController.resendCode)
router.post('/login', authLimiter, validate(credentials), authController.login)
router.post('/refresh', authLimiter, validate(refreshBody), authController.refresh)

/*
 * Rule 8 — a code is a credential, so both halves are limited even though they
 * already require a session: `request` costs real mail, and `confirm` is a
 * guessing oracle. The per-IP mail limiter sits in front of the send, and the
 * OTP verify limiter in front of the check, exactly as on the signup pair.
 */
router.post('/pin-reset/request', requireAuth, mailLimiterPerIp, authController.requestPinReset)
router.post('/pin-reset/confirm', requireAuth, otpVerifyLimiter, validate(codeOnly), authController.confirmPinReset)

router.post('/vault/init', requireAuth, validate(vaultInit), authController.initializeVault)
router.get('/vault/params', requireAuth, authController.vaultParams)
router.post('/logout', requireAuth, authController.logout)
router.get('/me', requireAuth, authController.me)

export default router
