import nodemailer from 'nodemailer'
import { env } from '../config/env.js'
import { logger } from '../utils/logger.js'
import { badRequest } from '../utils/app-error.js'

let transporter = null
function getTransporter() {
  if (!env.smtp.configured) return null
  transporter ??= nodemailer.createTransport({
    host: env.smtp.host,
    port: env.smtp.port,
    secure: env.smtp.port === 465,
    auth: { user: env.smtp.user, pass: env.smtp.pass },
  })
  return transporter
}

/*
 * `emailEncryptedBackup` was removed, not kept for later.
 *
 * It attached the backup archive with the subject "encrypted backup" and the
 * body "This file is useless without your master password". Neither was true:
 * the container was base64, carrying every item's title, folder and tags in the
 * clear. Leaving the function in place — unreachable but with the false promise
 * already written — is exactly how the next person re-enables the leak in one
 * line. When backups return, the CLIENT must encrypt the archive first, and the
 * copy can then say so honestly.
 */

/**
 * The email-verification code.
 *
 * Plain text only, no links: a verification LINK is a phishing template, and a
 * code the user types back into the app they already have open cannot be
 * clicked from a forwarded message. Nothing about the vault appears here — this
 * email proves control of an address, nothing more.
 */
export async function sendOtpEmail({ to, code, ttlMinutes }) {
  const tx = getTransporter()

  // Never reachable in production — see env.otpDevEcho. Prints the code whether
  // or not SMTP is configured, so the flow stays testable without reading a real
  // inbox; the mail is still sent when a transport exists.
  if (env.otpDevEcho) logger.warn('OTP_DEV_ECHO', { to, code })

  if (!tx) {
    if (env.otpDevEcho) return { sent: false, echoed: true }
    throw badRequest('Email is not configured on this server.', 'SMTP_NOT_CONFIGURED')
  }

  try {
    await tx.sendMail({
      from: env.smtp.from || env.smtp.user,
      to,
      subject: `${code} is your Personal Vault code`,
      text: [
        `Your verification code is ${code}`,
        '',
        `It expires in ${ttlMinutes} minutes and can be used once.`,
        '',
        "If you didn't ask for this, you can ignore this email — nobody can get in",
        'with the code alone.',
      ].join('\n'),
    })
  } catch (e) {
    /*
     * A transport failure is NOT "something went wrong".
     *
     * Uncaught, this surfaced as a bare 500 and the app said "Something went
     * wrong. Please try again." — which sent the user round the same loop with
     * nothing to act on, because retrying cannot fix a revoked app password or
     * a blocked port.
     *
     * Only the transport's own code is logged (EAUTH, ECONNECTION, ETIMEDOUT
     * and friends). Never the message, which can echo back the envelope, and
     * never the credentials or the code itself (rule 3).
     */
    logger.error('otp email failed', { code: e?.code, command: e?.command })
    throw badRequest(
      'We could not send the email just now. Try again in a minute.',
      'MAIL_SEND_FAILED'
    )
  }

  // The code is never logged (rule 3). The address is masked.
  logger.info('otp emailed', { to: to.replace(/(.{2}).*(@.*)/, '$1***$2') })
  return { sent: true }
}
