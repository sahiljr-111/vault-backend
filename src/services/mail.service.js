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
    /*
     * Timeouts, because without them a BLOCKED port hangs forever.
     *
     * Nodemailer waits on the socket indefinitely by default. Render's free
     * tier silently drops outbound traffic to 25/465/587, so the connection
     * never completed and never refused — the request simply never returned.
     * The client eventually gave up on its own timeout, the server kept the
     * handler open, and because nothing ever threw, NOTHING WAS EVER LOGGED.
     * A whole failure with no evidence anywhere is worse than a loud one.
     *
     * Ten seconds is generous for a submission handshake and short enough that
     * a blocked port now surfaces as ETIMEDOUT within one request.
     */
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 15_000,
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
/**
 * Send over the provider's HTTPS API instead of SMTP.
 *
 * ---------------------------------------------------------------------------
 * This exists because SMTP is not reachable from where this runs.
 * ---------------------------------------------------------------------------
 * Render blocks outbound traffic to ports 25, 465 and 587 on free web services.
 * The block is a silent drop, not a refusal, so nodemailer hung until the
 * client gave up — no email, no error, no log line. No SMTP setting can fix
 * that; the port is simply closed.
 *
 * An HTTP API goes out over 443, which is open. Deliberately written with the
 * built-in fetch and no SDK: it is one POST, and a mail vendor is not worth a
 * dependency (CLAUDE.md §8.4).
 *
 * Provider is chosen by which key is present, so the same build runs on a host
 * with working SMTP (local development, where Gmail is fine) and on one without.
 */
const HTTP_PROVIDERS = {
  brevo: {
    url: 'https://api.brevo.com/v3/smtp/email',
    headers: (key) => ({ 'api-key': key, 'content-type': 'application/json' }),
    body: ({ from, to, subject, text }) => ({
      sender: { email: from },
      to: [{ email: to }],
      subject,
      textContent: text,
    }),
  },
  resend: {
    url: 'https://api.resend.com/emails',
    headers: (key) => ({ authorization: `Bearer ${key}`, 'content-type': 'application/json' }),
    body: ({ from, to, subject, text }) => ({ from, to: [to], subject, text }),
  },
}

function httpProvider() {
  const name = env.mail.provider
  const key = env.mail.apiKey
  if (!name || !key) return null
  const spec = HTTP_PROVIDERS[name]
  if (!spec) throw badRequest(`Unknown MAIL_PROVIDER "${name}".`, 'MAIL_PROVIDER_UNKNOWN')
  return { spec, key }
}

async function sendViaHttp({ spec, key }, { from, to, subject, text }) {
  // Bounded like every other outbound call: a hung vendor must not become a
  // hung request (see the SMTP timeouts above for what that looks like).
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 15_000)
  try {
    const res = await fetch(spec.url, {
      method: 'POST',
      headers: spec.headers(key),
      body: JSON.stringify(spec.body({ from, to, subject, text })),
      signal: controller.signal,
    })
    if (!res.ok) {
      // Status only. A provider error body can echo the recipient and the
      // subject — and the subject carries the CODE (rule 3).
      logger.error('otp email failed', { provider: env.mail.provider, status: res.status })
      throw badRequest('We could not send the email just now. Try again in a minute.', 'MAIL_SEND_FAILED')
    }
  } catch (e) {
    if (e?.code === 'MAIL_SEND_FAILED') throw e
    logger.error('otp email failed', { provider: env.mail.provider, code: e?.name || e?.code })
    throw badRequest('We could not send the email just now. Try again in a minute.', 'MAIL_SEND_FAILED')
  } finally {
    clearTimeout(timer)
  }
}

export async function sendOtpEmail({ to, code, ttlMinutes }) {
  const tx = getTransporter()

  // Never reachable in production — see env.otpDevEcho. Prints the code whether
  // or not SMTP is configured, so the flow stays testable without reading a real
  // inbox; the mail is still sent when a transport exists.
  if (env.otpDevEcho) logger.warn('OTP_DEV_ECHO', { to, code })

  const subject = `${code} is your Personal Vault code`
  const text = [
    `Your verification code is ${code}`,
    '',
    `It expires in ${ttlMinutes} minutes and can be used once.`,
    '',
    "If you didn't ask for this, you can ignore this email — nobody can get in",
    'with the code alone.',
  ].join('\n')
  const masked = to.replace(/(.{2}).*(@.*)/, '$1***$2')

  // HTTPS API first when one is configured — it is the path that works on a
  // host with SMTP blocked.
  const http = httpProvider()
  if (http) {
    await sendViaHttp(http, { from: env.mail.from, to, subject, text })
    logger.info('otp emailed', { via: env.mail.provider, to: masked })
    return { sent: true }
  }

  if (!tx) {
    if (env.otpDevEcho) return { sent: false, echoed: true }
    throw badRequest('Email is not configured on this server.', 'SMTP_NOT_CONFIGURED')
  }

  try {
    await tx.sendMail({ from: env.smtp.from || env.smtp.user, to, subject, text })
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
  logger.info('otp emailed', { via: 'smtp', to: masked })
  return { sent: true }
}
