import dotenv from 'dotenv'

dotenv.config()

/**
 * Fail loudly at boot on a missing secret. A silently-absent JWT secret is far
 * worse than a server that refuses to start (vault-backend skill, "Config").
 * Note there are deliberately NO `|| 'dev-secret'` fallbacks anywhere.
 */
const REQUIRED = ['MONGO_URI', 'JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET']

const missing = REQUIRED.filter((k) => !process.env[k]?.trim())
if (missing.length) {
  console.error(`[config] Missing required env vars: ${missing.join(', ')}`)
  console.error('[config] Copy .env.example to .env and fill it in. Refusing to start.')
  process.exit(1)
}

if (process.env.JWT_ACCESS_SECRET === process.env.JWT_REFRESH_SECRET) {
  console.error('[config] JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must differ. Refusing to start.')
  process.exit(1)
}

export const env = {
  nodeEnv: process.env.NODE_ENV || 'development',
  isProd: process.env.NODE_ENV === 'production',
  port: Number(process.env.PORT) || 4000,
  mongoUri: process.env.MONGO_URI,
  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET,
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    accessTtl: process.env.JWT_ACCESS_TTL || '15m',
    refreshTtl: process.env.JWT_REFRESH_TTL || '30d',
  },
  /**
   * Development-only: print the OTP to the server console instead of mailing it.
   *
   * An OTP is a credential, so this is opt-in AND hard-blocked in production —
   * two independent conditions, because one of them being fat-fingered in a
   * deploy must not start leaking live codes into log aggregation. It exists so
   * the signup flow is testable before SMTP credentials are in place.
   */
  otpDevEcho: process.env.NODE_ENV !== 'production' && process.env.OTP_DEV_ECHO === '1',
  corsOrigins: (process.env.CORS_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean),
  /**
   * HTTPS email provider, used INSTEAD of SMTP when a key is present.
   *
   * Needed because some hosts (Render's free tier among them) block outbound
   * SMTP ports entirely. `from` falls back to the SMTP sender so a deployment
   * that already had one does not need a second copy of the same address.
   */
  mail: {
    provider: process.env.MAIL_PROVIDER,        // 'brevo' | 'resend'
    apiKey: process.env.MAIL_API_KEY,
    from: process.env.MAIL_FROM || process.env.SMTP_FROM || process.env.SMTP_USER,
  },
  smtp: {
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
    from: process.env.SMTP_FROM,
    configured: Boolean(process.env.SMTP_HOST && process.env.SMTP_USER),
  },
}
