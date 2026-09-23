import express from 'express'
import helmet from 'helmet'
import cors from 'cors'
import mongoSanitize from 'express-mongo-sanitize'
import { env } from './config/env.js'
import routes from './routes/index.js'
import { apiLimiter } from './middlewares/rate-limit.middleware.js'
import { errorHandler, notFoundHandler } from './middlewares/error.middleware.js'

export function createApp() {
  const app = express()

  app.set('trust proxy', 1) // behind a reverse proxy: needed for correct rate-limit IPs
  app.disable('x-powered-by')

  app.use(helmet())

  /*
   * Allow no-origin callers (the native app sends no Origin header) and, for
   * browsers, only the configured list.
   *
   * There used to be an `env.corsOrigins.length === 0` clause here that said
   * "allow everyone". It read like a convenience default but it FAILED OPEN:
   * with CORS_ORIGINS unset — which is the state of any fresh deployment — every
   * website on the internet was permitted to call this API from a browser. That
   * was survivable while the server only ever listened on a home LAN; it is not
   * once it has a public hostname.
   *
   * Dropping the clause costs nothing, because the only real client is the
   * native app and it is covered by `!origin`. So an unset CORS_ORIGINS now
   * means "no browser may call this", which is the correct default for an API
   * with no web client at all (the product is mobile-native — CLAUDE.md §9).
   */
  app.use(
    cors({
      origin(origin, cb) {
        if (!origin || env.corsOrigins.includes(origin)) return cb(null, true)
        cb(new Error('Not allowed by CORS'))
      },
      credentials: true,
    })
  )

  // Body cap: generous enough for a backup restore, small enough to matter.
  app.use(express.json({ limit: '10mb' }))
  app.use(mongoSanitize()) // strips $ / . operators — blocks query injection

  /**
   * DEV-ONLY request log. Records METHOD, PATH, STATUS and the client IP — never
   * headers and never bodies, which carry passwords, tokens and ciphertext
   * (rule 3). Disabled entirely in production.
   *
   * Its purpose is diagnostic: it answers "is the phone's request even arriving?"
   * A silent log while the app shows a network error means the request never
   * reached this process (firewall / wrong host), not that the API is broken.
   */
  if (!env.isProd) {
    app.use((req, res, next) => {
      const started = Date.now()
      res.on('finish', () => {
        const ip = (req.ip || '').replace('::ffff:', '')
        const who = ip === '127.0.0.1' || ip === '::1' ? 'localhost' : ip
        console.log(
          `\x1b[36m[req]\x1b[0m ${req.method} ${req.path} -> ${res.statusCode} ` +
            `(${Date.now() - started}ms) from ${who}`
        )
      })
      next()
    })
  }


  app.use('/api', apiLimiter, routes)

  app.use(notFoundHandler)
  app.use(errorHandler) // must be last
  return app
}
