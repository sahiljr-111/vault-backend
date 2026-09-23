import mongoose from 'mongoose'
import { env } from '../config/env.js'
import { logger } from '../utils/logger.js'

export function notFoundHandler(req, _res, next) {
  next(Object.assign(new Error(`Route ${req.method} ${req.path} not found.`), { status: 404 }))
}

/**
 * Centralized error handler — must be registered LAST.
 *
 * Rule 3: never logs req.body (it carries passwords, tokens and ciphertext).
 * Never leaks a stack trace in production.
 */
export function errorHandler(err, req, res, _next) {
  let status = err.status || 500
  let message = err.message || 'Something went wrong.'
  let code = err.code

  if (err instanceof mongoose.Error.ValidationError) {
    status = 400
    message = 'Invalid request.'
    code = 'VALIDATION_FAILED'
  } else if (err instanceof mongoose.Error.CastError) {
    status = 400
    message = 'Invalid identifier.'
    code = 'BAD_ID'
  } else if (err.code === 11000) {
    status = 409
    message = 'Already exists.'
    code = 'DUPLICATE'
  }

  // Log path + status only. No body, no headers, no query.
  logger[status >= 500 ? 'error' : 'warn']('request failed', {
    status,
    method: req.method,
    path: req.path,
    code,
    msg: err.message,
    userId: req.user?.id,
  })

  if (status >= 500 && env.isProd) message = 'Something went wrong.'

  res.status(status).json({
    error: {
      message,
      ...(code && { code }),
      // Only ever set deliberately by AppError, and only with recovery context
      // (which step, when a code expires) — never anything secret.
      ...(err.details && { details: err.details }),
      ...(!env.isProd && status >= 500 && { stack: err.stack }),
    },
  })
}
