import jwt from 'jsonwebtoken'
import { env } from '../config/env.js'
import { unauthorized } from '../utils/app-error.js'

/**
 * Sets req.user = { id } from a verified access token.
 *
 * This is the ENTIRE authorization model: every downstream query must scope by
 * req.user.id. Nothing ever trusts a user id from the body, params, or query.
 */
export function requireAuth(req, _res, next) {
  const header = req.headers.authorization || ''
  const [scheme, token] = header.split(' ')

  if (scheme !== 'Bearer' || !token) {
    return next(unauthorized('Authentication required.', 'NO_TOKEN'))
  }

  try {
    const payload = jwt.verify(token, env.jwt.accessSecret)
    if (payload.type !== 'access') return next(unauthorized('Invalid token.', 'WRONG_TOKEN_TYPE'))
    req.user = { id: payload.sub }
    next()
  } catch (err) {
    // Distinguish expiry so the client knows to refresh rather than re-login.
    const code = err.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN'
    next(unauthorized(code === 'TOKEN_EXPIRED' ? 'Session expired.' : 'Invalid token.', code))
  }
}
