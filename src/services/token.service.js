import crypto from 'node:crypto'
import jwt from 'jsonwebtoken'
import { env } from '../config/env.js'

export function signAccessToken(userId) {
  return jwt.sign({ sub: String(userId), type: 'access' }, env.jwt.accessSecret, {
    expiresIn: env.jwt.accessTtl,
  })
}

export function signRefreshToken(userId) {
  return jwt.sign({ sub: String(userId), type: 'refresh' }, env.jwt.refreshSecret, {
    expiresIn: env.jwt.refreshTtl,
  })
}

export function verifyRefreshToken(token) {
  const payload = jwt.verify(token, env.jwt.refreshSecret)
  if (payload.type !== 'refresh') throw new Error('wrong token type')
  return payload
}

/** Store only a hash of the refresh token, so a DB dump can't be replayed as a session. */
export function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex')
}

export function issueTokens(userId) {
  const accessToken = signAccessToken(userId)
  const refreshToken = signRefreshToken(userId)
  return { accessToken, refreshToken, refreshTokenHash: hashToken(refreshToken) }
}
