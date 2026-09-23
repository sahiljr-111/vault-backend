import * as authService from '../services/auth.service.js'

/** Thin: parse req -> call service -> shape res. No logic, no DB access. */

export async function signup(req, res, next) {
  try {
    res.status(201).json({ data: await authService.signup(req.body) })
  } catch (err) { next(err) }
}

/** Step 2 of signup — the only place a brand-new account gets a session. */
export async function verifyEmail(req, res, next) {
  try {
    res.json({ data: await authService.verifyEmail(req.body) })
  } catch (e) {
    next(e)
  }
}

export async function resendCode(req, res, next) {
  try {
    res.json({ data: await authService.resendCode(req.body) })
  } catch (e) {
    next(e)
  }
}

export async function login(req, res, next) {
  try {
    res.json({ data: await authService.login(req.body) })
  } catch (err) { next(err) }
}

export async function initializeVault(req, res, next) {
  try {
    res.json({ data: await authService.initializeVault(req.user.id, req.body) })
  } catch (err) { next(err) }
}

export async function vaultParams(req, res, next) {
  try {
    res.json({ data: await authService.getVaultParams(req.user.id) })
  } catch (err) { next(err) }
}

export async function refresh(req, res, next) {
  try {
    res.json({ data: await authService.refresh(req.body) })
  } catch (err) { next(err) }
}

export async function logout(req, res, next) {
  try {
    res.json({ data: await authService.logout(req.user.id) })
  } catch (err) { next(err) }
}

export async function me(req, res, next) {
  try {
    res.json({ data: await authService.getMe(req.user.id) })
  } catch (err) { next(err) }
}
