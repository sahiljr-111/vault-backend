import { badRequest } from '../utils/app-error.js'

/**
 * Validates request SHAPE only — never the content of a secret.
 *
 * The server cannot decrypt `encryptedData`, so it must not try to reason about
 * what is inside it (no strength checks, no field presence checks). Schemas use
 * zod `.strict()` so an unknown key is rejected rather than silently persisted —
 * that is what stops a stray plaintext field from ever reaching a document.
 */
export function validate(schema, source = 'body') {
  return (req, _res, next) => {
    const result = schema.safeParse(req[source])
    if (!result.success) {
      // Report the failing PATHS, never the values (rule 3 — a value could be a secret).
      const fields = result.error.issues.map((i) => i.path.join('.')).filter(Boolean)
      const detail = fields.length ? ` Check: ${[...new Set(fields)].join(', ')}.` : ''
      return next(badRequest(`Invalid request.${detail}`, 'VALIDATION_FAILED'))
    }
    req[source] = result.data
    next()
  }
}
