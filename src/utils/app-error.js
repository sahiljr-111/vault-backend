/** Operational error with an HTTP status. Message is safe to send to the client. */
export class AppError extends Error {
  /**
   * `details` carries the small amount of NON-SENSITIVE context a client needs to
   * recover — which step to go back to, when a code expires. It is never a place
   * for anything secret; it is serialised straight to the response.
   */
  constructor(status, message, code, details) {
    super(message)
    this.status = status
    this.code = code
    this.details = details
    this.isOperational = true
  }
}

export const badRequest = (m, c) => new AppError(400, m, c)
export const unauthorized = (m = 'Invalid credentials.', c) => new AppError(401, m, c)
export const forbidden = (m = 'Not allowed.', c) => new AppError(403, m, c)
export const notFound = (m = 'Not found.', c) => new AppError(404, m, c)
export const conflict = (m, c) => new AppError(409, m, c)
export const tooManyRequests = (m, c) => new AppError(429, m, c)
