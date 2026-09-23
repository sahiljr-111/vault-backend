import mongoose from 'mongoose'

/**
 * Email-verification codes.
 *
 * The code is stored as a bcrypt HASH, never plaintext — an OTP is a credential,
 * and a leaked database should not hand an attacker a live code for every pending
 * signup. It is checked by comparison, exactly like a password.
 *
 * `expiresAt` carries a TTL index, so Mongo removes dead codes itself. That is
 * belt-and-braces: verification also checks expiry, because TTL eviction runs on
 * a sweep and is not instant.
 *
 * One document per purpose per user: requesting a new code replaces the old one,
 * so an old code can never be used after a resend.
 */
const otpSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    /*
     * 'pin-reset' is a SEPARATE document from 'email-verify', which the unique
     * {userId, purpose} index enforces. Sharing one record would mean asking to
     * reset a PIN silently invalidated a pending signup code, and vice versa.
     */
    purpose: { type: String, required: true, enum: ['email-verify', 'pin-reset'], default: 'email-verify' },

    codeHash: { type: String, required: true, select: false },
    expiresAt: { type: Date, required: true },

    attempts: { type: Number, default: 0 },
    resends: { type: Number, default: 0 },
    lastSentAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
)

otpSchema.index({ userId: 1, purpose: 1 }, { unique: true })
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 })

otpSchema.set('toJSON', {
  transform(_doc, ret) {
    delete ret.codeHash
    return ret
  },
})

export const Otp = mongoose.model('Otp', otpSchema)
