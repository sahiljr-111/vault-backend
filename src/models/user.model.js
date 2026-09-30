import mongoose from 'mongoose'

/**
 * Security rules 1, 2, 4, 5.
 *
 * `passwordHash` is the LOGIN password only (bcrypt) — it is NOT the vault key
 * and cannot decrypt anything. The account password never reaches this server
 * in a form that could open a vault.
 *
 * `kdfSalt` is not secret, but must be unique per user and CSPRNG-generated.
 * The client needs it to re-derive the wrapping key on every unlock.
 *
 * `wrappedKey*` / `recovery*` hold the vault key sealed under the password and
 * under the recovery code. The server stores both and can open neither — see
 * the field comments below.
 */
const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    // select:false so a careless res.json(user) cannot leak these
    passwordHash: { type: String, required: true, select: false },
    kdfSalt: { type: String, required: true, select: false },

    /*
     * The vault key, sealed twice — once under the password, once under the
     * recovery code. Both are opaque to this server (rule 1): it stores them,
     * hands them back, and can open neither.
     *
     * This replaced deriving the key FROM the password. That made the password
     * and the key one fact, so changing the password changed the key and
     * orphaned every item — there was no change-password, and a forgotten
     * password was permanent. Wrapping a random key instead makes a password
     * change a rewrite of one small blob, and makes recovery possible at all.
     *
     * `kdfSalt` and `recoverySalt` are public by design; the blobs are AEAD, so
     * a wrong password fails the tag rather than producing a plausible key —
     * which is why the old `verifier*` canary is gone rather than kept.
     */
    wrappedKeyCiphertext: { type: String, select: false },
    wrappedKeyNonce: { type: String, select: false },

    recoverySalt: { type: String, select: false },
    recoveryCiphertext: { type: String, select: false },
    recoveryNonce: { type: String, select: false },

    // Set once the client has derived a key and stored the canary.
    vaultInitialized: { type: Boolean, default: false },

    /**
     * No session is issued until this is true. An unverified account is a parked
     * row, not a usable login — otherwise "sign up with someone else's address"
     * would hand out a working account before they ever saw the email.
     */
    emailVerified: { type: Boolean, default: false },

    refreshTokenHash: { type: String, select: false },
    /*
     * The token the current one replaced, honoured for a short grace window.
     *
     * Rotation is single-use: refreshing invalidates the old token instantly.
     * That is the right default, but with no grace period a LOST RESPONSE is
     * indistinguishable from a stolen token — if the app dies between the server
     * rotating and the device saving the new pair (an app update, a force-stop,
     * a dropped connection at the wrong moment), the device is left holding a
     * token the server has already retired, and the next launch signs the user
     * out and wipes their PIN. One dropped packet should not cost someone their
     * device setup.
     */
    prevRefreshTokenHash: { type: String, select: false },
    prevRefreshAt: { type: Date, select: false },
    lastLoginAt: Date,
  },
  { timestamps: true }
)

/** Defence in depth: strip secrets from any accidental serialization. */
userSchema.set('toJSON', {
  transform(_doc, ret) {
    delete ret.passwordHash
    delete ret.kdfSalt
    delete ret.wrappedKeyCiphertext
    delete ret.wrappedKeyNonce
    delete ret.recoverySalt
    delete ret.recoveryCiphertext
    delete ret.recoveryNonce
    delete ret.refreshTokenHash
    delete ret.prevRefreshTokenHash
    return ret
  },
})

export const User = mongoose.model('User', userSchema)
