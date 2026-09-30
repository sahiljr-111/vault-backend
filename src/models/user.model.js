import mongoose from 'mongoose'

/**
 * Security rules 1, 2, 4, 5.
 *
 * `passwordHash` is the LOGIN password only (bcrypt) — it is NOT the vault key and
 * cannot decrypt anything. The vault key is derived client-side from the master
 * password, which never reaches this server in any form.
 *
 * `kdfSalt` is not secret, but must be unique per user and CSPRNG-generated. The
 * client needs it to re-derive the vault key on every unlock.
 *
 * `verifier*` is an encrypted canary (a fixed known plaintext). It lets the CLIENT
 * check "was that master password correct?" offline. The server cannot decrypt it,
 * so it learns nothing — which is exactly why there is no /verify-master-password
 * endpoint.
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

    // Master-password canary. Opaque ciphertext — never parsed server-side.
    verifierCiphertext: { type: String, select: false },
    verifierIv: { type: String, select: false },

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
    delete ret.verifierCiphertext
    delete ret.verifierIv
    delete ret.refreshTokenHash
    delete ret.prevRefreshTokenHash
    return ret
  },
})

export const User = mongoose.model('User', userSchema)
