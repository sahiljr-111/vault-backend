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
    return ret
  },
})

export const User = mongoose.model('User', userSchema)
