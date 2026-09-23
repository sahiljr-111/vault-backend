import mongoose from 'mongoose'

/** Phase 1 categories only. Phase 2/3 categories (identity, dev_secret) are NOT here. */
export const VAULT_CATEGORIES = ['password', 'bank', 'card', 'note']

/**
 * Security rules 1, 2. THE core schema — TRD §10.2.
 *
 * `encryptedData` is an opaque base64 AEAD blob produced client-side. This server
 * never parses it, never validates its contents, never logs it, and never infers
 * anything from it. Every sensitive field lives inside it:
 *
 *   password | username | netbanking login+password | profile password
 *   accountNumber | ifsc | mpin | cardNumber | expiry | cvv | pin | notes | customFields
 *
 * `metadata` holds ONLY non-sensitive fields, plaintext so the DB can search/sort.
 *
 * NEVER add a sensitive top-level field here — no `cardLast4`, no `bankName`, no
 * `username`, however convenient a list view would find it. That is rule 2, and it
 * has no exceptions. New category => add to VAULT_CATEGORIES, reuse this shape.
 */
const vaultItemSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    category: { type: String, enum: VAULT_CATEGORIES, required: true },

    encryptedData: { type: String, required: true }, // opaque ciphertext + auth tag, base64
    iv: { type: String, required: true }, // 12-byte AES-GCM nonce, base64. Unique per encrypt.

    metadata: {
      title: { type: String, required: true, trim: true, maxlength: 200 },
      folder: { type: String, trim: true, maxlength: 100 },
      tags: { type: [String], default: [] },
      favorite: { type: Boolean, default: false },
    },
  },
  { timestamps: true }
)

vaultItemSchema.index({ userId: 1, category: 1 })
vaultItemSchema.index({ userId: 1, 'metadata.favorite': 1 })
vaultItemSchema.index({ userId: 1, updatedAt: -1 })

export const VaultItem = mongoose.model('VaultItem', vaultItemSchema)
