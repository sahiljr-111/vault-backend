import mongoose from 'mongoose'

/**
 * Security rule 7 — backups are encrypted blobs ONLY.
 *
 * `encryptedBlob` is built client-side from already-encrypted items. No code path
 * in this project may produce a plaintext export: not behind a debug flag, not to
 * a temp file, not in a test fixture.
 *
 * `kdfParams` records the Argon2id parameters + format version in the clear. This
 * is required, not optional: without it a restore onto a fresh device can never
 * re-derive the right key. Parameters are not secrets — the salt they pair with is
 * stored per-user, and the master password is what stays unknown.
 */
const backupSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    encryptedBlob: { type: String, required: true },
    itemCount: { type: Number, default: 0 }, // count only — never a manifest of titles
    kdfParams: {
      version: { type: Number, default: 1 },
      algorithm: { type: String, default: 'argon2id' },
      iterations: Number,
      memory: Number,
      parallelism: Number,
    },
  },
  { timestamps: true }
)

backupSchema.index({ userId: 1, createdAt: -1 })

export const Backup = mongoose.model('Backup', backupSchema)
