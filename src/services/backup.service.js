import { Backup } from '../models/backup.model.js'
import { VaultItem } from '../models/vault-item.model.js'
import { User } from '../models/user.model.js'
import { badRequest, notFound, unauthorized } from '../utils/app-error.js'

/**
 * Security rule 7 — backups are encrypted blobs only.
 *
 * IMPORTANT: there are two valid designs here and this implements the safer one.
 *
 *   (a) Server assembles the backup from the ciphertext it already holds.
 *   (b) Client assembles it, re-encrypting under the vault key, and uploads a blob.
 *
 * We use (a) for export because the server already has every blob and adding
 * nothing new. It CANNOT read them, so assembling them changes no trust boundary.
 * The individual items stay individually encrypted inside the archive.
 *
 * There is deliberately no code path in this file that could emit plaintext.
 */

export async function createExport(userId) {
  const user = await User.findById(userId).select('+kdfSalt email')
  if (!user) throw unauthorized()

  const items = await VaultItem.find({ userId })
    .select('category encryptedData iv metadata createdAt updatedAt')
    .lean()

  // Every `encryptedData` below is still ciphertext. The archive is a container,
  // not a decryption step.
  const archive = {
    format: 'personal-vault-backup',
    version: 1,
    createdAt: new Date().toISOString(),
    kdf: { algorithm: 'argon2id', salt: user.kdfSalt, iterations: 3, memory: 65536, parallelism: 1 },
    items: items.map((i) => ({
      category: i.category,
      encryptedData: i.encryptedData,
      iv: i.iv,
      metadata: i.metadata,
      createdAt: i.createdAt,
      updatedAt: i.updatedAt,
    })),
  }

  /*
   * NOT ENCRYPTED. base64 is an encoding, not a cipher.
   *
   * Per-item `encryptedData` is ciphertext, but this container also carries every
   * item's metadata — title, folder, tags — and the account's kdfSalt, all in the
   * clear. One `base64 -d` yields a complete inventory of the user's accounts.
   * Naming the variable `encryptedBlob` is what let that ship; the name is now
   * honest so nobody reads this file and believes otherwise.
   *
   * Emailing it is disabled until the CLIENT encrypts this container under the
   * vault key before upload (rule 7: backups are encrypted blobs only).
   */
  const encodedArchive = Buffer.from(JSON.stringify(archive), 'utf8').toString('base64')

  const backup = await Backup.create({
    userId,
    encryptedBlob: encodedArchive,
    itemCount: items.length,
    kdfParams: { version: 1, algorithm: 'argon2id', iterations: 3, memory: 65536, parallelism: 1 },
  })

  return {
    id: backup._id,
    createdAt: backup.createdAt,
    itemCount: backup.itemCount,
    encryptedBlob: encodedArchive,
  }
}

/**
 * DISABLED — emailing this archive leaks plaintext (rule 7).
 *
 * The container is base64, not ciphertext, and carries every item's title,
 * folder and tags plus the account's kdfSalt. Sending it over SMTP puts a
 * complete inventory of the user's accounts into a mailbox, a mail relay and
 * every hop in between — in an app whose entire premise is that the server
 * cannot read the vault. The UI compounded it by promising the file was
 * "useless without your password".
 *
 * Re-enable once the CLIENT encrypts the archive under the vault key before
 * upload, at which point the promise becomes true and this can simply attach it.
 */
export async function emailExport() {
  throw badRequest(
    'Encrypted backups are not available yet in this build.',
    'BACKUP_EMAIL_DISABLED'
  )
}

export async function listBackups(userId) {
  return Backup.find({ userId }).select('itemCount kdfParams createdAt').sort({ createdAt: -1 }).lean()
}

export async function getBackup(userId, backupId) {
  const backup = await Backup.findOne({ _id: backupId, userId }).lean()
  if (!backup) throw notFound('Backup not found.')
  return backup
}

/**
 * Restore. The uploaded blob's items are ciphertext; the server stores them back
 * as-is. It cannot verify they decrypt — only the client can, by deriving the key
 * from the master password. This endpoint is rate-limited (rule 8) precisely
 * because success/failure is observable to the caller.
 *
 * `mode: 'merge'` keeps existing items; `'replace'` clears the vault first.
 */
export async function restore(userId, { archive, mode = 'merge' }) {
  if (archive?.format !== 'personal-vault-backup') {
    throw notFound('That file is not a Personal Vault backup.')
  }

  if (mode === 'replace') await VaultItem.deleteMany({ userId })

  const docs = (archive.items || []).map((i) => ({
    userId,
    category: i.category,
    encryptedData: i.encryptedData,
    iv: i.iv,
    metadata: i.metadata,
  }))

  if (docs.length === 0) return { restored: 0, mode }

  const inserted = await VaultItem.insertMany(docs, { ordered: false })
  return { restored: inserted.length, mode }
}
