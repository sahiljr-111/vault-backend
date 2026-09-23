import mongoose from 'mongoose'
import { VaultItem } from '../models/vault-item.model.js'
import { notFound } from '../utils/app-error.js'

/**
 * Security rules 1, 2. This service moves opaque blobs. It never inspects
 * `encryptedData`, never parses it, never validates its contents.
 *
 * EVERY query is scoped by userId taken from the verified JWT — never from the
 * request body or a URL param. That is what prevents IDOR.
 */

const PROJECTION = 'category encryptedData iv metadata createdAt updatedAt'

export async function listItems(userId, { category, favorite, folder } = {}) {
  const query = { userId }
  if (category) query.category = category
  if (favorite === true) query['metadata.favorite'] = true
  if (folder) query['metadata.folder'] = folder

  // Returns ciphertext + metadata. Decryption and search-by-secret are the
  // client's job — this server literally cannot do them.
  return VaultItem.find(query).select(PROJECTION).sort({ updatedAt: -1 }).lean()
}

export async function getItem(userId, itemId) {
  const item = await VaultItem.findOne({ _id: itemId, userId }).select(PROJECTION).lean()
  if (!item) throw notFound('Item not found.')
  return item
}

export async function createItem(userId, { category, encryptedData, iv, metadata }) {
  return VaultItem.create({ userId, category, encryptedData, iv, metadata })
}

/**
 * A vault-item update always carries a FRESH iv, because re-encrypting with a
 * reused nonce would break AES-GCM catastrophically. The client generates it;
 * this schema requires it, so an update can never silently keep the old one.
 */
export async function updateItem(userId, itemId, patch) {
  const update = {}
  if (patch.category !== undefined) update.category = patch.category
  if (patch.encryptedData !== undefined) update.encryptedData = patch.encryptedData
  if (patch.iv !== undefined) update.iv = patch.iv
  if (patch.metadata !== undefined) {
    for (const [k, v] of Object.entries(patch.metadata)) update[`metadata.${k}`] = v
  }

  const item = await VaultItem.findOneAndUpdate(
    { _id: itemId, userId },
    { $set: update },
    { new: true, runValidators: true }
  ).select(PROJECTION).lean()

  if (!item) throw notFound('Item not found.')
  return item
}

/** Phase 1 is a hard delete. Soft-delete/trash is Phase 2 — do not add it here. */
export async function deleteItem(userId, itemId) {
  const res = await VaultItem.deleteOne({ _id: itemId, userId })
  if (res.deletedCount === 0) throw notFound('Item not found.')
  return { deleted: true }
}

/** Dashboard counts, computed from metadata only — no decryption needed. */
export async function getStats(userId) {
  const [byCategory, favorites, total] = await Promise.all([
    VaultItem.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(String(userId)) } },
      { $group: { _id: '$category', count: { $sum: 1 } } },
    ]),
    VaultItem.countDocuments({ userId, 'metadata.favorite': true }),
    VaultItem.countDocuments({ userId }),
  ])

  const counts = { password: 0, bank: 0, card: 0, note: 0 }
  for (const row of byCategory) counts[row._id] = row.count
  return { total, favorites, byCategory: counts }
}
