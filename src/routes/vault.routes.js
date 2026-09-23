import { Router } from 'express'
import { z } from 'zod'
import * as vaultController from '../controllers/vault.controller.js'
import { validate } from '../middlewares/validate.middleware.js'
import { requireAuth } from '../middlewares/auth.middleware.js'
import { VAULT_CATEGORIES } from '../models/vault-item.model.js'

const router = Router()

/**
 * Rules 1, 2. This schema is the plaintext gate.
 *
 * `.strict()` means an unknown key is REJECTED, not stripped-and-ignored — so a
 * client that tried to send `{ password: '...' }` or `{ cardLast4: '4242' }`
 * alongside the blob gets a 400 instead of quietly persisting plaintext.
 *
 * `metadata` lists every field allowed to be plaintext. Adding a field here is a
 * security decision: it must be non-sensitive (see the classification table in
 * the vault-security skill).
 */
const metadata = z
  .object({
    title: z.string().min(1).max(200).trim(),
    folder: z.string().max(100).trim().optional(),
    tags: z.array(z.string().max(50)).max(20).optional(),
    favorite: z.boolean().optional(),
  })
  .strict()

const createItem = z
  .object({
    category: z.enum(VAULT_CATEGORIES),
    // Opaque base64 AEAD blob. Never parsed, never validated for content.
    encryptedData: z.string().min(1).max(200_000).regex(/^[A-Za-z0-9+/=]+$/, 'base64'),
    // 12-byte GCM nonce, base64. Client MUST send a fresh one on every write.
    iv: z.string().min(1).max(64).regex(/^[A-Za-z0-9+/=]+$/, 'base64'),
    metadata,
  })
  .strict()

// An update requires a fresh iv whenever encryptedData changes — a reused nonce
// under the same key breaks AES-GCM. Enforced together via refine().
const updateItem = createItem
  .partial()
  .extend({ metadata: metadata.partial().optional() })
  .strict()
  .refine(
    (d) => (d.encryptedData === undefined) === (d.iv === undefined),
    { message: 'encryptedData and iv must be sent together (fresh nonce required)', path: ['iv'] }
  )

const listQuery = z
  .object({
    category: z.enum(VAULT_CATEGORIES).optional(),
    favorite: z.enum(['true', 'false']).optional(),
    folder: z.string().max(100).optional(),
  })
  .strict()

const idParam = z.object({ id: z.string().regex(/^[a-f\d]{24}$/i, 'invalid id') }).strict()

router.use(requireAuth) // every route below is user-scoped

router.get('/stats', vaultController.stats)
router.get('/items', validate(listQuery, 'query'), vaultController.listItems)
router.post('/items', validate(createItem), vaultController.createItem)
router.get('/items/:id', validate(idParam, 'params'), vaultController.getItem)
router.put('/items/:id', validate(idParam, 'params'), validate(updateItem), vaultController.updateItem)
router.delete('/items/:id', validate(idParam, 'params'), vaultController.deleteItem)

export default router
