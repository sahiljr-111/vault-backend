import { Router } from 'express'
import { z } from 'zod'
import * as backupController from '../controllers/backup.controller.js'
import { validate } from '../middlewares/validate.middleware.js'
import { requireAuth } from '../middlewares/auth.middleware.js'
import { restoreLimiter } from '../middlewares/rate-limit.middleware.js'

const router = Router()

/** Rule 7: only an encrypted archive is accepted. There is no plaintext import. */
const restoreBody = z
  .object({
    archive: z.object({
      format: z.literal('personal-vault-backup'),
      version: z.number().int().positive(),
      createdAt: z.string().optional(),
      kdf: z.record(z.any()).optional(),
      items: z
        .array(
          z
            .object({
              category: z.string(),
              encryptedData: z.string().min(1),
              iv: z.string().min(1),
              metadata: z.record(z.any()),
              createdAt: z.any().optional(),
              updatedAt: z.any().optional(),
            })
            .strip()
        )
        .max(10_000),
    }),
    mode: z.enum(['merge', 'replace']).default('merge'),
  })
  .strict()

router.use(requireAuth)

router.post('/export', backupController.exportBackup)
router.post('/email', backupController.emailBackup)
router.get('/', backupController.listBackups)

// Rule 8 — restore is a master-password guessing oracle without a limiter.
router.post('/restore', restoreLimiter, validate(restoreBody), backupController.restoreBackup)

export default router
