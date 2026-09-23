import { Router } from 'express'
import authRoutes from './auth.routes.js'
import vaultRoutes from './vault.routes.js'
import backupRoutes from './backup.routes.js'

const router = Router()

router.get('/health', (_req, res) => res.json({ data: { status: 'ok' } }))
router.use('/auth', authRoutes)
router.use('/vault', vaultRoutes)
router.use('/backup', backupRoutes)

export default router
