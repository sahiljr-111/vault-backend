import * as backupService from '../services/backup.service.js'

export async function exportBackup(req, res, next) {
  try {
    res.json({ data: await backupService.createExport(req.user.id) })
  } catch (err) { next(err) }
}

export async function emailBackup(req, res, next) {
  try {
    res.json({ data: await backupService.emailExport(req.user.id) })
  } catch (err) { next(err) }
}

export async function listBackups(req, res, next) {
  try {
    res.json({ data: await backupService.listBackups(req.user.id) })
  } catch (err) { next(err) }
}

export async function restoreBackup(req, res, next) {
  try {
    res.json({ data: await backupService.restore(req.user.id, req.body) })
  } catch (err) { next(err) }
}
