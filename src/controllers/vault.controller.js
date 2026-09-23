import * as vaultService from '../services/vault.service.js'

export async function listItems(req, res, next) {
  try {
    const { category, favorite, folder } = req.query
    const items = await vaultService.listItems(req.user.id, {
      category,
      favorite: favorite === 'true',
      folder,
    })
    res.json({ data: items })
  } catch (err) { next(err) }
}

export async function getItem(req, res, next) {
  try {
    res.json({ data: await vaultService.getItem(req.user.id, req.params.id) })
  } catch (err) { next(err) }
}

export async function createItem(req, res, next) {
  try {
    res.status(201).json({ data: await vaultService.createItem(req.user.id, req.body) })
  } catch (err) { next(err) }
}

export async function updateItem(req, res, next) {
  try {
    res.json({ data: await vaultService.updateItem(req.user.id, req.params.id, req.body) })
  } catch (err) { next(err) }
}

export async function deleteItem(req, res, next) {
  try {
    res.json({ data: await vaultService.deleteItem(req.user.id, req.params.id) })
  } catch (err) { next(err) }
}

export async function stats(req, res, next) {
  try {
    res.json({ data: await vaultService.getStats(req.user.id) })
  } catch (err) { next(err) }
}
