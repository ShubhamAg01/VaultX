import { Router, Request, Response } from 'express';
import { body, validationResult } from 'express-validator';
import { query, get, run, transaction } from '../config/db';
import { PasswordEntry } from '../types/database';

const router = Router();

// List encrypted credentials for user
router.get('/', async (req: Request, res: Response): Promise<void> => {
    if (!req.user) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }
    const passwords = await query<PasswordEntry>(
        'SELECT id, encrypted_data, iv, created_at, updated_at FROM passwords WHERE user_id = ? ORDER BY created_at DESC',
        [req.user.userId]
    );
    res.json(passwords);
});

// Create new credential entry
router.post('/', [
    body('encrypted_data').notEmpty().isHexadecimal().withMessage('Invalid encrypted data payload'),
    body('iv').notEmpty().isHexadecimal().withMessage('Invalid initialization vector')
], async (req: Request, res: Response): Promise<void> => {
    if (!req.user) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400).json({ errors: errors.array() });
        return;
    }

    const { encrypted_data, iv } = req.body;
    const result = await run(
        'INSERT INTO passwords (user_id, encrypted_data, iv) VALUES (?, ?, ?)',
        [req.user.userId, encrypted_data, iv]
    );

    res.status(201).json({ id: Number(result.lastInsertRowid), message: 'Password saved securely' });
});

// Update existing credential
router.put('/:id', [
    body('encrypted_data').notEmpty().isHexadecimal().withMessage('Invalid encrypted data payload'),
    body('iv').notEmpty().isHexadecimal().withMessage('Invalid initialization vector')
], async (req: Request, res: Response): Promise<void> => {
    if (!req.user) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400).json({ errors: errors.array() });
        return;
    }

    const { encrypted_data, iv } = req.body;
    const entryId = parseInt(Array.isArray(req.params.id) ? req.params.id[0] : req.params.id, 10);
    const entry = await get<{ id: number }>('SELECT id FROM passwords WHERE id = ? AND user_id = ?', [entryId, req.user.userId]);
    if (!entry) {
        res.status(404).json({ error: 'Entry not found' });
        return;
    }

    await run(
        'UPDATE passwords SET encrypted_data = ?, iv = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
        [encrypted_data, iv, entryId, req.user.userId]
    );

    res.json({ message: 'Password updated securely' });
});

// Delete credential
router.delete('/:id', async (req: Request, res: Response): Promise<void> => {
    if (!req.user) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }
    const entryId = parseInt(Array.isArray(req.params.id) ? req.params.id[0] : req.params.id, 10);
    const entry = await get<{ id: number }>('SELECT id FROM passwords WHERE id = ? AND user_id = ?', [entryId, req.user.userId]);
    if (!entry) {
        res.status(404).json({ error: 'Entry not found' });
        return;
    }

    await run('DELETE FROM passwords WHERE id = ? AND user_id = ?', [entryId, req.user.userId]);
    res.json({ message: 'Password deleted' });
});

// Batch import credentials
router.post('/batch', [
    body('items').isArray({ min: 1, max: 1000 }).withMessage('Items must be an array of up to 1000 credentials'),
    body('items.*.encrypted_data').notEmpty().isHexadecimal(),
    body('items.*.iv').notEmpty().isHexadecimal()
], async (req: Request, res: Response): Promise<void> => {
    if (!req.user) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400).json({ errors: errors.array() });
        return;
    }

    const { items } = req.body as { items: Array<{ encrypted_data: string; iv: string }> };
    const userId = req.user.userId;

    const imported = await transaction(async (tx) => {
        let count = 0;
        for (const r of items) {
            await tx.run('INSERT INTO passwords (user_id, encrypted_data, iv) VALUES (?, ?, ?)', [userId, r.encrypted_data, r.iv]);
            count++;
        }
        return count;
    });

    res.status(201).json({ count: imported, message: `Successfully imported ${imported} credentials` });
});

// k-Anonymity breach check proxy (HIBP range API)
router.get('/pwned-check/:prefix', async (req: Request, res: Response): Promise<void> => {
    const rawPrefix = Array.isArray(req.params.prefix) ? req.params.prefix[0] : req.params.prefix;
    const prefix = String(rawPrefix || '').toUpperCase().trim();
    if (!/^[0-9A-F]{5}$/.test(prefix)) {
        res.status(400).json({ error: 'Invalid 5-character hex prefix' });
        return;
    }

    try {
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
            headers: { 'User-Agent': 'VaultX-ZeroKnowledge-PasswordManager' }
        });
        if (!response.ok) {
            res.status(502).json({ error: 'Could not contact breach service' });
            return;
        }
        const text = await response.text();
        res.type('text/plain').send(text);
    } catch {
        res.status(502).json({ error: 'Failed to verify breach status' });
    }
});

export default router;
