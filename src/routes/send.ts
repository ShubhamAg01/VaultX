import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { get, run } from '../config/db';
import authMiddleware from '../middleware/auth';
import { authLimiter } from '../middleware/rateLimiter';
import { SendEntry } from '../types/database';

const router = Router();

// Create a temporary encrypted send
router.post('/', authMiddleware, async (req: Request, res: Response): Promise<void> => {
    const { encrypted_data, expiry_hours = 24, max_views = 1 } = req.body;
    if (!encrypted_data) {
        res.status(400).json({ error: 'Missing encrypted data' });
        return;
    }
    const hours = parseInt(expiry_hours);
    const views = parseInt(max_views);

    if (isNaN(hours) || hours < 1 || hours > 168) {
        res.status(400).json({ error: 'Expiry must be 1–168 hours' });
        return;
    }
    if (isNaN(views) || views < 1 || views > 10) {
        res.status(400).json({ error: 'Max views must be 1–10' });
        return;
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();

    await run(
        'INSERT INTO sends (token, encrypted_data, max_views, expires_at) VALUES (?, ?, ?, ?)',
        [token, encrypted_data, views, expiresAt]
    );

    res.json({ token });
});

// Retrieve and decrement/burn secret send
router.get('/:token', authLimiter, async (req: Request, res: Response): Promise<void> => {
    const rawToken = Array.isArray(req.params.token) ? req.params.token[0] : req.params.token;
    const token = String(rawToken || '');

    const send = await get<SendEntry>('SELECT * FROM sends WHERE token = ?', [token]);

    if (!send) {
        res.status(404).json({ error: 'Link not found or already burned' });
        return;
    }

    if (new Date(send.expires_at) < new Date()) {
        await run('DELETE FROM sends WHERE token = ?', [token]);
        res.status(410).json({ error: 'This secret link has expired' });
        return;
    }

    if (send.views >= send.max_views) {
        await run('DELETE FROM sends WHERE token = ?', [token]);
        res.status(410).json({ error: 'This secret link has reached maximum views' });
        return;
    }

    const newViews = send.views + 1;
    if (newViews >= send.max_views) {
        await run('DELETE FROM sends WHERE token = ?', [token]);
    } else {
        await run('UPDATE sends SET views = ? WHERE token = ?', [newViews, token]);
    }

    res.json({
        encrypted_data: send.encrypted_data,
        views_remaining: send.max_views - newViews
    });
});

export default router;
