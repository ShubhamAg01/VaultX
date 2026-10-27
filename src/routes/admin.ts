import { Router, Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { query, get, run } from '../config/db';
import { UserSummary, Invite } from '../types/database';

const router = Router();

const isAdmin = (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user || !req.user.isAdmin) {
        res.status(403).json({ error: 'Admin access required' });
        return;
    }
    next();
};

// List all registered users
router.get('/users', isAdmin, async (_req: Request, res: Response): Promise<void> => {
    const users = await query<UserSummary>(`
        SELECT u.id, u.username, u.is_admin, u.totp_enabled, u.created_at,
               COUNT(p.id) as entry_count
        FROM users u
        LEFT JOIN passwords p ON p.user_id = u.id
        GROUP BY u.id
        ORDER BY u.created_at ASC
    `);
    res.json(users);
});

// Instance statistics
router.get('/stats', isAdmin, async (_req: Request, res: Response): Promise<void> => {
    const userCount = await get<{ count: number }>('SELECT COUNT(*) as count FROM users');
    const passwordCount = await get<{ count: number }>('SELECT COUNT(*) as count FROM passwords');
    const sendCount = await get<{ count: number }>('SELECT COUNT(*) as count FROM sends');
    const activeInvitesCount = await get<{ count: number }>(
        "SELECT COUNT(*) as count FROM invites WHERE uses < max_uses AND datetime(expires_at) > datetime('now')"
    );

    res.json({
        users: userCount?.count || 0,
        passwords: passwordCount?.count || 0,
        sends: sendCount?.count || 0,
        activeInvites: activeInvitesCount?.count || 0
    });
});

// Generate invite link
router.post('/invites', isAdmin, async (req: Request, res: Response): Promise<void> => {
    if (!req.user) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }
    const { expiry_hours = 24, max_uses = 1 } = req.body;
    const hours = parseInt(expiry_hours);
    const uses = parseInt(max_uses);

    if (isNaN(hours) || hours < 1 || hours > 720) {
        res.status(400).json({ error: 'Expiry must be between 1 and 720 hours (30 days)' });
        return;
    }
    if (isNaN(uses) || uses < 1 || uses > 50) {
        res.status(400).json({ error: 'Max uses must be between 1 and 50' });
        return;
    }

    try {
        const code = crypto.randomBytes(24).toString('hex');
        const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();

        const result = await run(
            'INSERT INTO invites (code, created_by, max_uses, expires_at) VALUES (?, ?, ?, ?)',
            [code, req.user.userId, uses, expiresAt]
        );

        res.status(201).json({
            id: Number(result.lastInsertRowid),
            code,
            max_uses: uses,
            expires_at: expiresAt
        });
    } catch (err) {
        console.error('Error creating invite:', err);
        res.status(500).json({ error: 'Failed to create invite link' });
    }
});

// List active and expired invites
router.get('/invites', isAdmin, async (_req: Request, res: Response): Promise<void> => {
    const invites = await query<Invite>(`
        SELECT i.id, i.code, i.created_by, i.max_uses, i.uses, i.expires_at, i.created_at,
               u.username as creator_name
        FROM invites i
        LEFT JOIN users u ON u.id = i.created_by
        ORDER BY i.created_at DESC
    `);

    const now = new Date();
    const formatted = invites.map(inv => {
        const isExpired = new Date(inv.expires_at) < now;
        const isUsed = inv.uses >= inv.max_uses;
        let status: 'Active' | 'Used' | 'Expired' = 'Active';
        if (isUsed) status = 'Used';
        else if (isExpired) status = 'Expired';

        return {
            ...inv,
            status,
            is_active: status === 'Active'
        };
    });

    res.json(formatted);
});

// Revoke an invite
router.delete('/invites/:id', isAdmin, async (req: Request, res: Response): Promise<void> => {
    const inviteId = parseInt(Array.isArray(req.params.id) ? req.params.id[0] : req.params.id, 10);
    const result = await run('DELETE FROM invites WHERE id = ?', [inviteId]);
    if (!result.rowsAffected || result.rowsAffected === 0) {
        res.status(404).json({ error: 'Invite not found' });
        return;
    }
    res.json({ message: 'Invite revoked successfully' });
});

// Delete user account
router.delete('/users/:id', isAdmin, async (req: Request, res: Response): Promise<void> => {
    if (!req.user) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }
    const targetId = parseInt(Array.isArray(req.params.id) ? req.params.id[0] : req.params.id, 10);
    if (isNaN(targetId) || targetId === req.user.userId) {
        res.status(400).json({ error: 'Cannot delete your own account or invalid ID' });
        return;
    }
    const user = await get<{ id: number }>('SELECT id FROM users WHERE id = ?', [targetId]);
    if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
    }

    await run('DELETE FROM users WHERE id = ?', [targetId]);
    res.json({ message: 'User deleted successfully' });
});

// Toggle admin privileges
router.post('/users/:id/toggle-admin', isAdmin, async (req: Request, res: Response): Promise<void> => {
    if (!req.user) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }
    const targetId = parseInt(Array.isArray(req.params.id) ? req.params.id[0] : req.params.id, 10);
    if (isNaN(targetId) || targetId === req.user.userId) {
        res.status(400).json({ error: 'Cannot change your own admin status or invalid ID' });
        return;
    }
    const user = await get<{ is_admin: number }>('SELECT * FROM users WHERE id = ?', [targetId]);
    if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
    }

    const newStatus = user.is_admin ? 0 : 1;
    await run('UPDATE users SET is_admin = ? WHERE id = ?', [newStatus, targetId]);
    res.json({ message: `User ${newStatus ? 'promoted to' : 'removed from'} admin`, isAdmin: newStatus === 1 });
});

export default router;
