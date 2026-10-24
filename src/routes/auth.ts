import { Router, Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { body, query, validationResult } from 'express-validator';
import { get, run, transaction } from '../config/db';
import { authLimiter } from '../middleware/rateLimiter';
import authMiddleware from '../middleware/auth';
import { User, Invite } from '../types/database';

const router = Router();

// Check if first-time setup is needed
router.get('/status', async (_req: Request, res: Response): Promise<void> => {
    const count = await get<{ count: number }>('SELECT COUNT(*) as count FROM users');
    res.json({ initialized: (count?.count || 0) > 0 });
});

// Fetch user salt for client PBKDF2 derivation (or return deterministic dummy salt)
router.get('/pre-login', authLimiter, [
    query('username').trim().notEmpty()
], async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400).json({ error: 'Username required' });
        return;
    }

    const username = (req.query.username as string).trim();
    const user = await get<Pick<User, 'pbkdf2_salt'>>('SELECT pbkdf2_salt FROM users WHERE LOWER(username) = LOWER(?)', [username]);

    if (user) {
        res.json({ salt: user.pbkdf2_salt });
        return;
    }

    // Deterministic salt for non-existent users to mitigate timing/enumeration attacks
    const fakeSalt = crypto
        .createHmac('sha256', process.env.JWT_SECRET || 'vaultx-secret-fallback')
        .update(username.toLowerCase())
        .digest('hex');

    res.json({ salt: fakeSalt });
});

// User registration (first user becomes admin; subsequent users require invite code)
router.post('/register', [
    body('username').trim().isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9_]+$/).withMessage('Username must be 3–30 alphanumeric/underscore characters'),
    body('authHash').isHexadecimal().isLength({ min: 64, max: 64 }).withMessage('Invalid authentication hash format'),
    body('pbkdf2Salt').isHexadecimal().isLength({ min: 64, max: 64 }).withMessage('Invalid salt format')
], async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400).json({ errors: errors.array() });
        return;
    }

    const { username, authHash, pbkdf2Salt, inviteCode } = req.body;

    try {
        const userCount = await get<{ count: number }>('SELECT COUNT(*) as count FROM users');
        const isFirstUser = (userCount?.count || 0) === 0;

        let inviteIdToBurn: number | null = null;

        if (!isFirstUser) {
            if (!inviteCode || typeof inviteCode !== 'string') {
                res.status(403).json({ error: 'Registration is invite-only. A valid invite link is required.' });
                return;
            }

            const invite = await get<Invite>('SELECT * FROM invites WHERE code = ?', [inviteCode.trim()]);
            if (!invite) {
                res.status(400).json({ error: 'Invalid invite code.' });
                return;
            }

            if (new Date(invite.expires_at) < new Date()) {
                res.status(400).json({ error: 'This invite link has expired. Please ask your administrator for a new invite.' });
                return;
            }

            if (invite.uses >= invite.max_uses) {
                res.status(400).json({ error: 'This invite link has already been used.' });
                return;
            }

            inviteIdToBurn = invite.id;
        }

        const existing = await get<{ id: number }>('SELECT id FROM users WHERE LOWER(username) = LOWER(?)', [username]);
        if (existing) {
            res.status(409).json({ error: 'Username already taken' });
            return;
        }

        const passwordHash = await bcrypt.hash(authHash, 12);
        const isAdmin = isFirstUser ? 1 : 0;

        await transaction(async (tx) => {
            await tx.run(
                'INSERT INTO users (username, password_hash, pbkdf2_salt, is_admin) VALUES (?, ?, ?, ?)',
                [username, passwordHash, pbkdf2Salt, isAdmin]
            );

            if (inviteIdToBurn) {
                await tx.run('UPDATE invites SET uses = uses + 1 WHERE id = ?', [inviteIdToBurn]);
            }
        });

        res.status(201).json({
            message: 'Account created successfully',
            isAdmin: isAdmin === 1,
            isFirstUser
        });
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

// User login
router.post('/login', authLimiter, [
    body('username').trim().notEmpty(),
    body('authHash').isHexadecimal().isLength({ min: 64, max: 64 })
], async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400).json({ errors: errors.array() });
        return;
    }

    const { username, authHash } = req.body;

    try {
        const user = await get<User>('SELECT * FROM users WHERE LOWER(username) = LOWER(?)', [username]);
        if (!user) {
            res.status(401).json({ error: 'Invalid credentials' });
            return;
        }

        const valid = await bcrypt.compare(authHash, user.password_hash);
        if (!valid) {
            res.status(401).json({ error: 'Invalid credentials' });
            return;
        }

        if (user.totp_enabled) {
            const preAuthToken = jwt.sign(
                { userId: user.id, type: 'pre_auth' },
                process.env.JWT_SECRET || 'vaultx-secret-fallback',
                { expiresIn: '5m' }
            );
            res.json({ requires2FA: true, preAuthToken });
            return;
        }

        const token = jwt.sign(
            { userId: user.id, username: user.username, isAdmin: user.is_admin === 1, type: 'auth' },
            process.env.JWT_SECRET || 'vaultx-secret-fallback',
            { expiresIn: '8h' }
        );
        res.json({ token, isAdmin: user.is_admin === 1, username: user.username });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Verify 2FA code during login
router.post('/2fa/validate', authLimiter, async (req: Request, res: Response): Promise<void> => {
    const { preAuthToken, code } = req.body;
    if (!preAuthToken || !code) {
        res.status(400).json({ error: 'Missing fields' });
        return;
    }

    try {
        const decoded = jwt.verify(
            preAuthToken,
            process.env.JWT_SECRET || 'vaultx-secret-fallback'
        ) as { userId: number; type: string };

        if (decoded.type !== 'pre_auth') {
            res.status(401).json({ error: 'Invalid token' });
            return;
        }

        const user = await get<User>('SELECT * FROM users WHERE id = ?', [decoded.userId]);
        if (!user || !user.totp_secret) {
            res.status(401).json({ error: 'User not found or 2FA not configured' });
            return;
        }

        const verified = speakeasy.totp.verify({
            secret: user.totp_secret,
            encoding: 'base32',
            token: code,
            window: 1
        });
        if (!verified) {
            res.status(401).json({ error: 'Invalid 2FA code' });
            return;
        }

        const token = jwt.sign(
            { userId: user.id, username: user.username, isAdmin: user.is_admin === 1, type: 'auth' },
            process.env.JWT_SECRET || 'vaultx-secret-fallback',
            { expiresIn: '8h' }
        );
        res.json({ token, isAdmin: user.is_admin === 1, username: user.username });
    } catch {
        res.status(401).json({ error: 'Invalid or expired token' });
    }
});

// Generate TOTP secret and QR code
router.post('/2fa/setup', authMiddleware, async (req: Request, res: Response): Promise<void> => {
    if (!req.user) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }
    const user = await get<User>('SELECT * FROM users WHERE id = ?', [req.user.userId]);
    if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
    }

    const secret = speakeasy.generateSecret({ name: `VaultX:${user.username}`, length: 32 });
    await run('UPDATE users SET totp_secret = ? WHERE id = ?', [secret.base32, user.id]);

    const qrCode = await QRCode.toDataURL(secret.otpauth_url || '');
    res.json({ qrCode, secret: secret.base32 });
});

// Enable 2FA after verifying code
router.post('/2fa/verify', authMiddleware, async (req: Request, res: Response): Promise<void> => {
    if (!req.user) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }
    const { code } = req.body;
    const user = await get<User>('SELECT * FROM users WHERE id = ?', [req.user.userId]);

    if (!user || !user.totp_secret) {
        res.status(400).json({ error: '2FA setup not initiated' });
        return;
    }

    const verified = speakeasy.totp.verify({
        secret: user.totp_secret,
        encoding: 'base32',
        token: code,
        window: 1
    });
    if (!verified) {
        res.status(400).json({ error: 'Invalid code. Please try again.' });
        return;
    }

    await run('UPDATE users SET totp_enabled = 1 WHERE id = ?', [user.id]);
    res.json({ message: '2FA enabled successfully' });
});

// Disable 2FA
router.post('/2fa/disable', authMiddleware, async (req: Request, res: Response): Promise<void> => {
    if (!req.user) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }
    const { code } = req.body;
    const user = await get<User>('SELECT * FROM users WHERE id = ?', [req.user.userId]);

    if (!user || !user.totp_enabled || !user.totp_secret) {
        res.status(400).json({ error: '2FA is not enabled' });
        return;
    }

    const verified = speakeasy.totp.verify({
        secret: user.totp_secret,
        encoding: 'base32',
        token: code,
        window: 1
    });
    if (!verified) {
        res.status(400).json({ error: 'Invalid code' });
        return;
    }

    await run('UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?', [user.id]);
    res.json({ message: '2FA disabled' });
});

// Current user profile
router.get('/me', authMiddleware, async (req: Request, res: Response): Promise<void> => {
    if (!req.user) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }
    const user = await get('SELECT id, username, is_admin, totp_enabled, created_at FROM users WHERE id = ?', [req.user.userId]);
    if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
    }
    res.json(user);
});

export default router;
