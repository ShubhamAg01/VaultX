import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { AuthUserPayload } from '../types/database';

export const authMiddleware = (req: Request, res: Response, next: NextFunction): void => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ error: 'Unauthorized: Missing or invalid token format' });
        return;
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET || 'vaultx-secret-fallback'
        ) as AuthUserPayload;

        if (decoded.type !== 'auth') {
            res.status(401).json({ error: 'Invalid token type' });
            return;
        }

        req.user = decoded;
        next();
    } catch {
        res.status(401).json({ error: 'Invalid or expired session token' });
    }
};

export default authMiddleware;
