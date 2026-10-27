import dotenv from 'dotenv';
dotenv.config();

// Ensure BigInt (returned by database drivers) serializes gracefully in JSON responses
(BigInt.prototype as unknown as { toJSON: () => number }).toJSON = function () {
    return Number(this);
};

import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import path from 'path';
import { initDb } from './config/db';
import authRoutes from './routes/auth';
import passwordRoutes from './routes/passwords';
import adminRoutes from './routes/admin';
import sendRoutes from './routes/send';
import { apiLimiter } from './middleware/rateLimiter';
import authMiddleware from './middleware/auth';

export const app = express();
const PORT = process.env.PORT || 3000;

// Security headers and CSP
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            scriptSrcAttr: ["'unsafe-inline'", "'unsafe-hashes'"],
            styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
            fontSrc: ["'self'", 'https://fonts.gstatic.com'],
            imgSrc: ["'self'", 'data:'],
            connectSrc: ["'self'", 'https://api.pwnedpasswords.com']
        }
    },
    crossOriginEmbedderPolicy: false
}));

app.use(cors({ origin: process.env.FRONTEND_URL || `http://localhost:${PORT}`, credentials: true }));
app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: true }));

const publicDir = path.join(__dirname, '..', 'public');
app.use(express.static(publicDir));

// Health check endpoint for monitoring/keep-alive
app.get('/health', (_req: Request, res: Response) => {
    res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Favicon handler
app.get('/favicon.ico', (_req: Request, res: Response) => {
    res.type('image/svg+xml').sendFile(path.join(publicDir, 'favicon.svg'));
});

// Rate limiting
app.use('/api/', apiLimiter);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/passwords', authMiddleware, passwordRoutes);
app.use('/api/admin', authMiddleware, adminRoutes);
app.use('/api/send', sendRoutes);

// Frontend pages
const pages = ['index', 'register', 'dashboard', 'admin', 'send', 'receive', 'setup-2fa', '2fa'];
pages.forEach(page => {
    app.get(`/${page === 'index' ? '' : page}`, (_req: Request, res: Response) => {
        res.sendFile(path.join(publicDir, `${page}.html`));
    });
});

// 404 fallback
app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: 'Endpoint or resource not found' });
});

// Global error handler
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    console.error('Unhandled server error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

if (process.env.NODE_ENV !== 'test') {
    initDb()
        .then(() => {
            const server = app.listen(PORT, () => {
                console.log(`VaultX server running at http://localhost:${PORT}`);

                // Optional keep-alive ping for free-tier hosting (e.g. Render)
                if (process.env.KEEP_ALIVE_URL) {
                    const pingUrl = process.env.KEEP_ALIVE_URL.replace(/\/+$/, '') + '/health';
                    setInterval(async () => {
                        try {
                            const res = await fetch(pingUrl);
                            if (res.ok) console.log(`[keep-alive] pinged ${pingUrl}`);
                        } catch (err) {
                            console.warn('[keep-alive] ping failed:', err);
                        }
                    }, 14 * 60 * 1000);
                }
            });

            server.on('error', (err: NodeJS.ErrnoException) => {
                if (err.code === 'EADDRINUSE') {
                    console.error(`Port ${PORT} is already in use.`);
                    process.exit(1);
                } else {
                    console.error('Server error:', err);
                }
            });
        })
        .catch((err) => {
            console.error('Failed to initialize database schema:', err);
            process.exit(1);
        });
}
