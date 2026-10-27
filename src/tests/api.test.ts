process.env.NODE_ENV = 'test';

import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import { app } from '../server';
import { initDb } from '../config/db';

describe('VaultX API Security & Auth Integration Tests', () => {
    beforeAll(async () => {
        await initDb();
    });

    it('GET /health should return 200 ok for keep-alive monitoring', async () => {
        const res = await request(app).get('/health');
        expect(res.status).toBe(200);
        expect(res.body.status).toBe('ok');
        expect(res.body).toHaveProperty('timestamp');
    });

    it('GET /css/style.css should serve static CSS file with 200', async () => {
        const res = await request(app).get('/css/style.css');
        expect(res.status).toBe(200);
        expect(res.headers['content-type']).toContain('text/css');
    });

    it('GET /api/auth/status should return system initialization state', async () => {
        const res = await request(app).get('/api/auth/status');
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('initialized');
        expect(typeof res.body.initialized).toBe('boolean');
    });

    it('GET /api/auth/pre-login should return salt for username', async () => {
        const res = await request(app).get('/api/auth/pre-login?username=alice');
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('salt');
        expect(res.body.salt).toHaveLength(64);
    });

    it('POST /api/auth/login with invalid data format should fail with 400', async () => {
        const res = await request(app)
            .post('/api/auth/login')
            .send({ username: '', authHash: 'not-a-valid-hex-hash' });

        expect(res.status).toBe(400);
        expect(res.body).toHaveProperty('errors');
    });

    it('GET /api/passwords without Bearer token should return 401', async () => {
        const res = await request(app).get('/api/passwords');
        expect(res.status).toBe(401);
        expect(res.body.error).toContain('Unauthorized');
    });

    it('GET non-existent route should return 404 JSON', async () => {
        const res = await request(app).get('/api/some-non-existent-endpoint');
        expect(res.status).toBe(404);
        expect(res.body).toHaveProperty('error');
    });
});
