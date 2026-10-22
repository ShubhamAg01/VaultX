export type InArgs = any[] | Record<string, any>;

export interface Client {
    execute(stmt: { sql: string; args?: any } | string): Promise<{
        columns: string[];
        rows: any[];
        rowsAffected: number;
        lastInsertRowid?: bigint | number;
    }>;
    executeMultiple(sql: string): Promise<void>;
    transaction(mode?: 'write' | 'read' | 'deferred'): Promise<{
        execute(stmt: { sql: string; args?: any } | string): Promise<{
            columns: string[];
            rows: any[];
            rowsAffected: number;
            lastInsertRowid?: bigint | number;
        }>;
        commit(): Promise<void>;
        rollback(): Promise<void>;
    }>;
    close(): void;
}

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { createClient } = require('@libsql/client');
import path from 'path';

let client: Client | null = null;

export function getDb(): Client {
    if (!client) {
        const tursoUrl = process.env.TURSO_DATABASE_URL;
        const tursoAuthToken = process.env.TURSO_AUTH_TOKEN;

        if (tursoUrl) {
            client = createClient({
                url: tursoUrl,
                authToken: tursoAuthToken
            });
            console.log('🌐 Connected to Turso Cloud Database');
        } else {
            const rawPath = process.env.DB_PATH || path.join(__dirname, '..', '..', 'vault.db');
            const fileUrl = rawPath.startsWith('file:') ? rawPath : `file:${path.resolve(rawPath)}`;
            client = createClient({
                url: fileUrl
            });
            console.log(`📁 Connected to Local SQLite Database (${fileUrl})`);
        }
    }
    return client!;
}

export async function query<T = any>(sql: string, args: InArgs = []): Promise<T[]> {
    const db = getDb();
    const rs = await db.execute({ sql, args });
    return rs.rows as unknown as T[];
}

export async function get<T = any>(sql: string, args: InArgs = []): Promise<T | undefined> {
    const db = getDb();
    const rs = await db.execute({ sql, args });
    return (rs.rows[0] as unknown as T) || undefined;
}

export async function run(sql: string, args: InArgs = []): Promise<{ rowsAffected: number; lastInsertRowid?: number }> {
    const db = getDb();
    const rs = await db.execute({ sql, args });
    return {
        rowsAffected: rs.rowsAffected,
        lastInsertRowid: rs.lastInsertRowid !== undefined && rs.lastInsertRowid !== null
            ? Number(rs.lastInsertRowid)
            : undefined
    };
}

export interface TransactionContext {
    query: <R = any>(sql: string, args?: InArgs) => Promise<R[]>;
    get: <R = any>(sql: string, args?: InArgs) => Promise<R | undefined>;
    run: (sql: string, args?: InArgs) => Promise<{ rowsAffected: number; lastInsertRowid?: number }>;
}

export async function transaction<T>(fn: (tx: TransactionContext) => Promise<T>): Promise<T> {
    const db = getDb();
    const tx = await db.transaction('write');
    try {
        const result = await fn({
            query: async <R = any>(sql: string, args: InArgs = []) => {
                const rs = await tx.execute({ sql, args });
                return rs.rows as unknown as R[];
            },
            get: async <R = any>(sql: string, args: InArgs = []) => {
                const rs = await tx.execute({ sql, args });
                return (rs.rows[0] as unknown as R) || undefined;
            },
            run: async (sql: string, args: InArgs = []) => {
                const rs = await tx.execute({ sql, args });
                return {
                    rowsAffected: rs.rowsAffected,
                    lastInsertRowid: rs.lastInsertRowid !== undefined && rs.lastInsertRowid !== null
                        ? Number(rs.lastInsertRowid)
                        : undefined
                };
            }
        });
        await tx.commit();
        return result;
    } catch (err) {
        await tx.rollback();
        throw err;
    }
}

export async function initDb(): Promise<void> {
    const db = getDb();
    await db.executeMultiple(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            pbkdf2_salt TEXT NOT NULL,
            totp_secret TEXT,
            totp_enabled INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            created_by INTEGER NOT NULL,
            max_uses INTEGER DEFAULT 1,
            uses INTEGER DEFAULT 0,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            encrypted_data TEXT NOT NULL,
            iv TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            encrypted_data TEXT NOT NULL,
            max_views INTEGER DEFAULT 1,
            views INTEGER DEFAULT 0,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);
    console.log('✅ Database schema initialized');
}
