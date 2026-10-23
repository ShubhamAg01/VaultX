import { describe, it, expect } from 'vitest';
import crypto from 'crypto';

describe('Zero-Knowledge Cryptographic Derivation Tests', () => {
    it('should derive deterministic authHash from same password and salt', () => {
        const password = 'SuperSecretMasterPassword123!';
        const salt = crypto.randomBytes(32);

        // PBKDF2 300,000 iterations to derive 64 bytes
        const derivedKey = crypto.pbkdf2Sync(password, salt, 300000, 64, 'sha256');
        const authKey = derivedKey.subarray(0, 32);
        const vaultKey = derivedKey.subarray(32, 64);

        const authHash = crypto.createHash('sha256').update(authKey).digest('hex');

        // Repeating derivation with same parameters produces identical output
        const derivedKey2 = crypto.pbkdf2Sync(password, salt, 300000, 64, 'sha256');
        const authKey2 = derivedKey2.subarray(0, 32);
        const authHash2 = crypto.createHash('sha256').update(authKey2).digest('hex');

        expect(authHash).toBe(authHash2);
        expect(authHash).toHaveLength(64);
        expect(vaultKey).toHaveLength(32);
        expect(authKey).not.toEqual(vaultKey);
    });

    it('should perform AES-256-GCM encryption and decryption roundtrip', () => {
        const key = crypto.randomBytes(32); // 256-bit key
        const iv = crypto.randomBytes(12);  // 96-bit standard GCM IV

        const payload = JSON.stringify({
            site_name: 'GitHub',
            site_url: 'https://github.com',
            username: 'developer',
            password: 'CorrectHorseBatteryStaple99$',
            notes: '2FA Backup codes stored in hardware token'
        });

        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        let encrypted = cipher.update(payload, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag();

        // Combined encrypted data + auth tag
        const ciphertextWithTag = encrypted + authTag.toString('hex');

        // Decryption
        const tag = Buffer.from(ciphertextWithTag.slice(-32), 'hex');
        const actualCiphertext = ciphertextWithTag.slice(0, -32);

        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        let decrypted = decipher.update(actualCiphertext, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        const parsed = JSON.parse(decrypted);
        expect(parsed.site_name).toBe('GitHub');
        expect(parsed.password).toBe('CorrectHorseBatteryStaple99$');
        expect(parsed.username).toBe('developer');
    });
});
