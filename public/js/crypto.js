// Web Crypto helpers for key derivation and vault encryption

function hexToBuffer(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    return bytes.buffer;
}

function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateSalt(bytes = 32) {
    const arr = crypto.getRandomValues(new Uint8Array(bytes));
    return bufferToHex(arr);
}

/**
 * Derives both authHash (for server authentication) and vaultKey (for client encryption).
 * The master password never leaves the client.
 */
async function deriveKeys(masterPassword, saltHex) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        enc.encode(masterPassword),
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
    );

    // 512 bits = 64 bytes (32 bytes auth + 32 bytes vault)
    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: hexToBuffer(saltHex),
            iterations: 300000,
            hash: 'SHA-256'
        },
        keyMaterial,
        512
    );

    const authKeyBytes = derivedBits.slice(0, 32);
    const vaultKeyBytes = derivedBits.slice(32, 64);

    // authHash is SHA-256 of authKeyBytes. Server only ever receives this hash.
    const authHashBuffer = await crypto.subtle.digest('SHA-256', authKeyBytes);
    const authHash = bufferToHex(authHashBuffer);

    // vaultKey is AES-256-GCM key kept strictly in browser memory for vault encryption/decryption.
    const vaultKey = await crypto.subtle.importKey(
        'raw',
        vaultKeyBytes,
        { name: 'AES-GCM' },
        true, // Allow export to sessionStorage for same-session navigation
        ['encrypt', 'decrypt']
    );

    return { authHash, vaultKey, vaultKeyBytes };
}

/**
 * Encrypts an entire vault item object { site_name, site_url, username, password, notes }
 */
async function encryptVaultItem(vaultKey, itemObj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const plaintext = JSON.stringify(itemObj);
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        vaultKey,
        enc.encode(plaintext)
    );
    return {
        encrypted_data: bufferToHex(encrypted),
        iv: bufferToHex(iv)
    };
}

/**
 * Decrypts a vault item object
 */
async function decryptVaultItem(vaultKey, encryptedHex, ivHex) {
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: hexToBuffer(ivHex) },
        vaultKey,
        hexToBuffer(encryptedHex)
    );
    const decoded = new TextDecoder().decode(decrypted);
    return JSON.parse(decoded);
}

// Data encryption utilities
async function encryptData(key, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
    return { encrypted_data: bufferToHex(encrypted), iv: bufferToHex(iv) };
}

async function decryptData(key, encryptedHex, ivHex) {
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: hexToBuffer(ivHex) }, key, hexToBuffer(encryptedHex));
    return new TextDecoder().decode(decrypted);
}

// Secure send key helpers
async function generateSendKey() {
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const exported = await crypto.subtle.exportKey('raw', key);
    return { key, keyHex: bufferToHex(exported) };
}

async function importSendKey(keyHex) {
    return crypto.subtle.importKey('raw', hexToBuffer(keyHex), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/**
 * Derives a secondary key for PIN/Passphrase-protected sends.
 * Combines the random URL fragment key with the user's PIN using PBKDF2 (100,000 rounds).
 */
async function derivePinSendKey(keyHex, pin, saltHex) {
    const enc = new TextEncoder();
    const material = await crypto.subtle.importKey(
        'raw',
        enc.encode(`${keyHex}:${pin.trim()}`),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: hexToBuffer(saltHex),
            iterations: 100000,
            hash: 'SHA-256'
        },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

// Password generator & strength evaluation
function getPasswordStrength(password) {
    let score = 0;
    if (password.length >= 12) score++;
    if (password.length >= 16) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^a-zA-Z0-9]/.test(password)) score++;
    if (score <= 2) return { level: 'Weak', color: '#ef4444', width: '25%' };
    if (score <= 3) return { level: 'Fair', color: '#f59e0b', width: '50%' };
    if (score <= 4) return { level: 'Good', color: '#3b82f6', width: '75%' };
    return { level: 'Strong', color: '#10b981', width: '100%' };
}

function generatePassword(length = 20, useSymbols = true, useNumbers = true, useUpper = true) {
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    let chars = lower;
    if (useUpper) chars += upper;
    if (useNumbers) chars += numbers;
    if (useSymbols) chars += symbols;
    const arr = crypto.getRandomValues(new Uint32Array(length));
    return Array.from(arr, n => chars[n % chars.length]).join('');
}

// Session helpers
function saveSession(data) {
    sessionStorage.setItem('vaultx_token', data.token);
    sessionStorage.setItem('vaultx_username', data.username);
    sessionStorage.setItem('vaultx_isAdmin', data.isAdmin ? 'true' : 'false');
}

function getSession() {
    return {
        token: sessionStorage.getItem('vaultx_token'),
        username: sessionStorage.getItem('vaultx_username'),
        isAdmin: sessionStorage.getItem('vaultx_isAdmin') === 'true'
    };
}

function clearSession() {
    sessionStorage.clear();
}

function requireAuth(redirectTo = '/') {
    const { token } = getSession();
    if (!token) { window.location.href = redirectTo; return false; }
    return true;
}

async function apiFetch(url, options = {}) {
    const { token } = getSession();
    const headers = { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...options.headers };
    const res = await fetch(url, { ...options, headers });
    if (res.status === 401) { clearSession(); window.location.href = '/'; return null; }
    return res;
}
