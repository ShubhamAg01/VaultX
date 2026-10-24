/* auth.js — client-side authentication and 2FA handling */

// UI feedback helpers
function showAlert(container, msg, type = 'error') {
    const el = document.getElementById(container) || document.getElementById('alert-box');
    if (!el) return;
    if (!msg) { el.innerHTML = ''; return; }
    const cls = type === 'success' ? 'ok-msg' : 'err-msg';
    el.innerHTML = `<div class="${cls}"><span>${msg}</span></div>`;
}

function showToast(msg, type = 'success') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icon = typeof ICONS !== 'undefined' ? (type === 'success' ? ICONS.check : (type === 'error' ? ICONS.trash : ICONS.lock)) : '';
    toast.innerHTML = `<span style="display:inline-flex;align-items:center;">${icon}</span><span>${msg}</span>`;
    container.appendChild(toast);
    setTimeout(() => { toast.classList.add('fadeOut'); setTimeout(() => toast.remove(), 300); }, 3000);
}

function setLoading(btnId, textId, spinnerId, loading) {
    const btn = document.getElementById(btnId);
    const text = document.getElementById(textId);
    const spinner = document.getElementById(spinnerId);
    if (btn) btn.disabled = loading;
    if (text) text.style.display = loading ? 'none' : '';
    if (spinner) spinner.style.display = loading ? 'inline-block' : 'none';
}

async function storeEncryptionKey(key) {
    const rawBuffer = await crypto.subtle.exportKey('raw', key);
    sessionStorage.setItem('vaultx_key', bufferToHex(rawBuffer));
}

// Login form handling
const loginForm = document.getElementById('login-form');
if (loginForm) {
    if (getSession().token) window.location.href = '/dashboard';

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        showAlert('alert-container', '');
        setLoading('login-btn', 'btn-text', 'btn-spinner', true);

        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;

        try {
            // 1. Fetch user's PBKDF2 salt
            const saltRes = await fetch(`/api/auth/pre-login?username=${encodeURIComponent(username)}`);
            if (!saltRes.ok) throw new Error('Could not initialize authentication');
            const { salt } = await saltRes.json();
            if (!salt) throw new Error('Invalid authentication response');

            // 2. Derive zero-knowledge authHash and vaultKey locally
            const { authHash, vaultKey } = await deriveKeys(password, salt);

            // 3. Authenticate with server using authHash (master password is never sent)
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, authHash })
            });

            let data;
            try { data = await res.json(); } catch { throw new Error('Server returned an invalid response'); }

            if (!res.ok) {
                showAlert('alert-container', data.error || (data.errors?.[0]?.msg) || 'Login failed');
                return;
            }

            // Save derived vaultKey in sessionStorage
            await storeEncryptionKey(vaultKey);

            if (data.requires2FA) {
                sessionStorage.setItem('pre_auth_token', data.preAuthToken);
                sessionStorage.setItem('pre_auth_username', username);
                window.location.href = '/2fa';
                return;
            }

            saveSession(data);
            window.location.href = '/dashboard';
        } catch (err) {
            console.error('Login error:', err);
            showAlert('alert-container', err.message || 'Unable to connect. Please try again.');
        } finally {
            setLoading('login-btn', 'btn-text', 'btn-spinner', false);
        }
    });
}

// Registration handling
const registerForm = document.getElementById('register-form');
if (registerForm) {
    const inviteGroup = document.getElementById('invite-group');
    const inviteInput = document.getElementById('invite-code');
    const inviteBadge = document.getElementById('invite-badge');

    // Check system status on page load
    (async () => {
        try {
            const res = await fetch('/api/auth/status');
            const data = await res.json();

            // Check URL for invite code
            const params = new URLSearchParams(window.location.search);
            const inviteParam = params.get('invite') || params.get('code');

            if (!data.initialized) {
                // First user setup
                if (inviteGroup) inviteGroup.style.display = 'none';
                showAlert('alert-box', 'Welcome! You are setting up the primary VaultX Administrator account.', 'success');
            } else {
                if (inviteParam) {
                    if (inviteInput) {
                        inviteInput.value = inviteParam;
                        inviteInput.readOnly = true;
                        inviteInput.style.opacity = '0.9';
                    }
                    if (inviteBadge) {
                        inviteBadge.textContent = 'Verified Invite Code';
                        inviteBadge.style.color = 'var(--accent)';
                    }
                } else {
                    showAlert('alert-box', 'VaultX is private and invite-only. Enter your invite token to proceed.', 'info');
                }
            }
        } catch (err) {
            console.error('Status check error:', err);
        }
    })();

    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        showAlert('alert-box', '');

        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const confirm = document.getElementById('confirm-password').value;
        const inviteCode = inviteInput ? inviteInput.value.trim() : '';

        if (password !== confirm) {
            showAlert('alert-box', 'Passwords do not match');
            return;
        }
        if (password.length < 12) {
            showAlert('alert-box', 'Master password must be at least 12 characters');
            return;
        }

        const strength = getPasswordStrength(password);
        if (strength.level === 'Weak') {
            showAlert('alert-box', 'Please choose a stronger master password (mix uppercase, numbers & symbols)');
            return;
        }

        setLoading('register-btn', 'btn-text', 'btn-spinner', true);

        try {
            // 1. Generate client-side salt for PBKDF2
            const pbkdf2Salt = generateSalt(32);

            // 2. Derive authHash and vaultKey locally
            const { authHash, vaultKey } = await deriveKeys(password, pbkdf2Salt);

            // 3. Register with server
            const res = await fetch('/api/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username,
                    authHash,
                    pbkdf2Salt,
                    inviteCode: inviteCode || undefined
                })
            });

            let data;
            try { data = await res.json(); } catch { throw new Error('Server returned an invalid response'); }

            if (!res.ok) {
                const msg = data.errors ? data.errors.map(err => err.msg).join('. ') : (data.error || 'Registration failed');
                showAlert('alert-box', msg);
                return;
            }

            // Store vault key for immediate seamless login
            await storeEncryptionKey(vaultKey);

            showAlert('alert-box', `Account created successfully. ${data.isAdmin ? 'Admin privileges granted.' : ''} Redirecting to login…`, 'success');
            setTimeout(() => window.location.href = '/', 1800);
        } catch (err) {
            console.error('Register error:', err);
            showAlert('alert-box', err.message || 'Unable to connect. Please try again.');
        } finally {
            setLoading('register-btn', 'btn-text', 'btn-spinner', false);
        }
    });
}

// 2FA verification challenge
const totpForm = document.getElementById('totp-form');
if (totpForm) {
    const preAuthToken = sessionStorage.getItem('pre_auth_token');
    if (!preAuthToken) { window.location.href = '/'; }

    totpForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        setLoading('verify-btn', 'btn-text', 'btn-spinner', true);
        showAlert('alert-container', '');
        const code = document.getElementById('totp-code').value.trim();

        try {
            const res = await fetch('/api/auth/2fa/validate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ preAuthToken, code })
            });
            const data = await res.json();
            if (!res.ok) { showAlert('alert-container', data.error || 'Invalid code'); return; }

            sessionStorage.removeItem('pre_auth_token');
            saveSession(data);
            window.location.href = '/dashboard';
        } catch (err) {
            showAlert('alert-container', err.message || 'Unable to connect. Please try again.');
        } finally {
            setLoading('verify-btn', 'btn-text', 'btn-spinner', false);
        }
    });
}

// 2FA setup and QR code loading
async function loadQR() {
    if (!requireAuth()) return;
    const btn = document.getElementById('qr-btn-text');
    const spinner = document.getElementById('qr-spinner');
    if (btn) btn.classList.add('hidden');
    if (spinner) spinner.classList.remove('hidden');

    const res = await apiFetch('/api/auth/2fa/setup', { method: 'POST' });
    if (!res) return;
    const data = await res.json();

    document.getElementById('qr-img').src = data.qrCode;
    document.getElementById('manual-key').textContent = data.secret;
    showStep(2);
}

function showStep(n) {
    [1, 2, 3].forEach(i => {
        const el = document.getElementById(`step-${i}`);
        if (el) el.classList.toggle('hidden', i !== n);
    });
}

async function verifySetup() {
    const code = document.getElementById('confirm-code').value.trim();
    const alertEl = document.getElementById('setup-alert');
    const btnText = document.getElementById('verify-text');
    const spinner = document.getElementById('verify-spinner');

    if (btnText) btnText.classList.add('hidden');
    if (spinner) spinner.classList.remove('hidden');

    const res = await apiFetch('/api/auth/2fa/verify', { method: 'POST', body: JSON.stringify({ code }) });
    if (!res) return;
    const data = await res.json();

    if (!res.ok) {
        if (alertEl) alertEl.innerHTML = `<div class="alert alert-error">${data.error}</div>`;
        if (btnText) btnText.classList.remove('hidden');
        if (spinner) spinner.classList.add('hidden');
        return;
    }
    [1, 2, 3].forEach(i => { const el = document.getElementById(`step-${i}`); if (el) el.classList.add('hidden'); });
    document.getElementById('step-done')?.classList.remove('hidden');
}

function handleLogout() {
    clearSession();
    window.location.href = '/';
}
