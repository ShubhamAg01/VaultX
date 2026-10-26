/* send.js — handles both /send.html (sender) and /receive.html (receiver) with PIN protection */

function showToast(msg, type = 'success') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icon = typeof ICONS !== 'undefined' ? (type === 'success' ? ICONS.check : (type === 'error' ? ICONS.trash : ICONS.lock)) : '';
    toast.innerHTML = `<span style="display:inline-flex;align-items:center;">${icon}</span><span>${msg}</span>`;
    container.appendChild(toast);
    setTimeout(() => { toast.classList.add('fadeOut'); setTimeout(() => toast.remove(), 300); }, 3500);
}

// Sender page logic
const sendForm = document.getElementById('send-form');
if (sendForm) {
    if (!requireAuth()) { /* auth.js handles redirect */ }

    sendForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const btnText = document.getElementById('send-btn-text');
        const spinner = document.getElementById('send-btn-spinner');
        const sendBtn = document.getElementById('send-btn');
        sendBtn.disabled = true;
        btnText.classList.add('hidden');
        spinner.classList.remove('hidden');

        const secret = document.getElementById('secret-text').value;
        const expiryHours = parseInt(document.getElementById('expiry-hours').value);
        const maxViews = parseInt(document.getElementById('max-views').value);
        const pin = document.getElementById('send-pin')?.value.trim();

        try {
            // Generate a random 256-bit key — stays in the URL fragment, server never sees it
            const { key, keyHex } = await generateSendKey();

            let payload;
            if (pin) {
                // Dual-key derivation: Combines random URL key + user's secret PIN using PBKDF2
                const saltHex = generateSalt(16);
                const pinKey = await derivePinSendKey(keyHex, pin, saltHex);
                const { encrypted_data, iv } = await encryptData(pinKey, secret);
                payload = JSON.stringify({ encrypted_data, iv, saltHex, hasPin: true });
            } else {
                const { encrypted_data, iv } = await encryptData(key, secret);
                payload = JSON.stringify({ encrypted_data, iv, hasPin: false });
            }

            const res = await apiFetch('/api/send', {
                method: 'POST',
                body: JSON.stringify({ encrypted_data: payload, expiry_hours: expiryHours, max_views: maxViews })
            });

            if (!res || !res.ok) { showToast('Failed to create link', 'error'); return; }
            const data = await res.json();

            // Build link with token and key in fragment (key is never sent to server)
            const link = `${window.location.origin}/receive#${data.token}:${keyHex}`;
            document.getElementById('generated-link').textContent = link;
            document.getElementById('send-form-section').classList.add('hidden');
            document.getElementById('link-section').classList.remove('hidden');

            if (pin) {
                showToast('Link generated with PIN protection', 'success');
            } else {
                showToast('Secure link generated', 'success');
            }
        } catch (err) {
            showToast('Encryption error', 'error');
            console.error(err);
        } finally {
            sendBtn.disabled = false;
            btnText.classList.remove('hidden');
            spinner.classList.add('hidden');
        }
    });
}

function copyLink() {
    const link = document.getElementById('generated-link')?.textContent;
    if (!link) return;
    navigator.clipboard.writeText(link);
    const btn = document.getElementById('copy-btn');
    if (btn) { btn.textContent = 'Copied!'; setTimeout(() => btn.textContent = 'Copy Link', 2000); }
    showToast('Link copied to clipboard', 'success');
}

function resetSend() {
    document.getElementById('send-form')?.reset();
    document.getElementById('send-form-section')?.classList.remove('hidden');
    document.getElementById('link-section')?.classList.add('hidden');
}

// Receiver page logic
const receivePage = document.getElementById('content-state') !== null && document.getElementById('loading-state') !== null;
if (receivePage && window.location.pathname.includes('receive')) {
    (async () => {
        const fragment = window.location.hash.slice(1);
        const loading = document.getElementById('loading-state');
        const content = document.getElementById('content-state');
        const pinState = document.getElementById('pin-state');
        const errorState = document.getElementById('error-state');
        const errorMsg = document.getElementById('error-msg');

        if (!fragment || !fragment.includes(':')) {
            loading.classList.add('hidden');
            errorState.classList.remove('hidden');
            return;
        }

        const [token, keyHex] = fragment.split(':');

        try {
            const res = await fetch(`/api/send/${token}`);
            const data = await res.json();

            if (!res.ok) {
                loading.classList.add('hidden');
                errorState.classList.remove('hidden');
                if (errorMsg) errorMsg.textContent = data.error || 'Link not found or expired';
                return;
            }

            const parsed = JSON.parse(data.encrypted_data);

            if (parsed.hasPin) {
                // PIN is required to unlock this secret
                loading.classList.add('hidden');
                pinState.classList.remove('hidden');

                const pinForm = document.getElementById('pin-form');
                const pinInput = document.getElementById('pin-input');
                const pinError = document.getElementById('pin-error');
                const unlockBtn = document.getElementById('unlock-btn');

                pinForm.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    pinError.classList.add('hidden');
                    unlockBtn.disabled = true;
                    unlockBtn.textContent = 'Decrypting…';

                    const enteredPin = pinInput.value.trim();

                    try {
                        const pinKey = await derivePinSendKey(keyHex, enteredPin, parsed.saltHex);
                        const plaintext = await decryptData(pinKey, parsed.encrypted_data, parsed.iv);

                        document.getElementById('secret-display').value = plaintext;
                        pinState.classList.add('hidden');
                        content.classList.remove('hidden');

                        // Clear URL fragment so key isn't stored in browser history
                        window.history.replaceState(null, '', window.location.pathname);
                    } catch (err) {
                        pinError.textContent = 'Incorrect Passphrase or PIN. Please try again.';
                        pinError.classList.remove('hidden');
                        pinInput.select();
                    } finally {
                        unlockBtn.disabled = false;
                        unlockBtn.textContent = 'Decrypt Secret';
                    }
                });
            } else {
                // Direct decryption (no PIN required)
                const key = await importSendKey(keyHex);
                const plaintext = await decryptData(key, parsed.encrypted_data, parsed.iv);

                document.getElementById('secret-display').value = plaintext;
                loading.classList.add('hidden');
                content.classList.remove('hidden');

                // Clear URL fragment
                window.history.replaceState(null, '', window.location.pathname);
            }
        } catch (err) {
            loading.classList.add('hidden');
            errorState.classList.remove('hidden');
            if (errorMsg) errorMsg.textContent = 'Failed to decrypt. The link may be corrupted, expired, or already burned.';
        }
    })();
}

function copySecret() {
    const val = document.getElementById('secret-display')?.value;
    if (!val) return;
    navigator.clipboard.writeText(val);
    const btn = document.getElementById('copy-secret-btn');
    if (btn) {
        const orig = btn.innerHTML;
        btn.innerHTML = typeof ICONS !== 'undefined' ? ICONS.check : '✓';
        setTimeout(() => btn.innerHTML = orig, 2000);
    }
    showToast('Secret copied to clipboard', 'success');
}
