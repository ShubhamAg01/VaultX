/* dashboard.js — vault CRUD, generator, security audit, import/export, and 2FA */

let vaultKey = null;
let allEntries = [];
let editingId = null;
let lastGen = '';
let currentCategory = 'all';
let currentSearch = '';
let parsedImportItems = [];

// Dashboard initialization
(async () => {
    if (!requireAuth()) return;
    const session = getSession();

    const rawHex = sessionStorage.getItem('vaultx_key');
    if (!rawHex) { clearSession(); window.location.href = '/'; return; }

    try {
        vaultKey = await crypto.subtle.importKey(
            'raw',
            hexToBuffer(rawHex),
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        );
    } catch (err) {
        console.error('Key import error:', err);
        clearSession();
        window.location.href = '/';
        return;
    }

    // Set nav user info
    const avatar = document.getElementById('u-avatar');
    const nameEl = document.getElementById('u-name');
    if (avatar) avatar.textContent = (session.username || '?')[0].toUpperCase();
    if (nameEl) nameEl.textContent = session.username || 'User';
    if (session.isAdmin) {
        const al = document.getElementById('admin-link');
        if (al) al.style.display = 'flex';
    }

    await Promise.all([loadVault(), loadUserInfo()]);
})();

async function loadUserInfo() {
    const res = await apiFetch('/api/auth/me');
    if (!res) return;
    const user = await res.json();
    const el = document.getElementById('s-2fa');
    if (el) el.textContent = user.totp_enabled ? 'Enabled' : 'Disabled';
}

async function loadVault() {
    const res = await apiFetch('/api/passwords');
    if (!res) return;
    const encryptedEntries = await res.json();
    allEntries = [];

    for (const entry of encryptedEntries) {
        try {
            const dec = await decryptVaultItem(vaultKey, entry.encrypted_data, entry.iv);
            allEntries.push({
                id: entry.id,
                created_at: entry.created_at,
                updated_at: entry.updated_at,
                site_name: dec.site_name || '',
                site_url: dec.site_url || '',
                username: dec.username || '',
                password: dec.password || '',
                notes: dec.notes || '',
                category: dec.category || 'Logins',
                is_favorite: !!dec.is_favorite
            });
        } catch (err) {
            console.error('Decryption failed for item', entry.id, err);
            allEntries.push({
                id: entry.id,
                created_at: entry.created_at,
                updated_at: entry.updated_at,
                site_name: '[Decryption Error]',
                site_url: '',
                username: '',
                password: '',
                notes: 'Decryption failed for this item.',
                category: 'Other',
                is_favorite: false
            });
        }
    }

    updateCounts();
    applyFilter();
}

function updateCounts() {
    const countEl = document.getElementById('s-count');
    const sub = document.getElementById('vault-sub');
    if (countEl) countEl.textContent = allEntries.length;
    if (sub) sub.textContent = `${allEntries.length} password${allEntries.length !== 1 ? 's' : ''} stored — fully encrypted in your browser`;

    const cAll = document.getElementById('c-all');
    const cFav = document.getElementById('c-fav');
    const cLogins = document.getElementById('c-logins');
    const cCards = document.getElementById('c-cards');
    const cNotes = document.getElementById('c-notes');
    const cServers = document.getElementById('c-servers');

    if (cAll) cAll.textContent = allEntries.length;
    if (cFav) cFav.textContent = allEntries.filter(x => x.is_favorite).length;
    if (cLogins) cLogins.textContent = allEntries.filter(x => (x.category || 'Logins') === 'Logins').length;
    if (cCards) cCards.textContent = allEntries.filter(x => x.category === 'Cards').length;
    if (cNotes) cNotes.textContent = allEntries.filter(x => x.category === 'Notes').length;
    if (cServers) cServers.textContent = allEntries.filter(x => x.category === 'Servers').length;
}

// Search & category filters
function setCategoryFilter(cat) {
    currentCategory = cat;
    document.querySelectorAll('#cat-tabs .btn-tab').forEach(b => {
        const text = b.textContent.toLowerCase();
        const active = (cat === 'all' && text.includes('all')) ||
                       (cat === 'favorites' && text.includes('favorites')) ||
                       (text.includes(cat.toLowerCase()));
        b.classList.toggle('active', active);
    });
    applyFilter();
}

function filterVault(q) {
    currentSearch = (q || '').trim().toLowerCase();
    applyFilter();
}

function applyFilter() {
    let filtered = allEntries;

    if (currentCategory === 'favorites') {
        filtered = filtered.filter(x => x.is_favorite);
    } else if (currentCategory !== 'all') {
        filtered = filtered.filter(x => (x.category || 'Logins') === currentCategory);
    }

    if (currentSearch) {
        filtered = filtered.filter(e =>
            (e.site_name || '').toLowerCase().includes(currentSearch) ||
            (e.username || '').toLowerCase().includes(currentSearch) ||
            (e.site_url || '').toLowerCase().includes(currentSearch) ||
            (e.notes || '').toLowerCase().includes(currentSearch)
        );
    }

    renderVault(filtered);
}

function renderVault(entries) {
    const grid = document.getElementById('vault-grid');
    if (!grid) return;
    if (!entries.length) {
        grid.innerHTML = `<div class="empty">
            <div class="empty-ico">${ICONS.lock}</div>
            <div class="empty-title">No credentials found</div>
            <div class="empty-sub">${allEntries.length === 0 ? 'Click "+ Add Credential" above to store your first entry' : 'No items match the current filter or search'}</div>
        </div>`;
        return;
    }

    grid.innerHTML = entries.map((e) => {
        const letter = (e.site_name || '?')[0].toUpperCase();
        const masked = '••••••••••••';
        const starIcon = e.is_favorite ? ICONS.starFilled : ICONS.star;
        const starClass = e.is_favorite ? 'v-star starred' : 'v-star';

        return `<div class="v-card">
      <div class="v-head">
        <div class="v-icon">${letter}</div>
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;gap:6px;">
            <div class="v-site">${esc(e.site_name)}</div>
            ${e.category && e.category !== 'Logins' ? `<span class="v-cat">${esc(e.category)}</span>` : ''}
          </div>
          <div class="v-url">${e.site_url ? esc(e.site_url) : 'No URL'}</div>
        </div>
        <button class="${starClass}" onclick="toggleFavorite(${e.id})" title="${e.is_favorite ? 'Remove favorite' : 'Add to favorites'}">
          ${starIcon}
        </button>
      </div>
      <div class="v-body">
        ${e.username ? `<div class="v-field">
          <span class="v-lbl">User</span>
          <span class="v-val">${esc(e.username)}</span>
          <button class="v-action" onclick="cpUser(${e.id}, this)" title="Copy Username">${ICONS.copy}</button>
        </div>` : ''}
        <div class="v-field">
          <span class="v-lbl">Pass</span>
          <span class="v-val" id="pv-${e.id}" style="font-family:var(--font-mono);">${masked}</span>
          <button class="v-action" onclick="togglePw(${e.id}, this)" title="Show/Hide">${ICONS.eye}</button>
          <button class="v-action" onclick="cpPw(${e.id}, this)" title="Copy Password">${ICONS.copy}</button>
        </div>
        ${e.notes ? `<div class="v-field"><span class="v-lbl">Note</span><span class="v-val" style="font-family:var(--font-sans);font-size:11px;">${esc(e.notes)}</span></div>` : ''}
      </div>
      <div class="v-footer">
        <button class="v-edit" onclick="openEdit(${e.id})" title="Edit">${ICONS.edit} Edit</button>
        <button class="v-del" onclick="delEntry(${e.id})" title="Delete">${ICONS.trash} Delete</button>
      </div>
    </div>`;
    }).join('');
}

// Toggle favorite status
async function toggleFavorite(id) {
    const e = allEntries.find(x => x.id === id);
    if (!e) return;
    const newFav = !e.is_favorite;
    e.is_favorite = newFav;

    try {
        const { encrypted_data, iv } = await encryptVaultItem(vaultKey, {
            site_name: e.site_name,
            site_url: e.site_url,
            username: e.username,
            password: e.password,
            notes: e.notes,
            category: e.category || 'Logins',
            is_favorite: newFav
        });

        const res = await apiFetch(`/api/passwords/${id}`, {
            method: 'PUT',
            body: JSON.stringify({ encrypted_data, iv })
        });

        if (!res || !res.ok) {
            e.is_favorite = !newFav;
            toast('Failed to update favorite', 'error');
            return;
        }

        updateCounts();
        applyFilter();
    } catch {
        e.is_favorite = !newFav;
        toast('Error updating favorite', 'error');
    }
}

// Password visibility and clipboard helpers
function togglePw(id, btn) {
    const el = document.getElementById(`pv-${id}`);
    const entry = allEntries.find(x => x.id === id);
    if (!el || !entry) return;
    const isHidden = el.textContent.includes('•');
    el.textContent = isHidden ? entry.password : '••••••••••••';
    btn.innerHTML = isHidden ? ICONS.eyeOff : ICONS.eye;
}

function cpUser(id, btn) {
    const entry = allEntries.find(x => x.id === id);
    if (entry && entry.username) cp(entry.username, btn);
}

function cpPw(id, btn) {
    const entry = allEntries.find(x => x.id === id);
    if (entry && entry.password) cp(entry.password, btn);
}

function cp(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
        const orig = btn.innerHTML;
        btn.innerHTML = ICONS.check;
        setTimeout(() => { btn.innerHTML = orig; }, 1200);
        toast('Copied to clipboard', 'success');
    }).catch(() => {
        toast('Failed to copy', 'error');
    });
}

// Modal dialogs
function openModal(id) {
    const m = document.getElementById(id);
    if (m) { m.classList.add('active'); m.style.display = 'flex'; }
}

function closeModal(id) {
    const m = document.getElementById(id);
    if (m) { m.classList.remove('active'); m.style.display = 'none'; }
    editingId = null;
}

document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', e => {
        if (e.target === overlay) closeModal(overlay.id);
    });
});

document.addEventListener('keydown', e => {
    if (e.key === 'Escape') ['pw-modal', 'gen-modal', 'tools-modal', 'audit-modal', 'twofa-modal'].forEach(closeModal);
});

function openAdd() {
    editingId = null;
    document.getElementById('modal-ttl').textContent = 'Add Credential';
    document.getElementById('save-lbl').textContent = 'Save Credential';
    document.getElementById('pw-form').reset();
    document.getElementById('edit-id').value = '';
    document.getElementById('m-sbar').style.width = '0';
    document.getElementById('f-cat').value = 'Logins';
    document.getElementById('f-fav').checked = false;
    resetPwnedStatus();
    openModal('pw-modal');
}

function openEdit(id) {
    const e = allEntries.find(x => x.id === id);
    if (!e) return;
    editingId = id;
    document.getElementById('modal-ttl').textContent = 'Edit Credential';
    document.getElementById('save-lbl').textContent = 'Update Credential';
    document.getElementById('edit-id').value = id;
    document.getElementById('f-site').value = e.site_name || '';
    document.getElementById('f-url').value = e.site_url || '';
    document.getElementById('f-user').value = e.username || '';
    document.getElementById('f-pw').value = e.password || '';
    document.getElementById('f-notes').value = e.notes || '';
    document.getElementById('f-cat').value = e.category || 'Logins';
    document.getElementById('f-fav').checked = !!e.is_favorite;
    resetPwnedStatus();
    mStrength(e.password || '');
    openModal('pw-modal');
}

function toggleMPw() {
    const i = document.getElementById('f-pw');
    const b = document.querySelector('.m-eye');
    const show = i.type === 'password';
    i.type = show ? 'text' : 'password';
    if (b) b.innerHTML = show ? ICONS.eyeOff : ICONS.eye;
}

function mStrength(pw) {
    const bar = document.getElementById('m-sbar');
    if (!bar) return;
    if (!pw) { bar.style.width = '0'; return; }
    const s = getPasswordStrength(pw);
    bar.style.width = s.width;
    bar.style.background = s.color;
}

// Save or update credential entry
document.getElementById('pw-form')?.addEventListener('submit', async e => {
    e.preventDefault();
    const btn = document.getElementById('save-btn');
    const lbl = document.getElementById('save-lbl');
    const spin = document.getElementById('save-spin');
    btn.disabled = true;
    lbl.style.display = 'none';
    spin.style.display = 'inline-block';

    const site_name = document.getElementById('f-site').value.trim();
    const site_url = document.getElementById('f-url').value.trim();
    const username = document.getElementById('f-user').value.trim();
    const password = document.getElementById('f-pw').value;
    const notes = document.getElementById('f-notes').value.trim();
    const category = document.getElementById('f-cat').value || 'Logins';
    const is_favorite = document.getElementById('f-fav').checked;

    try {
        const { encrypted_data, iv } = await encryptVaultItem(vaultKey, {
            site_name,
            site_url,
            username,
            password,
            notes,
            category,
            is_favorite
        });

        const isEdit = !!editingId;
        const res = await apiFetch(isEdit ? `/api/passwords/${editingId}` : '/api/passwords', {
            method: isEdit ? 'PUT' : 'POST',
            body: JSON.stringify({ encrypted_data, iv })
        });

        if (!res || !res.ok) {
            toast('Failed to save credential', 'error');
            return;
        }

        toast(isEdit ? 'Updated securely' : 'Saved securely', 'success');
        closeModal('pw-modal');
        await loadVault();
    } catch (err) {
        toast(`Error: ${err.message}`, 'error');
    } finally {
        btn.disabled = false;
        lbl.style.display = '';
        spin.style.display = 'none';
    }
});

// Delete credential entry
async function delEntry(id) {
    if (!confirm('Delete this credential? This cannot be undone.')) return;
    const res = await apiFetch(`/api/passwords/${id}`, { method: 'DELETE' });
    if (!res || !res.ok) { toast('Failed to delete', 'error'); return; }
    toast('Credential deleted', 'success');
    await loadVault();
}

// Password generator UI
function openGenerator() { genPw(); openModal('gen-modal'); }

function genPw() {
    const len = parseInt(document.getElementById('gen-len')?.value || 20);
    const up = document.getElementById('g-upper')?.checked ?? true;
    const nums = document.getElementById('g-nums')?.checked ?? true;
    const sym = document.getElementById('g-sym')?.checked ?? true;
    lastGen = generatePassword(len, sym, nums, up);
    const out = document.getElementById('gen-out');
    if (out) out.textContent = lastGen;
}

function copyGenOut() {
    if (!lastGen) return;
    navigator.clipboard.writeText(lastGen);
    toast('Password copied', 'success');
}

function useGenInForm() {
    if (!lastGen) return;
    const inp = document.getElementById('f-pw');
    if (inp) {
        inp.value = lastGen;
        inp.type = 'text';
        mStrength(lastGen);
        resetPwnedStatus();
    }
    closeModal('gen-modal');
    toast('Password applied to form', 'success');
}

function fillGenerated() {
    const pw = generatePassword(20, true, true, true);
    const inp = document.getElementById('f-pw');
    if (inp) {
        inp.value = pw;
        inp.type = 'text';
        mStrength(pw);
        resetPwnedStatus();
    }
    toast('Secure password generated', 'success');
}

// k-Anonymity breach check (HaveIBeenPwned API)
async function checkPwnedPassword(password) {
    if (!password) return { pwned: false, count: 0 };
    const enc = new TextEncoder();
    const digest = await crypto.subtle.digest('SHA-1', enc.encode(password));
    const hash = bufferToHex(digest).toUpperCase();
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    let text = '';
    try {
        const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        if (res.ok) text = await res.text();
    } catch {
        try {
            const res = await apiFetch(`/api/passwords/pwned-check/${prefix}`);
            if (res && res.ok) text = await res.text();
        } catch { }
    }

    if (!text) return { pwned: false, count: 0, error: 'Service unreachable' };

    const lines = text.split('\n');
    for (const line of lines) {
        const [s, cnt] = line.trim().split(':');
        if (s && s.toUpperCase() === suffix) {
            return { pwned: true, count: parseInt(cnt, 10) || 1 };
        }
    }
    return { pwned: false, count: 0 };
}

async function checkCurrentPwned() {
    const pw = document.getElementById('f-pw')?.value;
    const btn = document.getElementById('check-pwned-btn');
    const ind = document.getElementById('pw-breach-indicator');
    if (!pw) { toast('Enter a password first', 'error'); return; }

    btn.disabled = true;
    btn.textContent = 'Checking…';
    ind.style.display = 'none';

    try {
        const result = await checkPwnedPassword(pw);
        ind.style.display = 'block';
        if (result.error) {
            ind.innerHTML = `<span class="badge" style="background:var(--bg-subtle);color:var(--text-muted);">${result.error}</span>`;
        } else if (result.pwned) {
            ind.innerHTML = `<span class="badge badge-pwned">${ICONS.alertTriangle} Leaked in ${result.count.toLocaleString()} known data breaches!</span>`;
        } else {
            ind.innerHTML = `<span class="badge badge-clean">${ICONS.check} Clean — No known breach records</span>`;
        }
    } catch (err) {
        ind.style.display = 'block';
        ind.innerHTML = `<span class="badge" style="color:var(--text-muted);">Check failed</span>`;
    } finally {
        btn.disabled = false;
        btn.textContent = 'Check Leaks';
    }
}

function resetPwnedStatus() {
    const ind = document.getElementById('pw-breach-indicator');
    if (ind) ind.style.display = 'none';
}

// Vault security audit
function openAuditModal() {
    document.getElementById('audit-status').textContent = 'Ready to scan';
    openModal('audit-modal');
}

async function runVaultAudit() {
    const btn = document.getElementById('run-audit-btn');
    const status = document.getElementById('audit-status');
    const leakedEl = document.getElementById('audit-leaked');
    const reusedEl = document.getElementById('audit-reused');
    const weakEl = document.getElementById('audit-weak');
    const resultsEl = document.getElementById('audit-results');

    if (!allEntries.length) {
        toast('Your vault is empty', 'info');
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Scanning…';
    status.textContent = 'Analyzing passwords for reuse and weak keys…';

    // 1. Weak check (< 12 chars)
    const weakItems = allEntries.filter(x => (x.password || '').length < 12);
    weakEl.textContent = weakItems.length;

    // 2. Reuse check
    const pwCounts = {};
    allEntries.forEach(x => {
        if (x.password) pwCounts[x.password] = (pwCounts[x.password] || 0) + 1;
    });
    const reusedItems = allEntries.filter(x => x.password && pwCounts[x.password] > 1);
    reusedEl.textContent = reusedItems.length;

    // 3. Pwned / Breach check (k-Anonymity)
    status.textContent = 'Checking known breach registries…';
    const uniquePws = [...new Set(allEntries.map(x => x.password).filter(Boolean))];
    const pwnedMap = new Map();

    for (const pw of uniquePws) {
        const res = await checkPwnedPassword(pw);
        if (res.pwned) pwnedMap.set(pw, res.count);
    }

    const leakedItems = allEntries.filter(x => pwnedMap.has(x.password));
    leakedEl.textContent = leakedItems.length;

    // Build results list
    const flaggedMap = new Map();
    allEntries.forEach(e => {
        const issues = [];
        if (pwnedMap.has(e.password)) issues.push(`<span class="badge badge-pwned">Leaked (${pwnedMap.get(e.password)}x)</span>`);
        if (pwCounts[e.password] > 1) issues.push(`<span class="badge" style="background:rgba(251,191,36,0.15);color:#fbbf24;border:1px solid rgba(251,191,36,0.3);">Reused</span>`);
        if ((e.password || '').length < 12) issues.push(`<span class="badge" style="background:rgba(96,165,250,0.15);color:#60a5fa;border:1px solid rgba(96,165,250,0.3);">Weak</span>`);
        if (issues.length) flaggedMap.set(e.id, { entry: e, issues });
    });

    if (flaggedMap.size === 0) {
        resultsEl.innerHTML = `<div style="text-align:center;padding:24px;color:#34d399;font-size:13px;font-weight:500;">
            ${ICONS.check} Excellent! No compromised, reused, or weak passwords detected.
        </div>`;
    } else {
        resultsEl.innerHTML = Array.from(flaggedMap.values()).map(({ entry, issues }) => `
            <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-bottom:1px solid var(--border);">
                <div>
                    <div style="font-weight:600;font-size:13px;color:var(--text);">${esc(entry.site_name)}</div>
                    <div style="font-size:11px;color:var(--text-muted);">${esc(entry.username || 'No username')}</div>
                </div>
                <div style="display:flex;align-items:center;gap:8px;">
                    ${issues.join(' ')}
                    <button class="btn btn-secondary" style="padding:3px 8px;font-size:11px;" onclick="closeModal('audit-modal'); openEdit(${entry.id})">Edit</button>
                </div>
            </div>
        `).join('');
    }

    status.textContent = `Scan complete. Found ${flaggedMap.size} item${flaggedMap.size !== 1 ? 's' : ''} to review.`;
    btn.disabled = false;
    btn.textContent = 'Re-Scan';
    toast('Audit completed', 'success');
}

// Export and backup handlers
function openToolsModal(tab = 'export') {
    switchToolsTab(tab);
    openModal('tools-modal');
}

function switchToolsTab(tab) {
    const isExp = tab === 'export';
    document.getElementById('tab-export-btn')?.classList.toggle('active', isExp);
    document.getElementById('tab-import-btn')?.classList.toggle('active', !isExp);
    document.getElementById('panel-export')?.classList.toggle('hidden', !isExp);
    document.getElementById('panel-import')?.classList.toggle('hidden', isExp);
}

function exportVaultJSON() {
    if (!allEntries.length) { toast('Vault is empty', 'error'); return; }
    const exportData = {
        vaultx_version: '1.0',
        exported_at: new Date().toISOString(),
        entries: allEntries.map(e => ({
            site_name: e.site_name,
            site_url: e.site_url,
            username: e.username,
            password: e.password,
            notes: e.notes,
            category: e.category || 'Logins',
            is_favorite: !!e.is_favorite,
            created_at: e.created_at
        }))
    };
    downloadFile(JSON.stringify(exportData, null, 2), `vaultx-backup-${formatDateFile()}.json`, 'application/json');
    toast('JSON backup downloaded', 'success');
}

function exportVaultCSV() {
    if (!allEntries.length) { toast('Vault is empty', 'error'); return; }
    const headers = ['Title', 'URL', 'Username', 'Password', 'Notes', 'Category', 'Favorite'];
    const rows = allEntries.map(e => [
        escapeCSV(e.site_name),
        escapeCSV(e.site_url),
        escapeCSV(e.username),
        escapeCSV(e.password),
        escapeCSV(e.notes),
        escapeCSV(e.category || 'Logins'),
        e.is_favorite ? '1' : '0'
    ]);
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\r\n');
    downloadFile(csvContent, `vaultx-passwords-${formatDateFile()}.csv`, 'text/csv;charset=utf-8;');
    toast('CSV table exported', 'success');
}

function escapeCSV(val) {
    const s = String(val ?? '').replace(/"/g, '""');
    return `"${s}"`;
}

function downloadFile(content, fileName, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 200);
}

function formatDateFile() {
    return new Date().toISOString().slice(0, 10);
}

// File import and parser
function handleFileSelect(e) {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (evt) => {
        try {
            const text = evt.target.result;
            parsedImportItems = [];

            if (file.name.endsWith('.json')) {
                const data = JSON.parse(text);
                const list = Array.isArray(data) ? data : (data.entries || []);
                parsedImportItems = list.map(item => ({
                    site_name: item.site_name || item.title || item.name || 'Untitled',
                    site_url: item.site_url || item.url || item.login_uri || '',
                    username: item.username || item.login_username || '',
                    password: item.password || item.login_password || '',
                    notes: item.notes || item.note || '',
                    category: item.category || 'Logins',
                    is_favorite: !!item.is_favorite
                })).filter(x => x.site_name && x.password);
            } else {
                // Parse CSV
                parsedImportItems = parseCSVToItems(text);
            }

            const preview = document.getElementById('import-preview');
            const previewText = document.getElementById('import-preview-text');
            if (preview && previewText) {
                preview.classList.remove('hidden');
                previewText.textContent = `Detected ${parsedImportItems.length} valid credential${parsedImportItems.length !== 1 ? 's' : ''} ready to import.`;
            }
        } catch (err) {
            toast('Failed to parse file: ' + err.message, 'error');
        }
    };
    reader.readAsText(file);
}

function parseCSVToItems(text) {
    const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0);
    if (lines.length < 2) return [];

    const headers = parseCSVLine(lines[0]).map(h => h.trim().toLowerCase());
    const items = [];

    const titleIdx = headers.findIndex(h => ['title', 'name', 'site', 'service'].includes(h));
    const urlIdx = headers.findIndex(h => ['url', 'login_uri', 'website'].includes(h));
    const userIdx = headers.findIndex(h => ['username', 'login_username', 'email', 'user'].includes(h));
    const passIdx = headers.findIndex(h => ['password', 'login_password', 'pass'].includes(h));
    const noteIdx = headers.findIndex(h => ['notes', 'note', 'comments'].includes(h));
    const catIdx = headers.findIndex(h => ['category', 'folder', 'group'].includes(h));

    for (let i = 1; i < lines.length; i++) {
        const cols = parseCSVLine(lines[i]);
        const site_name = (titleIdx !== -1 ? cols[titleIdx] : '') || 'Imported';
        const password = passIdx !== -1 ? cols[passIdx] : '';
        if (!password) continue;

        items.push({
            site_name,
            site_url: urlIdx !== -1 ? cols[urlIdx] || '' : '',
            username: userIdx !== -1 ? cols[userIdx] || '' : '',
            password,
            notes: noteIdx !== -1 ? cols[noteIdx] || '' : '',
            category: catIdx !== -1 ? cols[catIdx] || 'Logins' : 'Logins',
            is_favorite: false
        });
    }

    return items;
}

function parseCSVLine(line) {
    const res = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
        const c = line[i];
        if (c === '"') {
            if (inQuotes && line[i + 1] === '"') {
                cur += '"';
                i++;
            } else {
                inQuotes = !inQuotes;
            }
        } else if (c === ',' && !inQuotes) {
            res.push(cur);
            cur = '';
        } else {
            cur += c;
        }
    }
    res.push(cur);
    return res;
}

async function executeImport() {
    if (!parsedImportItems.length) {
        toast('No credentials to import', 'error');
        return;
    }

    const btn = document.getElementById('start-import-btn');
    const txt = document.getElementById('import-btn-text');
    const spin = document.getElementById('import-spinner');
    btn.disabled = true;
    txt.textContent = 'Encrypting & Importing…';
    spin.classList.remove('hidden');

    try {
        const encryptedBatch = [];
        for (const item of parsedImportItems) {
            const { encrypted_data, iv } = await encryptVaultItem(vaultKey, item);
            encryptedBatch.push({ encrypted_data, iv });
        }

        const res = await apiFetch('/api/passwords/batch', {
            method: 'POST',
            body: JSON.stringify({ items: encryptedBatch })
        });

        if (!res || !res.ok) {
            toast('Import failed on server', 'error');
            return;
        }

        const data = await res.json();
        toast(data.message || `Imported ${encryptedBatch.length} credentials!`, 'success');
        closeModal('tools-modal');
        parsedImportItems = [];
        document.getElementById('import-preview')?.classList.add('hidden');
        await loadVault();
    } catch (err) {
        toast('Import error: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        txt.textContent = 'Import Credentials';
        spin.classList.add('hidden');
    }
}

// 2FA modal controls
async function open2FAModal() {
    const res = await apiFetch('/api/auth/me');
    if (!res) return;
    const user = await res.json();
    const content = document.getElementById('2fa-content');
    if (!content) return;

    if (user.totp_enabled) {
        content.innerHTML = `
      <div class="alert alert-success" style="margin-bottom:16px;">Two-factor authentication is currently <strong>enabled</strong> on your account.</div>
      <p style="font-size:13px;color:var(--text-secondary);margin-bottom:14px;">Enter your 6-digit authenticator code to disable 2FA:</p>
      <div class="m-group"><input class="m-input" id="dis-code" placeholder="000000" maxlength="6" inputmode="numeric" style="text-align:center;letter-spacing:8px;font-size:22px;font-family:var(--font-mono);"/></div>
      <button class="btn btn-danger" style="width:100%;" onclick="disable2FA()">Disable 2FA</button>`;
    } else {
        content.innerHTML = `
      <p style="font-size:13px;color:var(--text-secondary);margin-bottom:16px;">Add an extra layer of security. Compatible with Google Authenticator, 1Password, or Authy.</p>
      <div id="qr-area" style="display:none;margin-bottom:16px;">
        <p style="font-size:12px;color:var(--text-muted);margin-bottom:10px;">Scan this QR code with your authenticator app:</p>
        <div style="display:flex;justify-content:center;margin-bottom:12px;background:#fff;padding:12px;border-radius:8px;border:1px solid var(--border);"><img id="qr-img" src="" style="width:160px;height:160px;border-radius:6px;"/></div>
        <div class="m-group"><input class="m-input" id="en-code" placeholder="000000" maxlength="6" inputmode="numeric" style="text-align:center;letter-spacing:8px;font-size:22px;font-family:var(--font-mono);"/></div>
        <button class="btn btn-primary" style="width:100%;" onclick="enable2FA()">Activate 2FA</button>
      </div>
      <button class="btn btn-primary" id="start-2fa-btn" style="width:100%;" onclick="start2FA()">Set Up 2FA</button>`;
    }
    openModal('twofa-modal');
}

async function start2FA() {
    const btn = document.getElementById('start-2fa-btn');
    if (btn) btn.textContent = '…';
    const res = await apiFetch('/api/auth/2fa/setup', { method: 'POST' });
    if (!res) return;
    const data = await res.json();
    document.getElementById('qr-img').src = data.qrCode;
    document.getElementById('qr-area').style.display = 'block';
    if (btn) btn.style.display = 'none';
}

async function enable2FA() {
    const code = document.getElementById('en-code')?.value.trim();
    const res = await apiFetch('/api/auth/2fa/verify', { method: 'POST', body: JSON.stringify({ code }) });
    if (!res) return;
    const data = await res.json();
    if (!res.ok) { toast(data.error || 'Invalid code', 'error'); return; }
    toast('2FA enabled successfully', 'success');
    closeModal('twofa-modal');
    await loadUserInfo();
}

async function disable2FA() {
    const code = document.getElementById('dis-code')?.value.trim();
    const res = await apiFetch('/api/auth/2fa/disable', { method: 'POST', body: JSON.stringify({ code }) });
    if (!res) return;
    const data = await res.json();
    if (!res.ok) { toast(data.error || 'Invalid code', 'error'); return; }
    toast('2FA Disabled', 'info');
    closeModal('twofa-modal');
    await loadUserInfo();
}

// Toast notifications
function toast(msg, type = 'success') {
    const c = document.getElementById('toast-container');
    if (!c) return;
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    const iconSvg = type === 'success' ? ICONS.check : (type === 'error' ? ICONS.trash : ICONS.lock);
    t.innerHTML = `<span style="display:flex;align-items:center;">${iconSvg}</span><span>${msg}</span>`;
    c.appendChild(t);
    setTimeout(() => { t.classList.add('fadeOut'); setTimeout(() => t.remove(), 250); }, 3000);
}

function handleLogout() {
    clearSession();
    window.location.href = '/';
}

function esc(s) {
    return String(s || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
