/* admin.js — admin panel & invite link management */

(async () => {
    if (!requireAuth()) return;
    const session = getSession();
    if (!session.isAdmin) { window.location.href = '/dashboard'; return; }

    const avatar = document.getElementById('user-avatar');
    const nameEl = document.getElementById('nav-username');
    if (avatar) avatar.textContent = (session.username || 'A')[0].toUpperCase();
    if (nameEl) nameEl.textContent = session.username || 'Admin';

    await Promise.all([loadStats(), loadUsers(), loadInvites()]);
})();

// Instance statistics
async function loadStats() {
    const res = await apiFetch('/api/admin/stats');
    if (!res) return;
    const data = await res.json();
    document.getElementById('stat-users').textContent = data.users ?? '0';
    document.getElementById('stat-passwords').textContent = data.passwords ?? '0';
    document.getElementById('stat-sends').textContent = data.sends ?? '0';
    const invEl = document.getElementById('stat-invites');
    if (invEl) invEl.textContent = data.activeInvites ?? '0';
}

// Invite management
async function loadInvites() {
    const res = await apiFetch('/api/admin/invites');
    if (!res) return;
    const invites = await res.json();

    const tbody = document.getElementById('invites-tbody');
    if (!tbody) return;

    if (!invites.length) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:30px;color:var(--text-muted);">No invite links created yet. Click "Generate New Invite Link" above to invite friends.</td></tr>`;
        return;
    }

    tbody.innerHTML = invites.map(inv => {
        const fullLink = `${window.location.origin}/register?invite=${inv.code}`;
        const shortCode = `${inv.code.substring(0, 10)}…${inv.code.substring(inv.code.length - 6)}`;
        const expDate = new Date(inv.expires_at).toLocaleString();
        const createdDate = new Date(inv.created_at).toLocaleDateString();

        let badgeClass = 'badge-user';
        if (inv.status === 'Active') badgeClass = 'badge-2fa';
        else if (inv.status === 'Used') badgeClass = 'badge-admin';

        return `<tr>
            <td>
                <div style="display:flex;align-items:center;gap:8px;">
                    <code style="background:var(--bg-subtle);border:1px solid var(--border);padding:3px 6px;border-radius:4px;font-family:var(--font-mono);font-size:11px;">
                        ${shortCode}
                    </code>
                    <button class="btn btn-secondary btn-icon" onclick="copyInviteUrl('${inv.code}')" title="Copy Invite Link">
                        ${ICONS.copy}
                    </button>
                </div>
            </td>
            <td>
                <span class="badge ${badgeClass}">${inv.status}</span>
            </td>
            <td style="font-family:var(--font-mono);font-size:12px;">
                ${inv.uses} / ${inv.max_uses}
            </td>
            <td style="font-size:12px;color:var(--text-muted);">
                ${expDate}
            </td>
            <td style="font-size:12px;color:var(--text-muted);">
                ${createdDate}
            </td>
            <td>
                <button class="btn btn-danger btn-icon" onclick="revokeInvite(${inv.id})" title="Revoke Invite">
                    ${ICONS.trash} Revoke
                </button>
            </td>
        </tr>`;
    }).join('');
}

// Handle Generate Invite Form
const inviteForm = document.getElementById('invite-form');
if (inviteForm) {
    inviteForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const btn = document.getElementById('gen-invite-btn');
        btn.disabled = true;
        btn.textContent = 'Generating…';

        const hours = document.getElementById('invite-expiry').value;
        const uses = document.getElementById('invite-uses').value;

        try {
            const res = await apiFetch('/api/admin/invites', {
                method: 'POST',
                body: JSON.stringify({ expiry_hours: hours, max_uses: uses })
            });

            if (!res || !res.ok) {
                const err = res ? (await res.json()).error : 'Failed to create invite';
                showToast(err, 'error');
                return;
            }

            const data = await res.json();
            const fullLink = `${window.location.origin}/register?invite=${data.code}`;

            const banner = document.getElementById('new-invite-banner');
            const urlInput = document.getElementById('new-invite-url');
            if (banner && urlInput) {
                urlInput.value = fullLink;
                banner.style.display = 'block';
            }

            showToast('Invite link generated successfully', 'success');
            await Promise.all([loadStats(), loadInvites()]);
        } catch (err) {
            showToast(err.message || 'Error creating invite', 'error');
        } finally {
            btn.disabled = false;
            btn.textContent = 'Generate New Invite Link';
        }
    });
}

function copyNewInvite() {
    const input = document.getElementById('new-invite-url');
    if (!input || !input.value) return;
    navigator.clipboard.writeText(input.value).then(() => {
        showToast('Invite link copied to clipboard', 'success');
    }).catch(() => {
        showToast('Failed to copy', 'error');
    });
}

function copyInviteUrl(code) {
    const fullLink = `${window.location.origin}/register?invite=${code}`;
    navigator.clipboard.writeText(fullLink).then(() => {
        showToast('Invite link copied to clipboard', 'success');
    }).catch(() => {
        showToast('Failed to copy', 'error');
    });
}

async function revokeInvite(id) {
    if (!confirm('Are you sure you want to revoke this invite? It will no longer allow any signups.')) return;
    const res = await apiFetch(`/api/admin/invites/${id}`, { method: 'DELETE' });
    if (!res || !res.ok) { showToast('Failed to revoke invite', 'error'); return; }
    showToast('Invite revoked', 'info');
    await Promise.all([loadStats(), loadInvites()]);
}

// User management
async function loadUsers() {
    const res = await apiFetch('/api/admin/users');
    if (!res) return;
    const users = await res.json();

    const badge = document.getElementById('user-count-badge');
    if (badge) badge.textContent = `${users.length} user${users.length !== 1 ? 's' : ''}`;

    const tbody = document.getElementById('users-tbody');
    if (!users.length) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--text-muted);">No users found</td></tr>`;
        return;
    }

    const session = getSession();
    tbody.innerHTML = users.map(u => {
        const isMe = session.username && u.username.toLowerCase() === session.username.toLowerCase();
        const joinDate = new Date(u.created_at).toLocaleDateString();
        return `<tr>
      <td>
        <div style="display:flex;align-items:center;gap:10px;">
          <div class="nav-avatar" style="flex-shrink:0;">${(u.username || '?')[0].toUpperCase()}</div>
          <div>
            <div style="font-weight:500;color:var(--text-primary);">${esc(u.username)}</div>
            ${isMe ? '<div style="font-size:11px;color:var(--text-muted);">Current User</div>' : ''}
          </div>
        </div>
      </td>
      <td><span class="badge ${u.is_admin ? 'badge-admin' : 'badge-user'}">${u.is_admin ? 'Admin' : 'Member'}</span></td>
      <td>${u.totp_enabled ? '<span class="badge badge-2fa">Enabled</span>' : '<span class="text-muted text-sm">Disabled</span>'}</td>
      <td style="color:var(--text-primary);font-weight:500;font-family:var(--font-mono);">${u.entry_count}</td>
      <td style="font-size:12px;color:var(--text-muted);">${joinDate}</td>
      <td>
        <div style="display:flex;gap:6px;">
          ${!isMe ? `
            <button class="btn btn-secondary btn-icon" onclick="toggleAdmin(${u.id}, ${u.is_admin})" title="${u.is_admin ? 'Demote from Admin' : 'Promote to Admin'}">
              ${u.is_admin ? ICONS.arrowDown : ICONS.arrowUp}
            </button>
            <button class="btn btn-danger btn-icon" onclick="deleteUser(${u.id}, '${esc(u.username)}')" title="Delete user">
              ${ICONS.trash}
            </button>
          ` : '<span class="text-muted text-sm">—</span>'}
        </div>
      </td>
    </tr>`;
    }).join('');
}

async function deleteUser(id, username) {
    if (!confirm(`Delete user "${username}" and all associated vault records? This cannot be undone.`)) return;
    const res = await apiFetch(`/api/admin/users/${id}`, { method: 'DELETE' });
    if (!res) return;
    const data = await res.json();
    if (!res.ok) { showToast(data.error || 'Failed to delete user', 'error'); return; }
    showToast(`User "${username}" deleted`, 'success');
    await Promise.all([loadStats(), loadUsers()]);
}

async function toggleAdmin(id, currentlyAdmin) {
    const action = currentlyAdmin ? 'remove admin privileges from' : 'grant admin privileges to';
    if (!confirm(`Are you sure you want to ${action} this user?`)) return;
    const res = await apiFetch(`/api/admin/users/${id}/toggle-admin`, { method: 'POST' });
    if (!res) return;
    const data = await res.json();
    if (!res.ok) { showToast(data.error || 'Action failed', 'error'); return; }
    showToast(data.message, 'success');
    await loadUsers();
}

function showToast(msg, type = 'success') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icon = type === 'success' ? ICONS.check : (type === 'error' ? ICONS.trash : ICONS.lock);
    toast.innerHTML = `<span style="display:inline-flex;align-items:center;">${icon}</span><span>${msg}</span>`;
    container.appendChild(toast);
    setTimeout(() => { toast.classList.add('fadeOut'); setTimeout(() => toast.remove(), 300); }, 3000);
}

function handleLogout() { clearSession(); window.location.href = '/'; }
function esc(str) { return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }
