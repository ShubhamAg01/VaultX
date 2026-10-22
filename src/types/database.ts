export interface User {
    id: number;
    username: string;
    password_hash: string;
    pbkdf2_salt: string;
    totp_secret: string | null;
    totp_enabled: number; // 0 or 1
    is_admin: number; // 0 or 1
    created_at: string;
}

export interface UserSummary {
    id: number;
    username: string;
    is_admin: number;
    totp_enabled: number;
    created_at: string;
    entry_count?: number;
}

export interface Invite {
    id: number;
    code: string;
    created_by: number;
    max_uses: number;
    uses: number;
    expires_at: string;
    created_at: string;
    creator_name?: string;
    status?: 'Active' | 'Used' | 'Expired';
    is_active?: boolean;
}

export interface PasswordEntry {
    id: number;
    user_id: number;
    encrypted_data: string;
    iv: string;
    created_at: string;
    updated_at: string;
}

export interface SendEntry {
    id: number;
    token: string;
    encrypted_data: string;
    max_views: number;
    views: number;
    expires_at: string;
    created_at: string;
}

export interface AuthUserPayload {
    userId: number;
    username: string;
    isAdmin: boolean;
    type: 'auth' | 'pre_auth';
}
