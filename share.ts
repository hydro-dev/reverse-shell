import { createHash, randomBytes } from 'crypto';

export type SharePermission = 'ro' | 'rw';

type Share = {
    connectionId: string;
    permission: SharePermission;
};

const shares = new Map<string, Share>();
const TOKEN_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz';
const TOKEN_LENGTH = 45;
const TOKEN_MAX_BYTE = Math.floor(256 / TOKEN_ALPHABET.length) * TOKEN_ALPHABET.length;

const digest = (token: string) => createHash('sha256').update(token).digest('hex');

function createToken() {
    let token = '';
    while (token.length < TOKEN_LENGTH) {
        for (const byte of randomBytes(TOKEN_LENGTH)) {
            if (byte >= TOKEN_MAX_BYTE) continue;
            token += TOKEN_ALPHABET[byte % TOKEN_ALPHABET.length];
            if (token.length === TOKEN_LENGTH) break;
        }
    }
    return token;
}

export function createShare(connectionId: string, permission: SharePermission): string {
    const token = createToken();
    shares.set(digest(token), { connectionId, permission });
    return token;
}

export function lookupShare(token: string): Share | null {
    return shares.get(digest(token)) ?? null;
}

export function revokeSharesForConnection(connectionId: string) {
    for (const [tokenDigest, share] of shares) {
        if (share.connectionId === connectionId) shares.delete(tokenDigest);
    }
}
