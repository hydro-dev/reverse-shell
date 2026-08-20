import { createHash, randomBytes } from 'crypto';

export type SharePermission = 'ro' | 'rw';

type Share = {
    connectionId: string;
    permission: SharePermission;
};

const shares = new Map<string, Share>();

const digest = (token: string) => createHash('sha256').update(token).digest('hex');

export function createShare(connectionId: string, permission: SharePermission): string {
    const token = randomBytes(32).toString('base64url');
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
