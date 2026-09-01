import assert from 'node:assert/strict';
import { createShare, lookupShare, revokeSharesForConnection } from '../share';

const readOnlyToken = createShare('connection-a', 'ro');
const readWriteToken = createShare('connection-b', 'rw');

assert.equal(readOnlyToken.length, 45);
assert.equal(readWriteToken.length, 45);
assert.match(readOnlyToken, /^[23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz]{45}$/);
assert.match(readWriteToken, /^[23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz]{45}$/);
assert.notEqual(readOnlyToken, readWriteToken);
assert.deepEqual(lookupShare(readOnlyToken), { connectionId: 'connection-a', permission: 'ro' });
assert.deepEqual(lookupShare(readWriteToken), { connectionId: 'connection-b', permission: 'rw' });
assert.equal(lookupShare('invalid-token'), null);

revokeSharesForConnection('connection-a');
assert.equal(lookupShare(readOnlyToken), null);
assert.deepEqual(lookupShare(readWriteToken), { connectionId: 'connection-b', permission: 'rw' });
