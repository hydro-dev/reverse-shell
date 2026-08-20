import assert from 'node:assert/strict';
import { createShare, lookupShare, revokeSharesForConnection } from '../share';

const readOnlyToken = createShare('connection-a', 'ro');
const readWriteToken = createShare('connection-b', 'rw');

assert.equal(readOnlyToken.length, 43);
assert.equal(readWriteToken.length, 43);
assert.match(readOnlyToken, /^[A-Za-z0-9_-]{43}$/);
assert.match(readWriteToken, /^[A-Za-z0-9_-]{43}$/);
assert.notEqual(readOnlyToken, readWriteToken);
assert.deepEqual(lookupShare(readOnlyToken), { connectionId: 'connection-a', permission: 'ro' });
assert.deepEqual(lookupShare(readWriteToken), { connectionId: 'connection-b', permission: 'rw' });
assert.equal(lookupShare('invalid-token'), null);

revokeSharesForConnection('connection-a');
assert.equal(lookupShare(readOnlyToken), null);
assert.deepEqual(lookupShare(readWriteToken), { connectionId: 'connection-b', permission: 'rw' });
