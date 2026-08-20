import assert from 'node:assert/strict';
import { once } from 'node:events';
import { Client } from 'ssh2';
import { ConnectionInfo, activeConnections } from '../state';
import { createShare, revokeSharesForConnection } from '../share';

process.env.SSH_PORT = '0';
const { sshServer } = require('../ssh') as typeof import('../ssh');

const wait = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

async function waitForOutput(stream: any, expected: string): Promise<string> {
    let output = '';
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            stream.off('data', onData);
            reject(new Error(`Timed out waiting for ${expected}; received ${JSON.stringify(output)}`));
        }, 2000);
        const onData = (data: Buffer) => {
            output += data.toString();
            if (!output.includes(expected)) return;
            clearTimeout(timer);
            stream.off('data', onData);
            resolve(output);
        };
        stream.on('data', onData);
    });
}

async function waitFor(check: () => boolean) {
    for (let i = 0; i < 20; i++) {
        if (check()) return;
        await wait(25);
    }
    assert.ok(check(), 'timed out waiting for expected target write');
}

async function connectGuest(port: number) {
    const client = new Client();
    client.connect({
        host: '127.0.0.1',
        port,
        username: 'guest',
        hostVerifier: () => true,
        authHandler: ['none'],
    });
    await once(client, 'ready');
    const stream = await new Promise<any>((resolve, reject) => {
        client.shell({ rows: 24, cols: 80 }, (err, channel) => err ? reject(err) : resolve(channel));
    });
    return { client, stream };
}

async function closeClient(client: Client) {
    const closed = once(client, 'close');
    client.end();
    await closed;
}

async function main() {
    if (!sshServer.listening) await once(sshServer, 'listening');
    const address = sshServer.address();
    assert.ok(address && typeof address !== 'string');

    const targetWrites: Buffer[] = [];
    const otherWrites: Buffer[] = [];
    const targetSocket = {
        destroyed: false,
        writable: true,
        writableEnded: false,
        write: (data: Buffer) => { targetWrites.push(Buffer.from(data)); return true; },
    } as any;
    const otherSocket = {
        destroyed: false,
        writable: true,
        writableEnded: false,
        write: (data: Buffer) => { otherWrites.push(Buffer.from(data)); return true; },
    } as any;
    const target = new ConnectionInfo(targetSocket, '', '');
    activeConnections.set('target', target);
    activeConnections.set('other-target', new ConnectionInfo(otherSocket, '', ''));

    try {
        const readOnlyToken = createShare('target', 'ro');
        const readOnly = await connectGuest(address.port);
        const prompt = await waitForOutput(readOnly.stream, 'Share token:');
        assert.ok(!prompt.includes('Command mode'));

        const forwardError = await new Promise<Error | undefined>((resolve) => {
            readOnly.client.forwardOut('127.0.0.1', 10000, '127.0.0.1', 22, resolve);
        });
        assert.ok(forwardError, 'guest direct-tcpip must be rejected');

        const prefix = readOnlyToken.slice(0, 3);
        const maskedPrompt = waitForOutput(readOnly.stream, '***');
        readOnly.stream.write(prefix);
        const maskedOutput = await maskedPrompt;
        assert.ok(!maskedOutput.includes(prefix));
        readOnly.stream.write('\x7f'.repeat(prefix.length));
        await wait(50);

        const readOnlyReady = waitForOutput(readOnly.stream, 'Shared terminal: read-only');
        readOnly.stream.write(`${readOnlyToken}\r`);
        await readOnlyReady;
        readOnly.stream.write('blocked');
        readOnly.stream.setWindow(40, 120, 0, 0);
        await wait(100);
        assert.equal(targetWrites.length, 0);
        assert.equal(target.rows, 24);
        assert.equal(target.cols, 80);
        await closeClient(readOnly.client);

        const readWriteToken = createShare('target', 'rw');
        const readWrite = await connectGuest(address.port);
        const readWriteReady = waitForOutput(readWrite.stream, 'Shared terminal: read-write');
        readWrite.stream.write(`${readWriteToken}\r`);
        await readWriteReady;
        const payload = Buffer.from('\x1b[<0;1;1Mhello');
        readWrite.stream.write(payload);
        await waitFor(() => targetWrites.length === 1);
        assert.deepEqual(targetWrites[0], payload);
        assert.equal(otherWrites.length, 0);
        readWrite.stream.setWindow(50, 100, 0, 0);
        await wait(100);
        assert.equal(target.rows, 24);
        assert.equal(target.cols, 80);
        await closeClient(readWrite.client);
    } finally {
        revokeSharesForConnection('target');
        activeConnections.clear();
        await new Promise<void>((resolve) => sshServer.close(() => resolve()));
    }
}

main().then(
    () => process.exit(0),
    (err) => { console.error(err); process.exit(1); },
);
