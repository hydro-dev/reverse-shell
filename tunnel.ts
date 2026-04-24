import * as net from 'net';
import { activeConnections, serverIp } from './state';

export const TUNNEL_SERVER_PORT = 13337;

interface TunnelEntry {
    targetSocket: net.Socket;
    connectionId: string;
    remotePort: number;
}

export interface LocalTunnel {
    server: net.Server;
    localPort: number;
    connectionId: string;
    remotePort: number;
}

const waitingTargetSockets: TunnelEntry[] = [];
export const activeTunnels = new Map<string, LocalTunnel>();

const tunnelServer = net.createServer((targetSocket) => {
    console.log(`[tunnel] target connected from ${targetSocket.remoteAddress}:${targetSocket.remotePort}`);
    let headerBuf = '';

    // Send READY signal so client knows it can send the TUNNEL header
    targetSocket.write('READY\n');

    const onData = (chunk: Buffer) => {
        console.log(`[tunnel] onData received ${chunk.length} bytes: ${chunk.toString().trim()}`);
        headerBuf += chunk.toString();
        const nlIdx = headerBuf.indexOf('\n');
        if (nlIdx === -1) return;

        targetSocket.off('data', onData);
        const line = headerBuf.slice(0, nlIdx).trim();
        const parts = line.split(' ');

        if (parts.length < 3 || parts[0] !== 'TUNNEL') {
            console.log(`[tunnel] bad header: ${line}`);
            targetSocket.destroy();
            return;
        }

        const connectionId = parts[1];
        const remotePort = parseInt(parts[2]);

        if (!activeTunnels.has(`${connectionId}:${remotePort}`)) {
            console.log(`[tunnel] no active tunnel for ${connectionId}:${remotePort}`);
            targetSocket.destroy();
            return;
        }

        console.log(`[tunnel] target registered: ${connectionId}:${remotePort}`);
        waitingTargetSockets.push({ targetSocket, connectionId, remotePort });

        targetSocket.on('close', () => {
            console.log(`[tunnel] target socket closed: ${connectionId}:${remotePort}`);
            const idx = waitingTargetSockets.findIndex((e) => e.targetSocket === targetSocket);
            if (idx !== -1) waitingTargetSockets.splice(idx, 1);
        });
        targetSocket.on('error', (err) => { console.log(`[tunnel] target socket error: ${err.message}`); });
    };

    targetSocket.on('data', onData);
    targetSocket.on('error', () => {});
});

tunnelServer.listen(TUNNEL_SERVER_PORT, '0.0.0.0', () => {
    console.log(`[*] Tunnel server listening on port ${TUNNEL_SERVER_PORT}`);
});

function popWaitingSocket(connectionId: string, remotePort: number): net.Socket | null {
    const idx = waitingTargetSockets.findIndex(
        (e) => e.connectionId === connectionId && e.remotePort === remotePort,
    );
    if (idx === -1) return null;
    const [entry] = waitingTargetSockets.splice(idx, 1);
    return entry.targetSocket;
}

function bridge(a: net.Socket, b: net.Socket) {
    a.pipe(b);
    b.pipe(a);
    const destroy = () => { try { a.destroy(); } catch {} try { b.destroy(); } catch {} };
    a.on('close', destroy);
    b.on('close', destroy);
    a.on('error', destroy);
    b.on('error', destroy);
}

export function requestTargetTunnel(connectionId: string, remotePort: number) {
    const connInfo = activeConnections.get(connectionId);
    if (!connInfo) { console.log(`[tunnel] requestTargetTunnel: no connection ${connectionId}`); return; }
    console.log(`[tunnel] requesting client tunnel: remote=${remotePort} server=${serverIp}:${TUNNEL_SERVER_PORT} conn=${connectionId}`);
    connInfo.socket.write(`\x1b[9;${remotePort};${TUNNEL_SERVER_PORT};${serverIp};${connectionId}t`);
}

export function findAvailablePort(start: number): Promise<number> {
    const port = start > 65535 ? 40000 : start;
    return new Promise((resolve, reject) => {
        const probe = net.createServer();
        probe.listen(port, '127.0.0.1', () => {
            probe.close(() => resolve(port));
        });
        probe.on('error', (err: NodeJS.ErrnoException) => {
            if (err.code === 'EADDRINUSE' && port < 65534) {
                resolve(findAvailablePort(port + 1));
            } else {
                reject(new Error(`No available port starting from ${start}`));
            }
        });
    });
}

export function registerTunnel(
    connectionId: string,
    remotePort: number,
    localPort: number,
): Promise<void> {
    const key = `${connectionId}:${remotePort}`;
    if (activeTunnels.has(key)) {
        return Promise.reject(new Error(`Tunnel ${key} already active`));
    }

    const bindHost = '0.0.0.0';

    return new Promise((resolve, reject) => {
        const localServer = net.createServer((localSocket) => {
            console.log(`[tunnel] local connection on port ${localPort} for ${connectionId}:${remotePort}`);
            const tryBridge = (attempts: number) => {
                const ts = popWaitingSocket(connectionId, remotePort);
                if (ts) {
                    console.log(`[tunnel] bridged ${connectionId}:${remotePort}`);
                    bridge(localSocket, ts);
                    requestTargetTunnel(connectionId, remotePort);
                    return;
                }
                if (attempts <= 0) {
                    console.log(`[tunnel] bridge timeout ${connectionId}:${remotePort}, no target socket arrived`);
                    localSocket.destroy();
                    return;
                }
                requestTargetTunnel(connectionId, remotePort);
                setTimeout(() => tryBridge(attempts - 1), 200);
            };
            tryBridge(25);
        });

        localServer.listen(localPort, bindHost, () => {
            activeTunnels.set(key, { server: localServer, localPort, connectionId, remotePort });
            resolve();
        });

        localServer.on('error', reject);
    });
}

export function unregisterTunnel(connectionId: string, remotePort: number) {
    const key = `${connectionId}:${remotePort}`;
    const tunnel = activeTunnels.get(key);
    if (!tunnel) return;
    tunnel.server.close();
    activeTunnels.delete(key);
    waitingTargetSockets
        .filter((e) => e.connectionId === connectionId && e.remotePort === remotePort)
        .forEach((e) => e.targetSocket.destroy());
}
