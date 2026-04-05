import * as net from 'net';
import { activeConnections } from './state';

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
    let headerBuf = '';

    const onData = (chunk: Buffer) => {
        headerBuf += chunk.toString();
        const nlIdx = headerBuf.indexOf('\n');
        if (nlIdx === -1) return;

        targetSocket.off('data', onData);
        const line = headerBuf.slice(0, nlIdx).trim();
        const parts = line.split(' ');

        if (parts.length < 3 || parts[0] !== 'TUNNEL') {
            targetSocket.destroy();
            return;
        }

        const connectionId = parts[1];
        const remotePort = parseInt(parts[2]);

        if (!activeTunnels.has(`${connectionId}:${remotePort}`)) {
            targetSocket.destroy();
            return;
        }

        waitingTargetSockets.push({ targetSocket, connectionId, remotePort });

        targetSocket.on('close', () => {
            const idx = waitingTargetSockets.findIndex((e) => e.targetSocket === targetSocket);
            if (idx !== -1) waitingTargetSockets.splice(idx, 1);
        });
        targetSocket.on('error', () => {});
    };

    targetSocket.on('data', onData);
    targetSocket.on('error', () => {});
});

tunnelServer.listen(TUNNEL_SERVER_PORT, () => {
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
    if (!connInfo) return;
    const serverIp = (connInfo.socket.localAddress ?? '127.0.0.1').replace('::ffff:', '');
    connInfo.socket.write(`\x1b[9;${remotePort};${TUNNEL_SERVER_PORT};${serverIp};${connectionId}t`);
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

    return new Promise((resolve, reject) => {
        const localServer = net.createServer((localSocket) => {
            const tryBridge = (attempts: number) => {
                const ts = popWaitingSocket(connectionId, remotePort);
                if (ts) {
                    bridge(localSocket, ts);
                    requestTargetTunnel(connectionId, remotePort);
                    return;
                }
                if (attempts <= 0) {
                    localSocket.destroy();
                    return;
                }
                requestTargetTunnel(connectionId, remotePort);
                setTimeout(() => tryBridge(attempts - 1), 200);
            };
            tryBridge(25);
        });

        localServer.listen(localPort, () => {
            activeTunnels.set(key, { server: localServer, localPort, connectionId, remotePort });
            requestTargetTunnel(connectionId, remotePort);
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
