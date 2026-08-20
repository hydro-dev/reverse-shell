import { timingSafeEqual } from 'crypto';
import { Server } from 'ssh2';
import * as fs from 'fs';
import * as path from 'path';
import { homedir } from 'os';
import { AuthorizedKeysStore } from './authorizedKeys';
import { activeConnections, activeSSHConnections, resetGuestSessionsForConnection, setAlias, SSHConnection, writeSocketSafe } from './state';
import { createShare, lookupShare, revokeSharesForConnection } from './share';
import { activeTunnels, findAvailablePort, registerTunnel, requestTargetSocket, unregisterTunnel } from './tunnel';

const SSH_PORT = Number(process.env.SSH_PORT ?? 13336);

const dotssh = path.join(homedir(), '.ssh');
if (!fs.existsSync(dotssh)) fs.mkdirSync(dotssh);

const privateKeyPath = path.join(dotssh, 'id_rsa');
const publicKeyPath = path.join(dotssh, 'id_rsa.pub');
const authorizedKeysPath = path.join(dotssh, 'authorized_keys');

if (!fs.existsSync(privateKeyPath)) {
    const { execSync } = require('child_process');
    execSync(`ssh-keygen -t rsa -b 4096 -f ${privateKeyPath} -N ""`);
}

const authorizedKeys = new AuthorizedKeysStore(authorizedKeysPath);
authorizedKeys.startWatching();

const eq = (a: Buffer, b: Buffer) => {
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
}

const normalizeHost = (ip: string) => {
    const c = ip.replace('::ffff:', '');
    return c === '::1' ? '127.0.0.1' : c;
};

// Resolve a direct-tcpip destIP (from `ssh -J admin@mgmt <user>@<dest>`) to an active
// connection id, matching by alias first, then client id, then remote IP / legacy ip:port key.
const resolveConnectionId = (destIP: string): string | null => {
    for (const [id, info] of activeConnections) {
        if (info.alias && info.alias === destIP) return id;
    }
    if (activeConnections.has(destIP)) return destIP;
    const target = normalizeHost(destIP);
    for (const [id, info] of activeConnections) {
        const rip = info.socket?.remoteAddress;
        if (rip && normalizeHost(rip) === target) return id;
        if (id.startsWith(`${target}:`)) return id;
    }
    return null;
};

// SSH direct-tcpip (ssh -J / ssh -L / ssh -W): bridge the channel to remotePort on the target.
const handleDirectTcpip = (
    accept: () => any,
    reject: () => void,
    info: { destIP: string; destPort: number; srcIP: string; srcPort: number },
) => {
    const connId = resolveConnectionId(info.destIP);
    if (!connId) {
        console.log(`[tcpip] no connection for dest ${info.destIP}:${info.destPort}`);
        try { reject(); } catch {}
        return;
    }
    console.log(`[tcpip] direct ${info.srcIP}:${info.srcPort} -> ${info.destIP}:${info.destPort} via ${connId}`);
    let channel: any;
    try { channel = accept(); } catch { return; }
    // Guard the requestTargetSocket window so a channel-level reset can't crash the daemon.
    channel.on('error', () => { try { channel.close(); } catch {} });
    requestTargetSocket(connId, info.destPort)
        .then((targetSocket) => {
            channel.pipe(targetSocket);
            targetSocket.pipe(channel);
            const cleanup = () => {
                try { targetSocket.destroy(); } catch {}
                try { channel.end(); } catch {}
                try { channel.close(); } catch {}
            };
            channel.on('close', cleanup);
            channel.on('error', cleanup);
            targetSocket.on('close', cleanup);
            targetSocket.on('error', cleanup);
        })
        .catch((e: Error) => {
            console.log(`[tcpip] failed ${connId}:${info.destPort}: ${e.message}`);
            try { channel.end(); } catch {}
            try { channel.close(); } catch {}
        });
};

export const sshServer = new Server({
    hostKeys: [fs.readFileSync(privateKeyPath)],
}, (client) => {
    const clientInfo = `SSH client`;
    console.log(`[+] New admin connection from ${clientInfo}`);

    const state = new SSHConnection(null);
    activeSSHConnections.set(client, state);

    client.on('authentication', (ctx) => {
        if (eq(Buffer.from(ctx.username), Buffer.from('guest'))) {
            if (ctx.method !== 'none') return ctx.reject();
            state.isGuest = true;
            return ctx.accept();
        }
        if (!eq(Buffer.from(ctx.username), Buffer.from('user')))
            return ctx.reject();
        switch (ctx.method) {
            case 'password':
                return ctx.reject();
            case 'publickey':
                for (const allowedPubKey of authorizedKeys.current) {
                    if (ctx.key.algo == allowedPubKey.type
                        && eq(ctx.key.data, allowedPubKey.getPublicSSH())
                        && (!ctx.signature || allowedPubKey.verify(ctx.blob!, ctx.signature, ctx.hashAlgo))) {
                        return ctx.accept();
                    }
                }
                return ctx.reject();
            default:
                return ctx.reject();
        }
    });

    client.on('ready', () => {
        client.on('tcpip', (accept, reject, info) => {
            if (state.isGuest) return reject();
            handleDirectTcpip(accept, reject, info);
        });
        client.on('session', (accept, reject) => {
            const session = accept();

            // 先处理PTY请求
            session.on('pty', (accept, reject, info) => {
                state.rows = info.rows;
                state.cols = info.cols;
                accept();
            });

            // 处理窗口大小变化
            session.on('window-change', (accept, reject, info) => {
                accept?.();
                state.rows = info.rows;
                state.cols = info.cols;
                if (state.isGuest) {
                    if (state.guestConnectionId) {
                        const connInfo = activeConnections.get(state.guestConnectionId);
                        if (connInfo) state.renderSharedTerminal(connInfo);
                        else state.resetGuestShare();
                    } else {
                        state.renderGuestTokenPrompt();
                    }
                    return;
                }
                if (state.settingsPanel) {
                    state.renderSettingsPanel();
                } else if (state.selectedId) {
                    const connInfo = activeConnections.get(state.selectedId);
                    if (connInfo && state.rows && state.cols) {
                        connInfo.resize(state.rows - 1, state.cols);
                    }
                    state.stream?.write(`\x1b[1;${info.rows - 1}r`);
                } else {
                    state.stream?.write('\x1b[r');
                }
                state.drawBottomBar();
            });

            session.on('shell', (accept, reject) => {
                const stream = accept();
                state.stream = stream;
                if (!state.rows) {
                    state.rows = 24;
                    state.cols = 80;
                }
                if (state.isGuest) {
                    console.log('[*] Guest shell session started');
                    state.renderGuestTokenPrompt();
                    stream.on('data', (data: Buffer) => {
                        if (state.guestConnectionId) {
                            if (state.guestPermission === 'rw') {
                                const conn = activeConnections.get(state.guestConnectionId);
                                if (conn) writeSocketSafe(conn.socket, data);
                                else state.resetGuestShare();
                            }
                            return;
                        }
                        for (const char of data.toString()) {
                            if (char === '\r' || char === '\n') {
                                const share = lookupShare(state.guestTokenInput);
                                const conn = share && activeConnections.get(share.connectionId);
                                state.guestTokenInput = '';
                                if (!share || !conn) {
                                    state.guestTokenError = 'Invalid share token';
                                    state.renderGuestTokenPrompt();
                                    continue;
                                }
                                state.guestTokenError = '';
                                state.guestConnectionId = share.connectionId;
                                state.guestPermission = share.permission;
                                state.renderSharedTerminal(conn);
                                return;
                            } else if (char === '\x7f' || char === '\x08') {
                                state.guestTokenInput = state.guestTokenInput.slice(0, -1);
                                state.guestTokenError = '';
                                state.renderGuestTokenPrompt();
                            } else if (/^[A-Za-z0-9_-]$/.test(char) && state.guestTokenInput.length < 128) {
                                state.guestTokenInput += char;
                                state.guestTokenError = '';
                                state.renderGuestTokenPrompt();
                            }
                        }
                    });
                    stream.on('close', () => {
                        state.stream = null;
                        state.guestConnectionId = null;
                        console.log('[-] Guest shell session closed');
                    });
                    stream.on('error', () => { try { stream.destroy(); } catch {} });
                    return;
                }
                console.log('[*] Admin shell session started');

                const closeAdminShell = () => {
                    try { stream.write('\x1b[?1002l\x1b[?1006l'); } catch {}
                    stream.end();
                };

                // 清屏并设置初始状态
                stream.write('\x1b[2J\x1b[H');
                stream.write('Command mode - click tab, 0=settings, number=switch connection, l=list, :alias <name>=rename, q=quit\r\n');
                stream.write('\x1b[r'); // Initial full scroll region for command mode
                state.drawBottomBar();

                const executeAdminCommand = (cmd: string) => {
                    const parts = cmd.trim().split(/\s+/);
                    switch (parts[0]) {
                        case 'fwd': {
                            if (!state.selectedId) {
                                state.statusMessage = 'Error: no connection selected';
                                break;
                            }
                            const fwdArgs = parts.slice(1);
                            const remotePort = parseInt(fwdArgs[0]);
                            if (isNaN(remotePort) || remotePort < 1 || remotePort > 65535) {
                                state.statusMessage = 'Usage: fwd <remotePort> [localPort]';
                                break;
                            }
                            const rawLocal = parseInt(fwdArgs[1]);
                            const isManual = !isNaN(rawLocal);
                            const connId = state.selectedId;
                            if (isManual) {
                                if (rawLocal < 1 || rawLocal > 65535) {
                                    state.statusMessage = 'Error: local port must be between 1 and 65535';
                                    break;
                                }
                                registerTunnel(connId, remotePort, rawLocal)
                                    .then(() => {
                                        state.statusMessage = `[+] Tunnel: 0.0.0.0:${rawLocal} -> target:${remotePort}`;
                                        state.drawBottomBar();
                                    })
                                    .catch((e: Error) => {
                                        state.statusMessage = `[-] Failed: ${e.message}`;
                                        state.drawBottomBar();
                                    });
                            } else {
                                findAvailablePort(10000 + remotePort)
                                    .then((localPort) =>
                                        registerTunnel(connId, remotePort, localPort).then(() => localPort),
                                    )
                                    .then((localPort) => {
                                        state.statusMessage = `[+] Tunnel: 0.0.0.0:${localPort} -> target:${remotePort}`;
                                        state.drawBottomBar();
                                    })
                                    .catch((e: Error) => {
                                        state.statusMessage = `[-] Failed: ${e.message}`;
                                        state.drawBottomBar();
                                    });
                            }
                            break;
                        }
                        case 'unfwd': {
                            if (!state.selectedId) {
                                state.statusMessage = 'Error: no connection selected';
                                break;
                            }
                            const remotePort = parseInt(parts[1]);
                            if (isNaN(remotePort)) {
                                state.statusMessage = 'Usage: unfwd <remotePort>';
                                break;
                            }
                            unregisterTunnel(state.selectedId, remotePort);
                            state.statusMessage = `[-] Tunnel removed: target:${remotePort}`;
                            break;
                        }
                        case 'tunnels': {
                            if (activeTunnels.size === 0) {
                                stream.write('No active tunnels\r\n');
                            } else {
                                activeTunnels.forEach((t) => {
                                    stream.write(`  ${t.connectionId}:${t.remotePort} -> 127.0.0.1:${t.localPort}\r\n`);
                                });
                            }
                            break;
                        }
                        case 'share': {
                            if (!state.selectedId) {
                                state.statusMessage = 'Error: no connection selected';
                                break;
                            }
                            const permission = parts[1];
                            if (parts.length !== 2 || (permission !== 'ro' && permission !== 'rw')) {
                                state.statusMessage = 'Usage: share <ro|rw>';
                                break;
                            }
                            const token = createShare(state.selectedId, permission);
                            stream.write(`\r\nShare token (${permission === 'ro' ? 'read-only' : 'read-write'}): ${token}\r\n`);
                            state.statusMessage = 'Share token printed above';
                            break;
                        }
                        case 'alias': {
                            if (!state.selectedId) {
                                state.statusMessage = 'Error: no connection selected (press a number to select one first)';
                                break;
                            }
                            const connInfo = activeConnections.get(state.selectedId);
                            if (!connInfo) {
                                state.statusMessage = 'Error: selected connection no longer exists';
                                break;
                            }
                            const aliasArg = parts.slice(1).join(' ').replace(/[\x00-\x1f\x7f]/g, '');
                            if (!aliasArg) {
                                if (connInfo.alias) {
                                    state.statusMessage = `[-] Cleared alias "${connInfo.alias}" for ${state.selectedId}`;
                                    connInfo.alias = '';
                                    setAlias(connInfo.clientId, '');
                                } else {
                                    state.statusMessage = 'Usage: alias <name>  (set an alias for the selected connection)';
                                }
                            } else {
                                connInfo.alias = aliasArg;
                                setAlias(connInfo.clientId, aliasArg);
                                const note = connInfo.clientId ? '' : ' (in-memory only)';
                                state.statusMessage = `[+] Alias set: ${state.selectedId} -> ${aliasArg}${note}`;
                            }
                            break;
                        }
                        default:
                            if (parts[0]) state.statusMessage = `Unknown command: ${parts[0]}`;
                    }
                    state.drawBottomBar();
                };

                const showConnectionPanel = (id: string) => {
                    const info = activeConnections.get(id);
                    if (!info) {
                        state.statusMessage = 'Connection panel no longer exists';
                        state.commandMode = true;
                        state.drawBottomBar();
                        return;
                    }

                    state.selectedId = id;
                    state.settingsPanel = false;
                    state.commandMode = false;
                    state.commandInputMode = false;
                    state.commandInputBuffer = '';
                    state.statusMessage = '';
                    state.tmuxInterceptMode = false;
                    state.deleteConfirmMode = false;
                    if (state.rows && state.cols) {
                        info.terminal.resize(state.cols, state.rows - 1);
                        const buffer = info.terminal.buffer.active;
                        const cursorY = buffer.cursorY + 1;
                        const cursorX = buffer.cursorX + 1;
                        console.log('[-] Cursor position', cursorY, cursorX);
                        stream.write('\x1b[2J');
                        stream.write(`\x1b[1;${state.rows - 1}r`);
                        stream.write('\x1b[H');
                        stream.write(info.serializeAddon.serialize());
                        stream.write(`\x1b[${cursorY};${cursorX}H`);
                        info.resize(state.rows - 1, state.cols);
                    }
                    state.drawBottomBar();
                };

                const showConnectionPanelByNumber = (num: number) => {
                    const connection = Array.from(activeConnections.entries())[num - 1];
                    if (!connection) {
                        state.statusMessage = `Invalid connection panel: ${num}`;
                        state.drawBottomBar();
                        return;
                    }
                    showConnectionPanel(connection[0]);
                };

                const activatePanelAtColumn = (column: number) => {
                    const target = state.getPanelAtColumn(column);
                    if (!target) return;
                    if (target.type === 'settings') state.showSettingsPanel();
                    else showConnectionPanel(target.id);
                };

                stream.on('data', (data: Buffer) => {
                    let inputData = data;
                    let input = inputData.toString();
                    // New input clears the previous one-shot status message.
                    if (state.statusMessage) {
                        state.statusMessage = '';
                        state.drawBottomBar();
                    }

                    // SGR mouse reports: ESC [ < button ; column ; row M/m.
                    // Consume clicks on the protected status row and leave other mouse input
                    // untouched so a selected remote TUI can still receive it.
                    const mousePattern = /\x1b\[<(\d+);(\d+);(\d+)([Mm])/g;
                    let filteredInput = '';
                    let inputOffset = 0;
                    let consumedStatusMouse = false;
                    for (const match of input.matchAll(mousePattern)) {
                        filteredInput += input.slice(inputOffset, match.index);
                        inputOffset = match.index! + match[0].length;
                        const button = parseInt(match[1]);
                        const column = parseInt(match[2]);
                        const row = parseInt(match[3]);
                        const eventType = match[4];
                        if (state.rows && row === state.rows) {
                            consumedStatusMouse = true;
                            const isLeftPress = eventType === 'M'
                                && (button & 3) === 0
                                && (button & 32) === 0
                                && (button & 64) === 0;
                            if (isLeftPress) activatePanelAtColumn(column);
                        } else {
                            filteredInput += match[0];
                        }
                    }
                    if (consumedStatusMouse) {
                        filteredInput += input.slice(inputOffset);
                        if (!filteredInput) return;
                        input = filteredInput;
                        inputData = Buffer.from(filteredInput);
                    }

                    if (inputData[0] === 2) { // Ctrl+B
                        if (state.tmuxInterceptMode) {
                            // ctrl-b inside tmux intercept → enter admin command mode
                            state.tmuxInterceptMode = false;
                            state.commandMode = true;
                        } else if (!state.commandMode) {
                            const conn = state.selectedId ? activeConnections.get(state.selectedId) : null;
                            if (conn?.tmuxEnabled) {
                                state.tmuxInterceptMode = true;
                            } else {
                                state.commandMode = true;
                            }
                        } else if (state.selectedId) {
                            // ctrl-b in command mode with selected connection → enter delete confirm mode
                            state.deleteConfirmMode = true;
                        }
                        state.drawBottomBar();
                        return;
                    }
                    // Handle tmux intercept mode: next key after ctrl-b is a tmux command
                    if (state.tmuxInterceptMode) {
                        state.tmuxInterceptMode = false;
                        const conn = state.selectedId ? activeConnections.get(state.selectedId) : null;
                        if (conn) {
                            const char = input[0];
                            if (char >= '1' && char <= '9') {
                                if (writeSocketSafe(conn.socket, Buffer.from([2, char.charCodeAt(0)]))) {
                                    conn.tmuxCurrentWindow = parseInt(char);
                                }
                            } else if (char === 'c') {
                                if (writeSocketSafe(conn.socket, Buffer.from([2, 99]))) { // ctrl-b + c
                                    conn.tmuxWindowCount++;
                                    conn.tmuxCurrentWindow = conn.tmuxWindowCount;
                                }
                            } else if (char === 'd') {
                                closeAdminShell();
                                return;
                            } else {
                                // Forward ctrl-b + key for other tmux operations
                                writeSocketSafe(conn.socket, Buffer.from([2]));
                                writeSocketSafe(conn.socket, inputData);
                            }
                        }
                        state.drawBottomBar();
                        return;
                    }
                    if (state.commandInputMode) {
                        for (const char of input) {
                            if (char === '\r' || char === '\n') {
                                const cmd = state.commandInputBuffer;
                                state.commandInputMode = false;
                                state.commandInputBuffer = '';
                                executeAdminCommand(cmd);
                            } else if (char === '\x7f' || char === '\x08') {
                                if (state.commandInputBuffer.length > 0) {
                                    state.commandInputBuffer = state.commandInputBuffer.slice(0, -1);
                                    state.drawBottomBar();
                                }
                            } else if (char === '\x1b') {
                                state.commandInputMode = false;
                                state.commandInputBuffer = '';
                                state.drawBottomBar();
                            } else {
                                state.commandInputBuffer += char;
                                state.drawBottomBar();
                            }
                        }
                        return;
                    }
                    if (state.commandMode) {
                        const char = input[0];
                        if (state.deleteConfirmMode) {
                            state.deleteConfirmMode = false;
                            if (char === 'x' && state.selectedId) {
                                const connId = state.selectedId;
                                const connInfo = activeConnections.get(connId);
                                if (connInfo) {
                                    const label = connInfo.user && connInfo.os ? `${connInfo.user}@${connInfo.os}` : connId;
                                    // Destroy the socket and remove from active connections
                                    try { connInfo.socket.removeAllListeners(); connInfo.socket.destroy(); } catch {}
                                    activeConnections.delete(connId);
                                    revokeSharesForConnection(connId);
                                    resetGuestSessionsForConnection(connId);
                                    // Also clean up any tunnels for this connection
                                    for (const [, tunnel] of activeTunnels) {
                                        if (tunnel.connectionId === connId) {
                                            unregisterTunnel(connId, tunnel.remotePort);
                                        }
                                    }
                                    // Reset SSH state if viewing this connection
                                    state.selectedId = null;
                                    state.commandMode = true;
                                    stream.write(`\r\n[+] Deleted connection: ${label}\r\n`);
                                    state.drawBottomBar();
                                }
                            } else {
                                // Cancelled
                                stream.write('\r\nDelete cancelled\r\n');
                                state.drawBottomBar();
                            }
                            return;
                        }
                        if (char === 'q' || char === 'd') closeAdminShell();
                        else if (char === ':') {
                            state.commandInputMode = true;
                            state.commandInputBuffer = '';
                            state.drawBottomBar();
                        } else if (char === '0') {
                            state.showSettingsPanel();
                        } else if (char === 'c') {
                            if (state.selectedId) {
                                const conn = activeConnections.get(state.selectedId);
                                if (conn?.tmuxEnabled) {
                                    if (writeSocketSafe(conn.socket, Buffer.from([2, 99]))) { // ctrl-b + c
                                        conn.tmuxWindowCount++;
                                        conn.tmuxCurrentWindow = conn.tmuxWindowCount;
                                    }
                                    state.commandMode = false;
                                    state.drawBottomBar();
                                }
                            }
                        } else {
                            const num = parseInt(char);
                            if (!isNaN(num)) {
                                showConnectionPanelByNumber(num);
                            } else if (char === 'l') {
                                stream.write('\r\nActive connections:\r\n');
                                const conns = Array.from(activeConnections.entries());
                                conns.forEach(([id, info], idx) => {
                                    const num = idx + 1;
                                    const ident = `${info.user || 'unknown'}@${info.os || 'unknown'}`;
                                    const label = info.alias ? `${info.alias} | ${ident}` : ident;
                                    stream.write(`${num}: ${label} (${id})\r\n`);
                                });
                                stream.write('\r\n');
                            }
                        }
                    } else if (state.selectedId) {
                        const conn = activeConnections.get(state.selectedId);
                        if (conn) writeSocketSafe(conn.socket, inputData);
                    }
                });

                // 处理会话结束
                stream.on('close', () => {
                    state.stream = null;
                    state.selectedId = null;
                    state.settingsPanel = false;
                    console.log('[-] Admin shell session closed');
                });
                stream.on('error', () => { try { stream.destroy(); } catch {} });
            });
        });
    });

    client.on('end', () => {
        activeSSHConnections.delete(client);
        console.log(`[-] Admin connection closed from ${clientInfo}`);
    });

    client.on('error', (err) => {
        activeSSHConnections.delete(client);
        console.error(`[-] Admin connection error: ${err.message}`);
    })
});

// 启动SSH服务器
sshServer.listen(SSH_PORT, '0.0.0.0', () => {
    console.log(`[*] SSH management server listening on port ${SSH_PORT}`);
    console.log('[*] Waiting for admin connections...');
    if (fs.existsSync(publicKeyPath)) {
        console.log(`[*] Public key for admin connection: ${fs.readFileSync(publicKeyPath, 'utf8')}`);
    }
});
