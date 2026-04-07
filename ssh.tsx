import { timingSafeEqual } from 'crypto';
import { Server, utils, ParsedKey } from 'ssh2';
import * as fs from 'fs';
import * as path from 'path';
import { homedir } from 'os';
import { activeConnections, activeSSHConnections, SSHConnection } from './state';
import { activeTunnels, findAvailablePort, registerTunnel, unregisterTunnel } from './tunnel';

const SSH_PORT = 13336;

const dotssh = path.join(homedir(), '.ssh');
if (!fs.existsSync(dotssh)) fs.mkdirSync(dotssh);

const privateKeyPath = path.join(dotssh, 'id_rsa');
const publicKeyPath = path.join(dotssh, 'id_rsa.pub');
const authorizedKeysPath = path.join(dotssh, 'authorized_keys');

if (!fs.existsSync(privateKeyPath)) {
    const { execSync } = require('child_process');
    execSync(`ssh-keygen -t rsa -b 4096 -f ${privateKeyPath} -N ""`);
}

const authorizedKeys = fs.existsSync(authorizedKeysPath) ? fs.readFileSync(authorizedKeysPath, 'utf-8').split('\n').filter(i => i.trim()) : [];
const allowedPubKeys = authorizedKeys.map(i => utils.parseKey(i + '\n')).filter(i => i && !(i instanceof Error)) as ParsedKey[];
console.log(allowedPubKeys.length + ' keys loaded');

const eq = (a: Buffer, b: Buffer) => {
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
}

const sshServer = new Server({
    hostKeys: [fs.readFileSync(privateKeyPath)],
}, (client) => {
    const clientInfo = `SSH client`;
    console.log(`[+] New admin connection from ${clientInfo}`);

    const state = new SSHConnection(null);
    activeSSHConnections.set(client, state);

    client.on('authentication', (ctx) => {
        if (!eq(Buffer.from(ctx.username), Buffer.from('user')))
            return ctx.reject();
        switch (ctx.method) {
            case 'password':
                return ctx.reject();
            case 'publickey':
                for (const allowedPubKey of allowedPubKeys) {
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
                if (state.selectedId) {
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
                console.log('[*] Admin shell session started');

                // 清屏并设置初始状态
                stream.write('\x1b[2J\x1b[H');
                stream.write('Command mode - Press number to switch tab, l to list, q to quit\r\n');
                stream.write('\x1b[r'); // Initial full scroll region for command mode
                state.drawBottomBar();

                const executeAdminCommand = (cmd: string) => {
                    const parts = cmd.trim().split(/\s+/);
                    switch (parts[0]) {
                        case 'fwd': {
                            if (!state.selectedId) {
                                stream.write('Error: no connection selected\r\n');
                                break;
                            }
                            const expose = parts.includes('--expose');
                            const fwdArgs = parts.slice(1).filter(p => p !== '--expose');
                            const remotePort = parseInt(fwdArgs[0]);
                            if (isNaN(remotePort) || remotePort < 1 || remotePort > 65535) {
                                stream.write('Usage: fwd <remotePort> [localPort] [--expose]\r\n');
                                break;
                            }
                            const rawLocal = parseInt(fwdArgs[1]);
                            const isManual = !isNaN(rawLocal);
                            const connId = state.selectedId;
                            const bindAddr = expose ? '0.0.0.0' : '127.0.0.1';
                            if (isManual) {
                                if (rawLocal < 1 || rawLocal > 65535) {
                                    stream.write('Error: local port must be between 1 and 65535\r\n');
                                    break;
                                }
                                registerTunnel(connId, remotePort, rawLocal, expose)
                                    .then(() => {
                                        stream.write(`[+] Tunnel: ${bindAddr}:${rawLocal} -> target:${remotePort}\r\n`);
                                        state.drawBottomBar();
                                    })
                                    .catch((e: Error) => {
                                        stream.write(`[-] Failed: ${e.message}\r\n`);
                                        state.drawBottomBar();
                                    });
                            } else {
                                findAvailablePort(10000 + remotePort)
                                    .then((localPort) =>
                                        registerTunnel(connId, remotePort, localPort, expose).then(() => localPort),
                                    )
                                    .then((localPort) => {
                                        stream.write(`[+] Tunnel: ${bindAddr}:${localPort} -> target:${remotePort}\r\n`);
                                        state.drawBottomBar();
                                    })
                                    .catch((e: Error) => {
                                        stream.write(`[-] Failed: ${e.message}\r\n`);
                                        state.drawBottomBar();
                                    });
                            }
                            break;
                        }
                        case 'unfwd': {
                            if (!state.selectedId) {
                                stream.write('Error: no connection selected\r\n');
                                break;
                            }
                            const remotePort = parseInt(parts[1]);
                            if (isNaN(remotePort)) {
                                stream.write('Usage: unfwd <remotePort>\r\n');
                                break;
                            }
                            unregisterTunnel(state.selectedId, remotePort);
                            stream.write(`[-] Tunnel removed: target:${remotePort}\r\n`);
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
                        default:
                            if (parts[0]) stream.write(`Unknown command: ${parts[0]}\r\n`);
                    }
                    state.drawBottomBar();
                };

                stream.on('data', (data: Buffer) => {
                    const input = data.toString();
                    if (data[0] === 2) { // Ctrl+B
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
                            state.commandMode = false;
                            const conn = activeConnections.get(state.selectedId);
                            if (!conn?.tmuxEnabled) {
                                activeConnections.get(state.selectedId)?.socket.write(data);
                            }
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
                                conn.socket.write(Buffer.from([2, char.charCodeAt(0)]));
                                conn.tmuxCurrentWindow = parseInt(char);
                            } else if (char === 'c') {
                                conn.socket.write(Buffer.from([2, 99])); // ctrl-b + c
                                conn.tmuxWindowCount++;
                                conn.tmuxCurrentWindow = conn.tmuxWindowCount;
                            } else if (char === 'd') {
                                stream.end();
                                return;
                            } else {
                                // Forward ctrl-b + key for other tmux operations
                                conn.socket.write(Buffer.from([2]));
                                conn.socket.write(data);
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
                                stream.write('\r\n');
                                executeAdminCommand(cmd);
                            } else if (char === '\x7f' || char === '\x08') {
                                if (state.commandInputBuffer.length > 0) {
                                    state.commandInputBuffer = state.commandInputBuffer.slice(0, -1);
                                    stream.write('\x08 \x08');
                                }
                            } else if (char === '\x1b') {
                                state.commandInputMode = false;
                                state.commandInputBuffer = '';
                                stream.write('\r\n');
                                state.drawBottomBar();
                            } else {
                                state.commandInputBuffer += char;
                                stream.write(char);
                            }
                        }
                        return;
                    }
                    if (state.commandMode) {
                        const char = input[0];
                        if (char === 'q' || char === 'd') stream.end();
                        else if (char === ':') {
                            state.commandInputMode = true;
                            state.commandInputBuffer = '';
                            stream.write('\r\n:');
                        } else if (char === 'c') {
                            if (state.selectedId) {
                                const conn = activeConnections.get(state.selectedId);
                                if (conn?.tmuxEnabled) {
                                    conn.socket.write(Buffer.from([2, 99])); // ctrl-b + c
                                    conn.tmuxWindowCount++;
                                    conn.tmuxCurrentWindow = conn.tmuxWindowCount;
                                    state.commandMode = false;
                                    state.drawBottomBar();
                                }
                            }
                        } else {
                            const num = parseInt(char);
                            if (!isNaN(num)) {
                                const connections = Array.from(activeConnections.entries());
                                if (num > 0 && num <= connections.length) {
                                    const [id, info] = connections[num - 1];
                                    state.selectedId = id;
                                    state.commandMode = false;
                                    if (state.rows && state.cols) {
                                        info.terminal.resize(state.cols, state.rows - 1);
                                        // Get cursor position before clearing
                                        const buffer = info.terminal.buffer.active;
                                        const cursorY = buffer.cursorY + 1; // 1-based
                                        const cursorX = buffer.cursorX + 1; // 1-based
                                        console.log('[-] Cursor position', cursorY, cursorX);
                                        // Clear screen and set scroll region first
                                        stream.write('\x1b[2J'); // Clear screen
                                        stream.write(`\x1b[1;${state.rows - 1}r`); // Set scroll region to protect bottom line
                                        stream.write('\x1b[H'); // Move cursor to home
                                        // Write serialized content (remove cursor position from it if present)
                                        const serialized = info.serializeAddon.serialize();
                                        // Remove cursor position ANSI codes from serialized content
                                        // const cleanedSerialized = serialized.replace(/\x1b\[\d+;\d+[Hf]/g, '');
                                        stream.write(serialized);
                                        // Restore cursor position after everything
                                        stream.write(`\x1b[${cursorY};${cursorX}H`);
                                        info.resize(state.rows - 1, state.cols);
                                    }
                                    state.drawBottomBar();
                                } else {
                                    stream.write('\r\nInvalid connection number\r\n');
                                }
                            } else if (char === 'l') {
                                stream.write('\r\nActive connections:\r\n');
                                const conns = Array.from(activeConnections.entries());
                                conns.forEach(([id, info], idx) => {
                                    const num = idx + 1;
                                    stream.write(`${num}: ${info.user || 'unknown'}@${info.os || 'unknown'} (${id})\r\n`);
                                });
                                stream.write('\r\n');
                            }
                        }
                    } else if (state.selectedId) {
                        activeConnections.get(state.selectedId)?.socket.write(data);
                    }
                });

                // 处理会话结束
                stream.on('close', () => {
                    state.stream = null;
                    state.selectedId = null;
                    console.log('[-] Admin shell session closed');
                });
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
    console.log(`[*] Public key for admin connection: ${fs.readFileSync(publicKeyPath, 'utf8')}`);
});
