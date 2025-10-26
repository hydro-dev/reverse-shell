import { timingSafeEqual } from 'crypto';
import { Server, utils, ParsedKey } from 'ssh2';
import * as fs from 'fs';
import * as path from 'path';
import { homedir } from 'os';
import { activeConnections, activeSSHConnections, SSHConnection } from './state';

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
                    activeConnections.get(state.selectedId)?.socket.write(`\x1b[8;${info.rows - 1};${info.cols}t`);
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

                // 切换到命令模式
                const switchToCommandMode = () => {
                    if (!state.selectedId) return;
                    state.selectedId = null;
                    state.commandMode = true;
                    stream.write('\r\nCommand mode - Press number to switch tab, l to list, q to quit\r\n');
                    stream.write('\x1b[r'); // Reset scroll region to full screen
                    state.drawBottomBar();
                };

                // 通过数字选择连接
                const selectConnectionByNumber = (num: number) => {
                    const connections = Array.from(activeConnections.entries());
                    if (num > 0 && num <= connections.length) {
                        const [id, info] = connections[num - 1];
                        state.selectedId = id;
                        stream.write(`\r\nSelected connection: ${info.user || 'unknown'}@${info.os || 'unknown'} (${id})\r\n`);
                        if (state.rows && state.cols) {
                            info.socket.write(`\x1b[8;${state.rows - 1};${state.cols}t`);
                            stream.write(`\x1b[1;${state.rows - 1}r`); // Set scroll region to protect bottom line
                        }
                        state.drawBottomBar();
                    } else {
                        stream.write('\r\nInvalid connection number\r\n');
                    }
                };

                // 清屏并设置初始状态
                stream.write('\x1b[2J\x1b[H');
                stream.write('Command mode - Press number to switch tab, l to list, q to quit\r\n');
                stream.write('\x1b[r'); // Initial full scroll region for command mode
                state.drawBottomBar();

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
                            state.drawBottomBar();
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
