import { Socket } from 'net';
import { Connection } from 'ssh2';
import { Terminal } from '@xterm/headless';
import { SerializeAddon } from '@xterm/addon-serialize';
import { networkInterfaces } from 'os';
import { get } from 'https';

const PRIVATE_RE = [
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./,
    /^127\./,
];

function getPublicIpFromWeb(): Promise<string> {
    return new Promise((resolve, reject) => {
        const req = get('https://ip.sb', { headers: { 'User-Agent': 'curl/8.0' } }, (res) => {
            let data = '';
            res.on('data', (chunk: Buffer) => { data += chunk; });
            res.on('end', () => resolve(data.trim()));
        });
        req.on('error', reject);
        req.setTimeout(5000, () => { req.destroy(); reject(new Error('timeout')); });
    });
}

async function resolveServerIp(): Promise<string> {
    if (process.env.SERVER_PUBLIC_IP) return process.env.SERVER_PUBLIC_IP;

    const ifaces = networkInterfaces();
    for (const name in ifaces) {
        for (const iface of ifaces[name] ?? []) {
            if (iface.internal || iface.family !== 'IPv4') continue;
            if (!PRIVATE_RE.some(r => r.test(iface.address))) return iface.address;
        }
    }

    try { return await getPublicIpFromWeb(); } catch {}
    return '127.0.0.1';
}

export let serverIp = '127.0.0.1';
export const serverIpReady = resolveServerIp().then(ip => {
    serverIp = ip;
    console.log(`[*] Server IP: ${serverIp}`);
});


const visibleLength = (str: string): number => {
    return str.replace(/\x1b\[[0-9;]*m/g, '').length;
};

export class SSHConnection {
    selectedId: string | null = null;
    commandMode: boolean = true;
    commandInputMode: boolean = false;
    commandInputBuffer: string = '';
    tmuxInterceptMode: boolean = false;
    rows?: number;
    cols?: number;
    constructor(public stream: any) { }

    drawBottomBar() {
        if (!this.rows || !this.cols || !this.stream) return;
        let status: string;
        if (this.tmuxInterceptMode) {
            status = '[Tmux >_]';
        } else if (this.commandMode) {
            status = '[Command Mode]';
        } else if (this.selectedId) {
            const info = activeConnections.get(this.selectedId);
            const label = info && info.user && info.os ? `${info.user}@${info.os}` : this.selectedId || 'None';
            status = `[Connected: ${label}]`;
        } else {
            status = '[No Connection]';
        }

        // Build tab string with bold for active, tmux-aware format
        let tabContent = '';
        let index = 1;
        activeConnections.forEach((info, id) => {
            const isActive = id === this.selectedId;
            const label = info.user && info.os ? `${info.user}@${info.os}` : id;
            const dcTag = info.disconnected ? ' [DC]' : '';
            let prefix: string;
            if (info.tmuxEnabled) {
                prefix = isActive
                    ? `[<${info.tmuxCurrentWindow}>,${info.tmuxWindowCount}]`
                    : `[${index}]`;
            } else {
                prefix = `${index}`;
            }
            tabContent += (isActive ? '\x1b[1m' : '') + ` ${prefix}:${label}${dcTag} ` + (isActive ? '\x1b[22m' : '');
            index++;
        });

        // Truncate tabs if too long
        const statusVisLength = visibleLength(status);
        const minStatusSpace = statusVisLength + 2;
        const availableForTabs = this.cols - minStatusSpace;
        let tabVisLength = visibleLength(tabContent);
        if (tabVisLength > availableForTabs) {
            // Truncate approximately; for simplicity, slice string and adjust
            tabContent = tabContent.slice(0, Math.floor(tabContent.length * (availableForTabs - 3) / tabVisLength)) + '...';
            tabVisLength = visibleLength(tabContent);
        }

        // Calculate visible padding to right-align status: total visible space between tabs and status
        const paddingVisLength = this.cols - tabVisLength - statusVisLength;
        const padding = ' '.repeat(Math.max(0, paddingVisLength));

        // Full line: set color bg based on mode (42=green commandMode, 43=yellow tmuxIntercept, 44=blue passthrough)
        const bgColor = this.commandMode ? '42' : (this.tmuxInterceptMode ? '43' : '44');
        const fullLine = `\x1b[${bgColor};37m` + tabContent + padding + status + '\x1b[0m';

        // Since padding is visible spaces, and all in the same background color, it should fill
        this.stream.write('\x1b[s');
        this.stream.write(`\x1b[${this.rows};0H`);
        this.stream.write('\x1b[2K');
        this.stream.write(fullLine);
        this.stream.write('\x1b[u');
    }
}

export class ConnectionInfo {
    socket: Socket;
    user: string;
    os: string;
    terminal: Terminal;
    serializeAddon: SerializeAddon;
    rows = 24;
    cols = 80;
    tmuxEnabled: boolean = false;
    tmuxCurrentWindow: number = 1;
    tmuxWindowCount: number = 1;
    disconnected: boolean = false;
    disconnectedAt: number = 0;
    collectingInfo: boolean = false;

    constructor(socket: Socket, user: string, os: string) {
        this.socket = socket;
        this.user = user;
        this.os = os;
        this.terminal = new Terminal({ rows: 24, cols: 80, allowProposedApi: true });
        this.serializeAddon = new SerializeAddon();
        this.terminal.loadAddon(this.serializeAddon);
    }

    resize(rows: number, cols: number) {
        this.terminal.resize(cols, rows);
        this.rows = rows;
        this.cols = cols;
        this.socket.write(`\x1b[8;${rows};${cols}t`);
    }
}

export const activeConnections = new Map<string, ConnectionInfo>();
export const activeSSHConnections = new Map<Connection, SSHConnection>();