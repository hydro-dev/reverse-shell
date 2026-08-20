import { Socket } from 'net';
import { Connection } from 'ssh2';
import { Terminal } from '@xterm/headless';
import { SerializeAddon } from '@xterm/addon-serialize';
import { networkInterfaces, homedir } from 'os';
import { get } from 'https';
import fs from 'fs';
import path from 'path';
import type { SharePermission } from './share';

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
            res.on('error', reject);
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


// Persistent aliases keyed by stable client id (client.py derives it from /etc/machine-id).
const aliasesPath = path.join(homedir(), '.ssh', 'aliases.json');
export const aliasesByClientId = new Map<string, string>();

export function loadAliases() {
    try {
        const obj = JSON.parse(fs.readFileSync(aliasesPath, 'utf-8'));
        if (obj && typeof obj === 'object') {
            for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
                if (typeof v === 'string' && v) aliasesByClientId.set(k, v);
            }
        }
        console.log(`[*] Loaded ${aliasesByClientId.size} alias(es) from ${aliasesPath}`);
    } catch (e: any) {
        if (e?.code !== 'ENOENT') console.error(`[!] Failed to load aliases: ${e.message}`);
    }
}

export function setAlias(clientId: string, alias: string) {
    if (!clientId) return;
    if (alias) aliasesByClientId.set(clientId, alias);
    else aliasesByClientId.delete(clientId);
    try {
        const obj: Record<string, string> = {};
        for (const [k, v] of aliasesByClientId) obj[k] = v;
        fs.writeFileSync(aliasesPath, JSON.stringify(obj, null, 2));
    } catch (e: any) {
        console.error(`[!] Failed to save aliases: ${e.message}`);
    }
}

loadAliases();

const visibleLength = (str: string): number => {
    return str.replace(/\x1b\[[0-9;]*m/g, '').length;
};

export type PanelTarget =
    | { type: 'settings' }
    | { type: 'connection'; id: string };

type PanelHitArea = {
    startColumn: number;
    endColumn: number;
    target: PanelTarget;
};

export class SSHConnection {
    selectedId: string | null = null;
    settingsPanel: boolean = false;
    commandMode: boolean = true;
    commandInputMode: boolean = false;
    commandInputBuffer: string = '';
    statusMessage: string = '';
    tmuxInterceptMode: boolean = false;
    deleteConfirmMode: boolean = false;
    rows?: number;
    cols?: number;
    isGuest: boolean = false;
    guestConnectionId: string | null = null;
    guestPermission: SharePermission | null = null;
    guestTokenInput: string = '';
    guestTokenError: string = '';
    private panelHitAreas: PanelHitArea[] = [];
    constructor(public stream: any) { }

    renderGuestTokenPrompt() {
        if (!this.stream) return;
        const width = Math.max(20, Math.min(60, (this.cols ?? 80) - 2));
        const innerWidth = width - 2;
        const valueWidth = Math.max(1, innerWidth - ' Share token: '.length);
        const token = '*'.repeat(Math.min(this.guestTokenInput.length, valueWidth));
        const fit = (text: string) => text.slice(0, innerWidth).padEnd(innerWidth);
        const border = `+${'-'.repeat(innerWidth)}+`;
        this.stream.write('\x1b[2J\x1b[H\x1b[r');
        this.stream.write(`${border}\r\n`);
        this.stream.write(`|${fit(' Share token: ' + token)}|\r\n`);
        this.stream.write(`${border}\r\n`);
        if (this.guestTokenError) this.stream.write(`${this.guestTokenError}\r\n`);
    }

    renderSharedTerminal(info: ConnectionInfo) {
        if (!this.stream || !this.rows) return;
        const contentRows = Math.max(1, this.rows - 1);
        const buffer = info.terminal.buffer.active;
        this.stream.write('\x1b[2J\x1b[H');
        this.stream.write(`\x1b[1;${contentRows}r`);
        this.stream.write(info.serializeAddon.serialize());
        this.stream.write(`\x1b[${buffer.cursorY + 1};${buffer.cursorX + 1}H`);
        this.drawBottomBar();
    }

    resetGuestShare() {
        if (!this.isGuest) return;
        this.guestConnectionId = null;
        this.guestPermission = null;
        this.guestTokenInput = '';
        this.guestTokenError = '';
        this.renderGuestTokenPrompt();
    }

    getPanelAtColumn(column: number): PanelTarget | null {
        return this.panelHitAreas.find((area) => (
            column >= area.startColumn && column <= area.endColumn
        ))?.target ?? null;
    }

    showSettingsPanel() {
        this.selectedId = null;
        this.settingsPanel = true;
        this.commandMode = true;
        this.commandInputMode = false;
        this.commandInputBuffer = '';
        this.statusMessage = '';
        this.tmuxInterceptMode = false;
        this.deleteConfirmMode = false;
        this.renderSettingsPanel();
        this.drawBottomBar();
    }

    renderSettingsPanel() {
        if (!this.rows || !this.cols || !this.stream) return;

        const contentRows = Math.max(1, this.rows - 1);
        const panelWidth = Math.max(4, Math.min(72, this.cols - 2));
        const innerWidth = panelWidth - 2;
        const fit = (text: string) => text.slice(0, innerWidth).padEnd(innerWidth);
        const center = (text: string) => {
            if (text.length >= innerWidth) return text.slice(0, innerWidth);
            const left = Math.floor((innerWidth - text.length) / 2);
            return ' '.repeat(left) + text + ' '.repeat(innerWidth - text.length - left);
        };
        const border = `+${'-'.repeat(innerWidth)}+`;
        const lines = [
            border,
            `|${center('Settings')}|`,
            `|${fit('')}|`,
            `|${fit(' Reserved for future settings.')}|`,
            `|${fit(' No settings are available yet.')}|`,
            `|${fit('')}|`,
            `|${fit(' Controls')}|`,
            `|${fit('   Mouse Click a status bar tab')}|`,
            `|${fit('   0     Open this settings panel')}|`,
            `|${fit('   1-9   Switch to a connection panel')}|`,
            `|${fit('   :     Open the command prompt')}|`,
            border,
        ];
        const topRow = Math.max(1, Math.floor((contentRows - lines.length) / 2) + 1);
        const leftCol = Math.max(1, Math.floor((this.cols - panelWidth) / 2) + 1);

        this.stream.write('\x1b[2J');
        this.stream.write(`\x1b[1;${contentRows}r`);
        lines.forEach((line, index) => {
            const row = topRow + index;
            if (row <= contentRows) this.stream.write(`\x1b[${row};${leftCol}H${line}`);
        });
        this.stream.write('\x1b[H');
    }

    drawBottomBar() {
        if (!this.rows || !this.cols || !this.stream) return;
        this.panelHitAreas = [];

        if (this.isGuest) {
            if (!this.guestConnectionId || !this.guestPermission) return;
            this.writeStatusBar(`Shared terminal: ${this.guestPermission === 'ro' ? 'read-only' : 'read-write'}`, '44');
            return;
        }

        // Command line input takes over the bottom bar (vim-like): no echo into the content area.
        if (this.commandInputMode) {
            this.writeStatusBar(': ' + this.commandInputBuffer, '42');
            return;
        }

        let status: string;
        if (this.tmuxInterceptMode) {
            status = '[Tmux >_]';
        } else if (this.deleteConfirmMode) {
            status = '[Delete? x=confirm]';
        } else if (this.settingsPanel) {
            status = '[Settings]';
        } else if (this.commandMode) {
            status = '[Command Mode]';
        } else if (this.selectedId) {
            const info = activeConnections.get(this.selectedId);
            const label = info?.alias || (info && info.user && info.os ? `${info.user}@${info.os}` : this.selectedId) || 'None';
            status = `[Connected: ${label}]`;
        } else {
            status = '[No Connection]';
        }

        // One-shot command result replaces the bottom bar so the main content stays clean.
        if (this.statusMessage) {
            this.writeStatusBar(this.statusMessage, '42');
            return;
        }

        const tabs: Array<{ text: string; active: boolean; target: PanelTarget }> = [{
            text: ' 0:Settings ',
            active: this.settingsPanel,
            target: { type: 'settings' },
        }];
        let index = 1;
        activeConnections.forEach((info, id) => {
            const isActive = id === this.selectedId;
            const label = info.alias || (info.user && info.os ? `${info.user}@${info.os}` : id);
            const dcTag = info.disconnected ? ' [DC]' : '';
            const prefix = info.tmuxEnabled
                ? (isActive ? `[<${info.tmuxCurrentWindow}>,${info.tmuxWindowCount}]` : `[${index}]`)
                : `${index}`;
            tabs.push({
                text: ` ${prefix}:${label}${dcTag} `,
                active: isActive,
                target: { type: 'connection', id },
            });
            index++;
        });

        const statusVisLength = visibleLength(status);
        const availableForTabs = Math.max(0, this.cols - statusVisLength - 2);
        let tabContent = '';
        let tabVisLength = 0;
        for (const tab of tabs) {
            const remaining = availableForTabs - tabVisLength;
            if (remaining <= 0) break;

            const isTruncated = tab.text.length > remaining;
            const visibleText = isTruncated
                ? (remaining > 3 ? tab.text.slice(0, remaining - 3) + '...' : tab.text.slice(0, remaining))
                : tab.text;
            if (!visibleText) break;

            const startColumn = tabVisLength + 1;
            tabVisLength += visibleText.length;
            this.panelHitAreas.push({
                startColumn,
                endColumn: tabVisLength,
                target: tab.target,
            });
            tabContent += (tab.active ? '\x1b[1m' : '') + visibleText + (tab.active ? '\x1b[22m' : '');
            if (isTruncated) break;
        }

        // Calculate visible padding to right-align status: total visible space between tabs and status
        const paddingVisLength = this.cols - tabVisLength - statusVisLength;
        const padding = ' '.repeat(Math.max(0, paddingVisLength));

        // Full line: set color bg based on mode (41=red deleteConfirm, 42=green commandMode, 43=yellow tmuxIntercept, 44=blue passthrough)
        const bgColor = this.deleteConfirmMode ? '41' : (this.commandMode ? '42' : (this.tmuxInterceptMode ? '43' : '44'));
        const fullLine = `\x1b[${bgColor};37m` + tabContent + padding + status + '\x1b[0m';
        this.writeRawStatusBar(fullLine);
    }

    // Paint a full bottom-bar line (save/restore cursor, clear the line).
    private writeRawStatusBar(fullLine: string) {
        // Enable basic click tracking with SGR coordinates for terminals wider than 223 columns.
        this.stream.write('\x1b[?1000h\x1b[?1006h');
        this.stream.write('\x1b[s');
        this.stream.write(`\x1b[${this.rows};0H`);
        this.stream.write('\x1b[2K');
        this.stream.write(fullLine);
        this.stream.write('\x1b[u');
    }

    // Paint plain text on the bottom bar with a solid background, truncating to cols.
    private writeStatusBar(text: string, bgColor: string) {
        const max = this.cols!;
        let line = text;
        const visLen = visibleLength(line);
        if (visLen > max) {
            // Truncate approximately; for simplicity, slice string and adjust
            line = line.slice(0, Math.floor(line.length * (max - 3) / visLen)) + '...';
        }
        const pad = ' '.repeat(Math.max(0, max - visibleLength(line)));
        this.writeRawStatusBar(`\x1b[${bgColor};37m${line}${pad}\x1b[0m`);
    }
}

export const writeSocketSafe = (socket: Socket, data: string | Buffer): boolean => {
    if (socket.destroyed || !socket.writable || socket.writableEnded) return false;
    try {
        return socket.write(data);
    } catch {
        try { socket.destroy(); } catch { }
        return false;
    }
};

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
    alias: string = '';
    clientId: string = '';

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
        writeSocketSafe(this.socket, `\x1b[8;${rows};${cols}t`);
    }
}

export const activeConnections = new Map<string, ConnectionInfo>();
export const activeSSHConnections = new Map<Connection, SSHConnection>();

export const resetGuestSessionsForConnection = (connectionId: string) => {
    activeSSHConnections.forEach((sshState) => {
        if (sshState.guestConnectionId === connectionId) sshState.resetGuestShare();
    });
};