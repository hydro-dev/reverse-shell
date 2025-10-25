import { Socket } from 'net';
import { Connection } from 'ssh2';


const visibleLength = (str: string): number => {
    return str.replace(/\x1b\[[0-9;]*m/g, '').length;
};

export class SSHConnection {
    selectedId: string | null = null;
    commandMode: boolean = true;
    rows?: number;
    cols?: number;
    constructor(public stream: any) { }

    drawBottomBar() {
        if (!this.rows || !this.cols || !this.stream) return;
        const status = this.selectedId
            ? (() => {
                const info = activeConnections.get(this.selectedId);
                const label = info && info.user && info.os ? `${info.user}@${info.os}` : this.selectedId || 'None';
                return `[Connected to: ${label}]`;
            })()
            : '[Command Mode]';

        // Build tab string with bold for active
        let tabContent = '';
        let index = 1;
        activeConnections.forEach((info, id) => {
            const isActive = id === this.selectedId;
            const label = info.user && info.os ? `${info.user}@${info.os}` : id;
            tabContent += (isActive ? '\x1b[1m' : '') + ` ${index}:${label} ` + (isActive ? '\x1b[22m' : '');
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
        const padding = ' '.repeat(paddingVisLength);

        // Full line: set blue bg, write tabs, padding, status, reset
        const fullLine = '\x1b[44;37m' + tabContent + padding + status + '\x1b[0m';

        // Since padding is visible spaces, and all in blue, it should fill
        this.stream.write('\x1b[s');
        this.stream.write(`\x1b[${this.rows};0H`);
        this.stream.write('\x1b[2K');
        this.stream.write(fullLine);
        this.stream.write('\x1b[u');
    }
}

export interface ConnectionInfo {
    socket: Socket;
    user: string;
    os: string;
}

export const activeConnections = new Map<string, ConnectionInfo>();
export const activeSSHConnections = new Map<Connection, SSHConnection>();