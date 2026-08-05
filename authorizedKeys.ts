import fs from 'fs';
import type { Stats } from 'fs';
import { ParsedKey, utils } from 'ssh2';

export class AuthorizedKeysStore {
    private keys: ParsedKey[] = [];
    private reloadTimer: NodeJS.Timeout | null = null;
    private watching = false;

    constructor(
        public readonly filePath: string,
        private readonly watchInterval = 500,
    ) { }

    get current(): readonly ParsedKey[] {
        return this.keys;
    }

    reload(initial = false): number {
        let content = '';
        try {
            content = fs.readFileSync(this.filePath, 'utf-8');
        } catch (e: any) {
            if (e?.code !== 'ENOENT') {
                console.error(`[!] Failed to reload authorized keys from ${this.filePath}: ${e.message}`);
                return this.keys.length;
            }
        }

        const nextKeys: ParsedKey[] = [];
        let invalidCount = 0;
        for (const line of content.split(/\r?\n/)) {
            const keyText = line.trim();
            if (!keyText || keyText.startsWith('#')) continue;
            const parsed = utils.parseKey(keyText);
            if (parsed instanceof Error) {
                invalidCount++;
                continue;
            }
            nextKeys.push(parsed);
        }

        this.keys = nextKeys;
        const action = initial ? 'Loaded' : 'Reloaded';
        console.log(`[*] ${action} ${nextKeys.length} authorized key(s) from ${this.filePath}`);
        if (invalidCount > 0) {
            console.error(`[!] Ignored ${invalidCount} invalid authorized key line(s)`);
        }
        return nextKeys.length;
    }

    startWatching() {
        if (this.watching) return;
        this.watching = true;
        this.reload(true);
        fs.watchFile(this.filePath, { interval: this.watchInterval }, this.handleFileChange);
    }

    stopWatching() {
        if (!this.watching) return;
        this.watching = false;
        if (this.reloadTimer) {
            clearTimeout(this.reloadTimer);
            this.reloadTimer = null;
        }
        fs.unwatchFile(this.filePath, this.handleFileChange);
    }

    private handleFileChange = (current: Stats, previous: Stats) => {
        const changed = current.mtimeMs !== previous.mtimeMs
            || current.ctimeMs !== previous.ctimeMs
            || current.size !== previous.size
            || current.ino !== previous.ino
            || current.nlink !== previous.nlink;
        if (!changed) return;

        if (this.reloadTimer) clearTimeout(this.reloadTimer);
        this.reloadTimer = setTimeout(() => {
            this.reloadTimer = null;
            this.reload();
        }, 100);
    };
}
