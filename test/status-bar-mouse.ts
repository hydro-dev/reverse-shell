import assert from 'node:assert/strict';
import { Terminal } from '@xterm/headless';
import { SSHConnection } from '../state';

async function main() {
    const terminal = new Terminal();
    const mouseService = (terminal as any)._core.coreMouseService;

    await new Promise<void>((resolve) => terminal.write('\x1b[?1006h\x1b[?1002h', resolve));
    assert.deepEqual(
        [mouseService._activeProtocol, mouseService._activeEncoding],
        ['DRAG', 'SGR'],
    );

    const writes: string[] = [];
    const state = new SSHConnection({ write: (data: string) => writes.push(data) });
    state.rows = 24;
    state.cols = 80;
    state.drawBottomBar();

    assert.ok(writes.includes('\x1b[?1002h\x1b[?1006h'));
    assert.ok(!writes.some((data) => data.includes('\x1b[?1000h')));

    for (const data of writes) {
        await new Promise<void>((resolve) => terminal.write(data, resolve));
    }
    assert.deepEqual(
        [mouseService._activeProtocol, mouseService._activeEncoding],
        ['DRAG', 'SGR'],
    );
}

main().then(
    () => process.exit(0),
    (err) => { console.error(err); process.exit(1); },
);
