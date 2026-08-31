// The Xfuzz Frida agent: block coverage from Stalker, written as DRcov.
//
// Stalker rewrites the target's code as it runs and can report every basic
// block it compiles. That is what makes Frida the one backend at this tier that
// works on a stripped binary on all three platforms, and the one that works
// against a program already running rather than one the fuzzer starts.
//
// The `compile` event, not `exec`. A compile event fires the first time Stalker
// translates a block, which is once per block per process; an exec event fires
// every time the block runs, which for a loop is millions of times and would
// spend the whole execution formatting events. This is the same trade the
// ptrace backend makes with one-shot breakpoints, for the same reason, and it
// loses the same thing: which blocks ran, not how often, and not in what order.
//
// The output is DRcov because every tool that draws coverage reads DRcov, so
// what a campaign collects can also be opened in a disassembler.

'use strict';

const OUTPUT = '__XFUZZ_OUTPUT__';

const blocks = [];
const modules = [];

function moduleIndex(address) {
    for (let i = 0; i < modules.length; i++) {
        if (address.compare(modules[i].base) >= 0 && address.compare(modules[i].end) < 0) {
            return i;
        }
    }
    return -1;
}

function collectModules() {
    Process.enumerateModules().forEach(function (m) {
        modules.push({
            base: m.base,
            end: m.base.add(m.size),
            path: m.path || m.name,
        });
    });
}

function u32(v) {
    const b = new Uint8Array(4);
    b[0] = v & 0xff; b[1] = (v >>> 8) & 0xff; b[2] = (v >>> 16) & 0xff; b[3] = (v >>> 24) & 0xff;
    return b;
}

function u16(v) {
    const b = new Uint8Array(2);
    b[0] = v & 0xff; b[1] = (v >>> 8) & 0xff;
    return b;
}

function writeCoverage() {
    let header = 'DRCOV VERSION: 2\n';
    header += 'DRCOV FLAVOR: xfuzz\n';
    header += 'Module Table: version 2, count ' + modules.length + '\n';
    header += 'Columns: id, base, end, entry, checksum, timestamp, path\n';
    for (let i = 0; i < modules.length; i++) {
        header += '  ' + i + ', 0x' + modules[i].base.toString(16) +
            ', 0x' + modules[i].end.toString(16) +
            ', 0x0, 0x0, 0x0, ' + modules[i].path + '\n';
    }
    header += 'BB Table: ' + blocks.length + ' bbs\n';

    const body = new Uint8Array(blocks.length * 8);
    for (let i = 0; i < blocks.length; i++) {
        body.set(u32(blocks[i].offset), i * 8);
        body.set(u16(blocks[i].size), i * 8 + 4);
        body.set(u16(blocks[i].module), i * 8 + 6);
    }

    const f = new File(OUTPUT, 'wb');
    f.write(header);
    f.write(body.buffer);
    f.flush();
    f.close();
}

function record(start, end) {
    const i = moduleIndex(start);
    if (i < 0) {
        // Code outside every known module: a just-in-time compiler's output, or
        // a mapping made after the module list was taken. Nothing can be said
        // about where it came from, so it is dropped rather than attributed to
        // whichever module happens to be nearest.
        return;
    }
    const offset = start.sub(modules[i].base).toInt32();
    let size = end.sub(start).toInt32();
    if (size < 0 || size > 0xffff) size = 0;
    blocks.push({ offset: offset >>> 0, size: size, module: i });
}

collectModules();

Stalker.follow(Process.getCurrentThreadId(), {
    events: { compile: true },
    onReceive: function (events) {
        const parsed = Stalker.parse(events, { annotate: false, stringify: false });
        for (let i = 0; i < parsed.length; i++) {
            record(parsed[i][0], parsed[i][1]);
        }
    },
});

// The target is a one-shot program: it runs, it exits, and the coverage has to
// be on disk before it does. Frida's exit hook is what guarantees that; leaving
// the write to a timer would lose the coverage of every input that finished
// quickly, which is most of them.
Process.setExceptionHandler(function () { return false; });

const atexit = Module.findExportByName(null, 'exit');
if (atexit !== null) {
    Interceptor.attach(atexit, {
        onEnter: function () {
            Stalker.flush();
            writeCoverage();
        },
    });
}

const at_exit_group = Module.findExportByName(null, '_exit');
if (at_exit_group !== null) {
    Interceptor.attach(at_exit_group, {
        onEnter: function () {
            Stalker.flush();
            writeCoverage();
        },
    });
}

rpc.exports = {
    dump: function () {
        Stalker.flush();
        writeCoverage();
        return blocks.length;
    },
};
