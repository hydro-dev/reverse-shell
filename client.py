import pty, os, sys, select, fcntl, termios, struct, re

def set_winsize(fd, rows, cols):
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)

master, slave = pty.openpty()
set_winsize(master, 24, 80)

pid = os.fork()
if pid == 0:
    os.setsid()
    os.dup2(slave, 0)
    os.dup2(slave, 1)
    os.dup2(slave, 2)
    os.close(master)
    os.close(slave)
    os.execve('/bin/bash', ['/bin/bash'], os.environ)
    sys.exit(0)

os.close(slave)
esc_pattern = re.compile(b'\x1b\[8;(\d+);(\d+)t')

while True:
    r, _, _ = select.select([sys.stdin.fileno(), master], [], [])
    if sys.stdin.fileno() in r:
        data = os.read(sys.stdin.fileno(), 1024)
        if not data: break
        while True:
            match = esc_pattern.search(data)
            if not match: break
            set_winsize(master, int(match.group(1)), int(match.group(2)))
            data = data[:match.start()] + data[match.end():]
        os.write(master, data)
    if master in r:
        data = os.read(master, 1024)
        if not data: break
        os.write(sys.stdout.fileno(), data)

os.waitpid(pid, 0)
