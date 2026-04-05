import pty, os, sys, select, fcntl, termios, struct, re, socket, threading

def set_winsize(fd, rows, cols):
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)

def do_tunnel(remote_port, tunnel_port, server_ip, conn_id):
    s = r = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server_ip, tunnel_port))
        s.sendall(f'TUNNEL {conn_id} {remote_port}\n'.encode())
        r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        r.connect(('127.0.0.1', remote_port))
        while True:
            rd, _, _ = select.select([s, r], [], [])
            for sock in rd:
                data = sock.recv(4096)
                if not data:
                    return
                (r if sock is s else s).sendall(data)
    except Exception:
        pass
    finally:
        for sock in [s, r]:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass

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
tunnel_pattern = re.compile(b'\x1b\[9;(\d+);(\d+);([\d.]+);([^\x1b]+?)t')

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
        while True:
            match = tunnel_pattern.search(data)
            if not match: break
            remote_port = int(match.group(1))
            tunnel_port = int(match.group(2))
            server_ip = match.group(3).decode()
            conn_id = match.group(4).decode()
            threading.Thread(
                target=do_tunnel,
                args=(remote_port, tunnel_port, server_ip, conn_id),
                daemon=True,
            ).start()
            data = data[:match.start()] + data[match.end():]
        os.write(master, data)
    if master in r:
        data = os.read(master, 1024)
        if not data: break
        os.write(sys.stdout.fileno(), data)

os.waitpid(pid, 0)
