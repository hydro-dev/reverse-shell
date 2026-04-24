import pty, os, sys, select, fcntl, termios, struct, re, socket, threading, time, hashlib, shutil, subprocess

# Rename process to make it identifiable (e.g. for kill/ps)
try:
    import ctypes
    libc = ctypes.CDLL('libc.so.6')
    libc.prctl(15, b'executor-client', 0, 0, 0)  # PR_SET_NAME = 15
except Exception:
    pass

SERVER_IP = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
SERVER_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 13335
RECONNECT_DELAY = 5

def singleton_lock(client_id):
    """Acquire an exclusive lock to ensure only one instance per client_id."""
    lock_path = f'/tmp/executor-client-{client_id}.lock'
    fd = open(lock_path, 'w')
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fd.write(str(os.getpid()))
        fd.flush()
        return fd
    except (IOError, OSError):
        fd.close()
        return None

def get_client_id():
    try:
        with open('/etc/machine-id') as f:
            return f.read().strip()
    except Exception:
        pass
    try:
        import uuid
        return str(uuid.getnode())
    except Exception:
        return hashlib.md5(socket.gethostname().encode()).hexdigest()

def get_sysinfo():
    whoami = subprocess.check_output(['whoami'], text=True).strip()
    try:
        os_name = ''
        with open('/etc/os-release') as f:
            for line in f:
                if line.startswith('PRETTY_NAME='):
                    os_name = line.strip().split('=', 1)[1].strip('"')
                    break
    except Exception:
        os_name = ''
    has_tmux = shutil.which('tmux') is not None
    return whoami, os_name, has_tmux

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
                if sock: sock.close()
            except Exception:
                pass

# --- Init ---

CLIENT_ID = get_client_id()

_lock_fd = singleton_lock(CLIENT_ID)
if _lock_fd is None:
    sys.exit(0)

_whoami, _os_name, _has_tmux = get_sysinfo()

def new_shell():
    """Fork a new shell child, return (pid, master_fd).
    If tmux is available, run tmux in a loop so ctrl-d won't drop to plain bash."""
    m, s = pty.openpty()
    set_winsize(m, 24, 80)
    p = os.fork()
    if p == 0:
        os.setsid()
        os.dup2(s, 0); os.dup2(s, 1); os.dup2(s, 2)
        os.close(m); os.close(s)
        env = dict(os.environ)
        for k in ('TMUX', 'TMUX_PANE'):
            env.pop(k, None)
        if _has_tmux:
            os.execve('/bin/bash', ['/bin/bash', '-c',
                'while true; do '
                'tmux new-session -d -s omc 2>/dev/null; '
                'tmux set -g mouse on 2>/dev/null; '
                'tmux attach -t omc; '
                'sleep 0.1; done'
            ], env)
        else:
            os.execve('/bin/bash', ['/bin/bash'], env)
    os.close(s)
    return p, m

pid, master = new_shell()

esc_pattern = re.compile(b'\x1b\[8;(\d+);(\d+)t')
tunnel_pattern = re.compile(b'\x1b\[9;(\d+);(\d+);([\d.]+);([^\x1b]+?)t')
PING_FRAME = b'\x1b[9199t'

def run_session(conn):
    global pid, master
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 10)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except Exception:
        pass
    tmux_flag = ' TMUX' if _has_tmux else ''
    conn.sendall(f'HELLO {CLIENT_ID} {_whoami} {_os_name}{tmux_flag} OLLEH'.encode())
    conn_fd = conn.fileno()

    stop = threading.Event()
    def ping_loop():
        while not stop.wait(60):
            try:
                conn.sendall(PING_FRAME)
            except Exception:
                break
    threading.Thread(target=ping_loop, daemon=True).start()
    while True:
        try:
            rd, _, _ = select.select([conn_fd, master], [], [])
        except (ValueError, OSError):
            break
        if conn_fd in rd:
            try:
                data = conn.recv(4096)
            except Exception:
                break
            if not data:
                break
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
            if data:
                os.write(master, data)
        if master in rd:
            try:
                data = os.read(master, 4096)
            except OSError:
                # bash exited — reap and spawn a new shell
                os.waitpid(pid, 0)
                pid, master = new_shell()
                continue
            if not data:
                break
            try:
                conn.sendall(data)
            except Exception:
                break
    stop.set()

while True:
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((SERVER_IP, SERVER_PORT))
        run_session(conn)
    except Exception:
        pass
    finally:
        try: conn.close()
        except Exception: pass
    time.sleep(RECONNECT_DELAY)
