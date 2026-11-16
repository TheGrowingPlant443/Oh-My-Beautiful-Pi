"""Retire an SSH connection when its controller dies, including SIGKILL (portable parent identity check)."""
import os
import signal
import subprocess
import sys


def main(parent, command):
    # getppid is a kernel relationship, not a lookup of a possibly reused controller PID. Reparenting after
    # controller death cannot authorize adopting a new process with its old numeric PID.
    if os.getppid() != parent:
        return 1
    stopped = False
    def stop(_number, _frame):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGHUP, stop)
    child = subprocess.Popen(command)
    try:
        while not stopped and os.getppid() == parent:
            try:
                return child.wait(timeout=0.25)
            except subprocess.TimeoutExpired:
                pass
        return 1
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == "__main__":
    sys.exit(main(int(sys.argv[1]), sys.argv[2:]))
