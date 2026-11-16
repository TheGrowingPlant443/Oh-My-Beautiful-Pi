"""Retire the nested compositor when the launcher process exits, not its HTTP thread."""
import os
import select
import signal
import subprocess
import sys


def main():
    parent = os.pidfd_open(int(sys.argv[1]))
    child = None
    stopped = False

    def stop(_signal, _frame):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        if select.select([parent], [], [], 0)[0]:
            return 1
        # Only descriptors the launcher passed on purpose (pass_fds, e.g. wayvnc's listener) are inheritable here.
        child = subprocess.Popen(sys.argv[2:], close_fds=False)
        while child.poll() is None:
            if stopped or select.select([parent], [], [], 0.25)[0]:
                break
        return child.poll() or 0
    finally:
        os.close(parent)
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == "__main__":
    sys.exit(main())
