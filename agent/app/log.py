"""Tiny logger: one line per event with timestamp, ring buffer + stdout.

Never pass secrets (keys, tokens, passwords, config text) to ``log``.
"""

import collections
import sys
import threading
import time

_LINES = collections.deque(maxlen=200)
_LOCK = threading.Lock()
quiet = False  # tests set this to keep output clean


def log(msg, *args):
    if args:
        msg = msg % args
    msg = " ".join(str(msg).split())  # force a single line
    line = "%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    with _LOCK:
        _LINES.append(line)
    if not quiet:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def lines():
    with _LOCK:
        return list(_LINES)


def clear():
    with _LOCK:
        _LINES.clear()
