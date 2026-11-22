"""Single entry point for running system tools.

Every external command goes through ``run`` with an argument list (never a
shell). Tests replace ``run`` with a fake. Secrets are passed via ``input``
(stdin) only, never as arguments, so error messages built from ``args`` are
safe to log.
"""

import subprocess


class SysRunError(Exception):
    """A command failed or could not be started."""

    def __init__(self, args, returncode, stderr):
        self.cmd = list(args)
        self.returncode = returncode
        self.stderr = (stderr or "").strip()
        detail = self.stderr.splitlines()[-1] if self.stderr else "exit %s" % returncode
        super().__init__("%s failed: %s" % (" ".join(self.cmd[:3]), detail[:200]))


def run(args, input=None, check=True, timeout=30, text=True):
    """Run ``args`` (list of str) and return a ``subprocess.CompletedProcess``.

    stdout/stderr are captured as text (bytes with ``text=False``). With ``check`` a non-zero exit raises
    ``SysRunError``. A missing binary or a timeout always raises ``SysRunError``.
    """
    if not isinstance(args, (list, tuple)) or not args or not all(isinstance(a, str) for a in args):
        raise ValueError("args must be a non-empty list of str")
    try:
        proc = subprocess.run(
            list(args),
            input=input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=text,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        raise SysRunError(args, 127, "command not found")
    except subprocess.TimeoutExpired:
        raise SysRunError(args, -1, "timeout after %ss" % timeout)
    if check and proc.returncode != 0:
        err = proc.stderr if text else (proc.stderr or b"").decode("utf-8", "replace")
        raise SysRunError(args, proc.returncode, err)
    return proc
