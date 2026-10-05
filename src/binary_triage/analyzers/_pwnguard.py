"""Make pwntools import-safe on a locked-down Attack & Defense vulnbox.

Importing ``from pwn import ...`` runs ``pwnlib.update.check_automatically()`` at
import time, which once per week issues an outbound HTTPS request to
``pypi.org`` to look for a newer pwntools. On a fresh vulnbox image (exactly
game day) that cache is empty, so the call fires: a multi-second stall and an
unexpected network connection at tool start -- a bad look under screen-recording
scrutiny, and the competition requires the AD path to stay offline.

Import this module *before* the first ``from pwn import ...`` in any module that
uses pwntools. It only flips in-process flags; it makes no network call itself
and imports no AI/ML code.

Belt-and-suspenders for anyone importing ``pwn`` directly in exploit scripts:
disable the check on the box once, before play::

    mkdir -p ~/.config && printf '[update]\\ninterval=never\\n' >> ~/.config/pwn.conf
    # (or /etc/pwn.conf system-wide)
"""

import os

# Non-interactive terminal: don't assume a TTY when we're piped/headless.
os.environ.setdefault("PWNLIB_NOTERM", "1")

# Disable the weekly PyPI update check deterministically, without needing a
# config file on disk. `pwnlib.update.should_check()` returns False when
# `disabled` is truthy, so no request is ever attempted.
try:  # pragma: no cover - defensive; pwntools may be absent (fallback path)
    import pwnlib.update

    pwnlib.update.disabled = True
except Exception:
    pass
