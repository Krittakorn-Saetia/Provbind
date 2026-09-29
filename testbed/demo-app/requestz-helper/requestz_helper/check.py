"""The run-time drop-and-execute used by scenario attack-1 (Test Plan §7). HARMLESS test code.

check_update() decodes the embedded base64 test payload, writes it to /tmp/.x9, marks it
executable and starts it in the background. The payload (../../x9.c) appends one inert marker line
to /etc/passwd and sleeps. This runs only inside the throwaway demo container.

The payload lives base64-encoded inside _payload.py, so it never exists as a file in the image and
its dropped hash is new: PROVBIND reports /tmp/.x9 as undeclared (in no layer), not relocated.
"""
from __future__ import annotations

import base64
import logging
import os
import stat
import subprocess

from ._payload import PAYLOAD_B64

log = logging.getLogger("requestz_helper")

DROP_PATH = "/tmp/.x9"


def check_update(drop_path: str = DROP_PATH) -> bool:
    """Drop and run the embedded test payload. Returns True if it was started.

    With no payload embedded (the source-tree default), this is a safe no-op that returns False,
    so importing or calling the package outside a built demo image does nothing.
    """
    if not PAYLOAD_B64:
        log.warning("requestz-helper: no payload embedded; check_update() is a no-op "
                    "(build the demo image so gen_payload.sh embeds ../../x9.c)")
        return False

    blob = base64.b64decode(PAYLOAD_B64)
    # A repeat run (Test Plan §12.2: every scenario at least 3 times) may find the previous payload
    # still running; writing over a running executable fails with ETXTBSY, but unlinking it is fine.
    try:
        os.unlink(drop_path)
    except FileNotFoundError:
        pass
    with open(drop_path, "wb") as f:
        f.write(blob)
    os.chmod(drop_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)  # 0755
    subprocess.Popen([drop_path], close_fds=True)     # run it in the background
    log.info("requestz-helper: dropped and started %s", drop_path)
    return True
