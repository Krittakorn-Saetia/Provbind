"""requestz-helper: HARMLESS PROVBIND demo test package (SF9-26, SIIT). Not real malware.

Stands in for a compromised transitive dependency. `check_update()` reproduces a run-time
drop-and-execute (scenario attack-1) using an embedded test payload; it runs only inside the
throwaway demo container. See check.py and ../../x9.c.
"""
from .check import check_update

__version__ = "0.1.0"
__all__ = ["check_update"]
