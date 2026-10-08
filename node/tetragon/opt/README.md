# Optimised policy variant (overhead work, 5 October 2026)

The same five hooks as `node/tetragon/*.yaml`, made cheaper for the overhead test (supervisor's 20% limit).
The originals are unchanged; apply ONE set at a time (both together report every event twice).

| Policy | Change | Why | What PROVBIND loses |
|---|---|---|---|
| write | no return probe; in-kernel rate limit: an identical event (same file, same mask) once a minute per process; only paths starting with `/` leave the kernel | the app rewrites the same few files; every write() was an event, and so was every HTTP response written to a socket | repeated writes to the same file by the same process within a minute (the first is still reported) |
| cap | in-kernel rate limit: the same capability check once a minute per process | `cap_capable` is one of the hottest kernel functions | repeated checks of the same capability by the same process (the first is still reported) |
| load | no return probe; in-kernel rate limit: the same library mapped executable once a minute across processes | every new process maps the same libraries | a second process mapping an already-reported library within a minute |
| truncate | no return probes; in-kernel rate limit: the same truncation (same file) once a minute per process | `open(path, "w")` on an existing file passes `security_file_truncate`: every request that rewrites a file was an event (found 7 October) | repeated truncations of the same file by the same process within a minute (the first is still reported) |
| connect | unchanged (rare events) | | |

Without the return probe a refused write or mapping is reported as an attempt (`node/normalize.py` keeps an
event with no return value). ML-B counts writes per window, so its model, trained under the original
policies, may need retraining under these; the comparison is re-run to check (F1, false alarms, attack-2).
Rate limiting needs Tetragon >= 1.1 (`rateLimit`, `rateLimitScope` on the Post action); the VM has 1.7.1.
