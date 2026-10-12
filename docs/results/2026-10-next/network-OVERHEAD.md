# PROVBIND runtime overhead

Configurations: none, falco, tetragon, provbind; repetitions: none 3, falco 3, tetragon 3, provbind 3. Values are medians over repetitions; overhead is against `none` (no monitor).

| Metric | none | falco | tetragon | provbind | falco overhead | tetragon overhead | provbind overhead |
|---|---|---|---|---|---|---|---|
| UDP send, socket + sendto (us/packet) | 6.99 | 8.58 | 7.06 | 7.06 | 22.60% | 0.90% | 1.00% |

Spread over repetitions (min – max):

| Metric | none | falco | tetragon | provbind |
|---|---|---|---|---|
| UDP send, socket + sendto (us/packet) | 6.95 – 7.04 | 8.57 – 8.63 | 6.97 – 7.07 | 6.98 – 7.08 |

## Against the 20% limit

- **provbind**: worst application overhead not run in this test; worst-case micro-benchmark not run in this test.
- **falco**: worst application overhead not run in this test; worst-case micro-benchmark not run in this test.
- **tetragon**: worst application overhead not run in this test; worst-case micro-benchmark not run in this test.

## PROVBIND against Falco

| Metric | PROVBIND overhead minus Falco overhead |
|---|---|
| UDP send, socket + sendto (us/packet) | -21.60 points |
| monitor CPU, PROVBIND / Falco | — |

## Network test against Her et al. (IEEE Access 2025)

Her et al. time socket() + sendto() for 100,000 UDP packets, 10 times per tool, on one Xeon node (their udp.c). Ours runs the same loop in Python inside the demo pod, to a socket in the pod instead of a public DNS server. Their Tetragon is the default install; our `tetragon` configuration carries PROVBIND's policies. Compare their figures with our Falco first: it shows how far this setup reproduces theirs.

| System | Overhead on our VM | Her et al., no policy | Her et al., with a UDP policy |
|---|---|---|---|
| PROVBIND | 1.00% | — | — |
| Falco | 22.60% | 19.93% | 24.77% |
| Tetragon | 0.90% | 3.14% | 72.92% |
| Tracee | — | 1.48% | 71.50% |
| KubeArmor | — | 87.74% | 88.59% |

## PROVBIND over the existing runtime collection (Tetragon with the same policies)

The paper's evaluation plan reports overhead relative to the runtime collection, not to an unmonitored host: this is PROVBIND's own userspace cost.

| Metric | PROVBIND vs Tetragon alone |
|---|---|
| UDP send, socket + sendto (us/packet) | 0.00% |

## Cost beside accuracy

| System | TP | FP | F1 | FPR | worst app overhead | worst micro overhead | monitor CPU |
|---|---|---|---|---|---|---|---|
| PROVBIND | 50 | 0 | 0.87 | 0.00 | — | — | — |
| Falco | 25 | 10 | 0.50 | 0.33 | — | — | — |
