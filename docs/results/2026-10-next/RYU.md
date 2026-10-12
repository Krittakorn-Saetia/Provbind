# Ryu-E: Ryu et al. [17] rebuilt on the comparison run

Host-based detector as published: 5-call windows of x86-64 call numbers, a decision tree trained on labelled examples. Trained on 3 normal-traffic recording(s) and the known attacks rk-2, rk-3 (10 runs, each scored without itself); labels `clean`; run rule `fraction`, threshold 0.0000 (leave one recording out: [0.0, 0.0, 0.0]).

**Their protocol** (random 70:30 split of windows, 15 classes, 14142 test windows): accuracy 0.7921, weighted precision 0.7825, recall 0.7921, F1 0.7636 (published: accuracy 0.9839, F1 0.9837).

**Our protocol** (trained only on what is known before an attack; every run scored out of sample):

| Scenario | Truth | Runs | Ryu-E | traced |
|---|---|---|---|---|
| benign-1 | benign | 5 | 5/5 | 5 |
| benign-traffic | benign | 5 | 5/5 | 5 |
| ph4-14 | benign | 5 | 5/5 | 5 |
| attack-1 | malicious | 5 | 5/5 | 5 |
| attack-2 | malicious | 5 | 5/5 | 5 |
| trust-1 | malicious | 5 | 0/5 | 5 |
| trust-2 | malicious | 5 | 0/5 | 5 |
| rk-2 | malicious | 5 | 5/5 | 5 |
| rk-3 | malicious | 5 | 5/5 | 5 |
| ru-3 | malicious | 5 | 5/5 | 5 |
| ru-4 | malicious | 5 | 5/5 | 5 |
| ru-5 | malicious | 5 | 5/5 | 5 |
| benign-3 | benign | 5 | 5/5 | 5 |
| benign-4 | benign | 5 | 0/5 | 5 |
| ab-1 | benign | 5 | 0/5 | 0 |
| ak-1 | malicious | 5 | 0/5 | 0 |
| ak-2 | malicious | 5 | 0/5 | 0 |
| ak-3 | malicious | 5 | 0/5 | 0 |
| au-2 | malicious | 5 | 0/5 | 0 |

| System | TP | FP | Precision | Recall | F1 | FPR | Known caught | Unknown caught |
|---|---|---|---|---|---|---|---|---|
| PROVBIND | 50 | 0 | 1.00 | 0.77 | 0.87 | 0.00 | 30/35 | 20/30 |
| Falco | 25 | 10 | 0.71 | 0.38 | 0.50 | 0.33 | 15/35 | 10/30 |
| DeSFAM-E | 34 | 23 | 0.60 | 0.52 | 0.56 | 0.77 | 10/35 | 24/30 |
| Confine-E | 0 | 5 | 0.00 | 0.00 | — | 0.17 | 0/35 | 0/30 |
| Sig-only | 5 | 0 | 1.00 | 0.08 | 0.14 | 0.00 | 5/35 | 0/30 |
| **Ryu-E** (estimated) | 35 | 20 | 0.64 | 0.54 | 0.58 | 0.67 | 10/35 | 25/30 |

Ryu-E is estimated from the published design on recorded traces, not Ryu et al.'s code. The admission scenarios are not traced, so no trace-based estimator can see them. Their network-flow detector is left out: our runs did not record flows.
