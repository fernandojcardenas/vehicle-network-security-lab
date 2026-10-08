# M3 intrusion detection on simulated traffic (2026-10-08)

Five minutes of simulated truck traffic (`vn-sim --duration 300 --seed 3`), each attack
injected into the test region with `vn-attack`, scored with `tools/evaluate_ids.py`.
The detector trains on the first 40% and is tested on the rest.

Clean traffic (no attack), held-out test region: 22 novelty alerts, all
value-out-of-range, at 150-170 s. They are legitimate: a later drive cycle
(the simulated truck picks a new random top speed each cycle) drove faster
than the training window had seen. This is the inherent residual of learning a
value range from a limited window, not a detector fault. CI asserts the count
stays small (below 100) so a regression that floods alerts is still caught.

    vn-ids: trained on 120.0 s (29007 messages, 6 sources), testing on 180.0 s
    vn-ids: 22 alerts
      value-out-of-range     22

Each attack (`--start 200 --duration 20`):

| Attack | Alert types raised in the window | Result |
|---|---|---|
| flood | unknown-source (20) | detected |
| spoof | value-out-of-range (20), impossible-jump (20) | detected |
| replay | flood-rate (296), value-out-of-range (13), impossible-jump (31) | detected |
| jump | value-out-of-range (1), impossible-jump (1) | detected |
| hijack | address-claim-conflict (20) | detected |

All five detected. No novelty alert fell inside an attack window, so every
in-window alert above is from the attack itself.
