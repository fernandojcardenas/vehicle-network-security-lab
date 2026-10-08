# M1 cross-check against can-j1939 (2026-10-08)

Command:
    vn-decode testdata/turku-truck-2020-11-26-slice.csv > ours.jsonl
    python3 tools/crosscheck_j1939.py testdata/turku-truck-2020-11-26-slice.csv ours.jsonl

Reference: can-j1939 2.0.12 (MIT) with python-can 4.6.1, Python 3.13.16.

Output:

    frames read: 15766
    can-j1939 messages: 15640 (40 reassembled transfers)
    vn-decode messages: 15640 (40 reassembled transfers)
    field mismatches: 0
    PASS
