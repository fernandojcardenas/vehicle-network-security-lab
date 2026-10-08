# M2 cross-check against can-j1939 on simulated traffic (2026-10-08)

Commands:

    vn-sim --duration 600 --seed 1 --conflict --summary --out sim.log
    vn-decode sim.log > sim.jsonl
    python3 tools/crosscheck_j1939.py sim.log sim.jsonl

Reference: can-j1939 2.0.12 (MIT) with python-can 4.6.1, listening passively (see the script's docstring).

Simulator summary:

    simulated 600.0 s at 250 kbit/s: 146267 frames, bus load 13.7 %
    arbitration: 15756 contested starts, 15943 frames waited; longest wait 6840 us; most queued 7
    node            addr   frames claims   BAM   RTS  rxRTS  NACK
    engine          0x00    54451      2   510    12      0     0
    transmission    0x03    65976      2     0     0      0     1
    brakes          0x0B     6000      2     0     0      0     0
    cluster         0x17     7200      2     0     0      0     0
    tachograph      0xEE    12597      2     0     0      0     0
    service-tool    0xF9       38      2     0     0     11     0
    service-tool-2  0x80        5      2     0     0      1     0

Decoder transport counters:

    single-frame messages 144666
    BAM started 510, completed 510; RTS started 12, completed 12; CTS 12, EndOfMsgAck 12
    transport problems: timeouts 0, sequence errors 0, bad announcements 0, aborts 0, replaced 0, orphan data 0, malformed 0, rejected (too many sessions) 0

Cross-check output:

    compared: every message except Requests and Address Claimed (checked against raw frames below)
    frames read: 146267
    can-j1939 messages: 145159 (522 reassembled transfers)
    vn-decode messages: 145159 (522 reassembled transfers)
    requests + address claims: 29 vn-decode messages vs 29 raw frames -> identical
    field mismatches: 0
    PASS
