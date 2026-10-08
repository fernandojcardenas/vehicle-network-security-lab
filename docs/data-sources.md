# Data sources

## University of Turku heavy-duty truck CAN dataset

- **What:** over 180 hours of CAN traffic from a Renault T520 6x2 heavy truck
  (Euro VI), recorded at 250 kbit/s on the truck's FMS (fleet management
  system) interface with a PCAN-USB adapter and python-can. All frames are
  J1939 data frames.
- **Publisher:** University of Turku, 2021.
- **Licence:** Creative Commons Attribution 4.0 International (CC BY 4.0).
- **Record:** <https://doi.org/10.23729/3160254e-85e9-4268-a636-5b3e54091706>
  (Fairdata Etsin, dataset `7586f24f-c91b-41df-92af-283524de8b3e`).
- **Format:** CSV, one frame per row: `timestamp;id;dlc;data...` with the
  identifier in hex and data bytes in decimal, separated by semicolons.
  Published as four `tar.xz` archives (about 800 MB each).

### The slice in this repository

`testdata/turku-truck-2020-11-26-slice.csv` holds the first 15,766 rows of
`part_1/20201126113000265148.csv` from `part_1.tar.xz`, with the original CRLF
line endings. It is a slice, not the whole file. Attribution: *CAN bus dataset
collected from a heavy-duty truck*, University of Turku, CC BY 4.0. The only
change is truncation: the last, partial row was removed.

SHA-256: `0c7e019a6e7938654d84adf4003875397caaae6795d6b27313dde510b0f7b8eb`

What is in it, as decoded:

- About 20 seconds of traffic in three bursts (9.2 s, 9.8 s and 0.4 s),
  separated by two logger pauses of 98 s and 438 s.
- The truck is parked: parking brake set, and engine and vehicle-speed values
  are sent as "not available".
- Nearly all traffic comes from source address 230 (0xE6), the truck's FMS
  gateway, which republishes the vehicle's internal buses (47 parameter
  groups). Five more nodes (168, 176, 184, 192, 200) each send the same three
  groups (58624, 65116, 65220); nodes 83 and 246 send one group each.
- 40 complete broadcast transfers (BAM): 38 of a proprietary group (PGN
  65450, 21 bytes) and 2 vehicle identification messages (PGN 65260). The VIN
  is not printed anywhere in this repository.
- Timestamps are Finnish local time (UTC+2 in November). The dataset does not
  say so; the truck's own Time/Date broadcasts show it (see
  [m1-consistency.md](evidence/m1-consistency.md)). `vn-decode` reads the
  timestamps as if they were UTC, so its times are 2 hours ahead of real UTC.

### Why only a slice

The dataset's download service could not deliver a whole file on 2026-10-08:
every download (each of the four archives, and the server's pre-built zip
packages) stopped after 65–98 KB with the connection closed mid-transfer. That
happened from two different networks and from a web browser. The slice is
what arrived from `part_1.tar.xz` before the cut. M3 needs hours of traffic,
so this has to be solved before then: retry the download, ask the publisher,
or use another public J1939 capture.

## Parameter definitions

The SPN positions and scaling in `src/j1939/signals.cpp` come from public
sources:

- *FMS-Standard interface description*, version 02.00 (2010), published by
  the European truck manufacturers' FMS group, for the FMS parameter groups
  and their repetition rates.
- Public summaries of SAE J1939-71 for the remaining groups (EEC1, ETC1,
  ETC2, EBC1, EFL/P1, VEP1, TD).

The paid SAE J1939 Digital Annex was not used, and the table is limited to
common parameters. Positions are checked against real traffic where the
capture allows it (see [j1939-decoder.md](j1939-decoder.md)).

## Colorado State University heavy-vehicle J1939 data (M3)

The intrusion detector (M3) is validated on real driving traffic from two
trucks published by Jeremy Daily's group at Colorado State University:

- 2015 Kenworth T660, a 7-minute drive (~137k frames).
- 2014 Kenworth T270, a 4.2-hour drive (~9.86M frames).

Source page: <https://www.engr.colostate.edu/~jdaily/J1939/candata.html>. The
page states no licence, so these logs are **not** committed here. `tools/fetch_csu.py`
downloads them on demand and verifies each zip against a known SHA-256; they
are used only for local evaluation. The evidence files quote the measured
detection and false-alarm numbers so the results can be read without the data.

