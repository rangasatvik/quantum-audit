# Research findings

The study contains 104 sites: 80 complete results and 24 incomplete or failed results.
The hybrid X25519MLKEM768 group was selected by 62 of 80 sites with a measurable key exchange (77.5%).

## By category

- banks: 9 of 11 measured sites (81.8%).
- government: 4 of 9 measured sites (44.4%).
- healthcare: 6 of 8 measured sites (75.0%).
- news: 10 of 10 measured sites (100.0%).
- shopping: 11 of 12 measured sites (91.7%).
- tech: 16 of 19 measured sites (84.2%).
- universities: 6 of 11 measured sites (54.5%).

## Other observations

- Grades (80 measured): A: 62, B: 18.
- TLS versions (100 measured): TLSv1.2: 19, TLSv1.3: 81.
- Certificate keys (100 measured): EC: 35, RSA: 65.
- Incomplete measurements: 24 PQ probe errors, 4 certificate scan errors, and 0 retry requests. These counts can overlap.

Observations were collected from 2026-11-02T22:30:19.781914+00:00 to 2026-11-02T22:33:06.694708+00:00 (UTC).

[Cloudflare](https://blog.cloudflare.com/post-quantum-visibility/) reported about 15% adoption on connections to origin servers; this study measures public-facing hosts, so the populations and methods differ and the percentages are not directly comparable.

Grades use the project's heuristic: 75% key-exchange score and 25% certificate score, with caps for weak or expired keys. They are not a comprehensive security assessment.

The ranked entries come from [Tranco list V354N](https://tranco-list.eu/list/V354N) (retrieved 2026-11-02); other entries were hand-picked. This is a small, non-random sample, not a representative estimate of all websites. Each host receives a raw PQ probe and a separate certificate handshake, paused between, with at least one second between hosts. The connections may reach different endpoints. A non-selected group may still be supported. The probe offers only TLS 1.3; a failed probe does not establish why negotiation failed. Failed and retry-request probes are excluded from the PQ percentage, not counted as negative results. The raw ServerHello is not authenticated; certificate verification failures are recorded separately.

Reproduce the study with `python research/scan_sites.py --timeout 5`, then `python research/analyze.py`. The scan overwrites `research/results.csv` and saves each row as it finishes.
