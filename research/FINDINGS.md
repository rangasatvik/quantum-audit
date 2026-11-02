# Research findings

The study contains 104 sites: 99 classified and graded results and 5 incomplete or failed results.
The hybrid X25519MLKEM768 group was selected by 62 of 99 classified sites (62.6%).

## By category

- banks: 9 of 14 classified sites (64.3%).
- government: 4 of 13 classified sites (30.8%).
- healthcare: 6 of 12 classified sites (50.0%).
- news: 10 of 13 classified sites (76.9%).
- shopping: 11 of 13 classified sites (84.6%).
- tech: 16 of 19 classified sites (84.2%).
- universities: 6 of 15 classified sites (40.0%).

Government, universities, healthcare, and banks have lower measured rates than both tech and shopping in this sample. Category counts are small.
Banks are above the overall rate despite trailing tech and shopping.

## Other observations

- Grades (99 measured): A: 62, B: 18, C: 19.
- TLS versions (100 measured): TLSv1.2: 19, TLSv1.3: 81.
- Certificate keys (100 measured): EC: 35, RSA: 65.
- 19 sites were classified as no PQ after a TLS 1.2-or-older connection and an unsuccessful TLS 1.3 probe.
- Incomplete measurements: 5 PQ probe errors, 4 certificate scan errors, and 0 retry requests. These counts can overlap.
- Unclassified hosts: bing.com, fifththirdbank.com, ssa.gov, atlanta.gov, humana.com. See the CSV for the underlying connection and certificate errors.

Observations were collected from 2026-11-02T22:30:19.781914+00:00 to 2026-11-02T22:33:06.694708+00:00 (UTC).

[Cloudflare](https://blog.cloudflare.com/post-quantum-visibility/) reported about 15% adoption on connections to origin servers; this study measures public-facing hosts, so the populations and methods differ and the percentages are not directly comparable.

Grades use the project's heuristic: 75% key-exchange score and 25% certificate score, with caps for weak or expired keys. TLS 1.2 with forward secrecy is graded C. They are not a comprehensive security assessment.

The ranked entries come from [Tranco list V354N](https://tranco-list.eu/list/V354N) (retrieved 2026-11-02); other entries were hand-picked. This is a small, non-random sample, not a representative estimate of all websites. Each host receives a raw PQ probe and a separate certificate handshake, paused between, with at least one second between hosts. The connections may reach different endpoints. A non-selected group may still be supported. The probe offers only TLS 1.3; a failed probe does not establish why negotiation failed. For this study, a protocol-alert or invalid-record probe failure combined with TLS 1.2 or older is classified as no PQ on the observed connection. This is an assumption, not proof that the host supports only TLS 1.2 or does not support PQ under other conditions. Network errors and retry requests are excluded. The raw ServerHello is not authenticated; certificate verification failures are recorded separately.

Reproduce the study with `python research/scan_sites.py --timeout 5`, then `python research/analyze.py`. The scan overwrites `research/results.csv` and saves each row as it finishes.
