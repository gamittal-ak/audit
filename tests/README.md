UI, report deletion, and origin certificate regression checks:

```sh
pip install -r requirements-dev.txt
python -m playwright install --with-deps chromium
python -m pytest tests -q
```

Browser checks start a loopback-only fixture server with synthetic account data.
Account search and deletion are simulated; no production audit or deletion requests
are made. Screenshots are saved under /tmp/audit-ui-*.png.

Deletion tests use fake Redis/Celery services and temporary report files.

Origin lifecycle checks cover short-lived certificate thresholds, configured pins
and CA certificates, snapshot timestamps, grouping with all rule references, and
saved-report Excel downloads. Tests use synthetic evidence and temporary files.
The All Data, Origins, and Origin Certificates sheet values and column schemas
remain intact; origin recommendations and Summary context use the same policy as
the UI.

Compact layout review: checked desktop widths 1024-1920, tablet 800, and mobile
390 pixels, plus sticky report controls. The synthetic origin table starts at
487px instead of 749px at a 1440px viewport. The September 24 density pass
shortened the synthetic report page from 3433px to 2937px at 1440px and history
rows from about 80px to 50px, with no content or controls removed.

Edge TLS checks (`test_edge_security.py`, `test_edge_certificates.py`) cover
sTLS/eTLS and shared-certificate classification, legacy reports, per-network
coverage, CPS parsing, wildcard matching, null SNI name lists, contracts outside
the API client's access, and every case that must never become HTTP-only.
Pivot checks (`test_pivots.py`) cover distinct cache IDs, sources, record counts,
grand totals, empty sources, and text-only labels.

Live activity checks cover task isolation, bounded storage and expiry, activity
store outages, task outcomes, authenticated polling, HTML escaping, report cleanup,
retry summaries, and a synthetic pipeline. Set TEST_REDIS_URL for Redis integration
checks. Browser checks verify auto-scroll, scroll anchoring as old entries are
trimmed, keyboard focus, mobile overflow and transition to the finished report.
