# Akamai API pacing

Verified against Akamai documentation on September 23, 2026:

| Limit | Akamai documentation | Application cap |
| --- | --- | --- |
| PAPI sustained requests | 100/minute per account, shared across API clients | 80/minute across this deployment |
| Delivery traffic report | 20/minute per account; also subject to query cost | 15/minute across this deployment |
| PAPI IP burst / average | 16/second over 5 seconds; 12/second over 2 minutes | 2/second across all Akamai API families |
| IP penalty period | 10 minutes, extendable by further bursts | At least 610 seconds with no new app requests |

Sources:
- https://techdocs.akamai.com/property-mgr/reference/rate-and-resource-limiting
- https://techdocs.akamai.com/reporting/reference/delivery-traffic-current
- https://techdocs.akamai.com/reporting/reference/rate-limiting

HAPI (edge hostname inventory) and CPS (certificate enrollments and deployments)
requests are paced under the PAPI budget. Each is fetched once per audit.

The Redis limiter coordinates FastAPI, both Celery worker processes, every account,
and both credential sections. Each HTTP attempt acquires a slot, including retries
and retries after removing unauthorized CP codes. Requests are spaced evenly, with
no accumulated burst allowance. The concurrency semaphore only limits work in flight.
The application fails closed if Redis is unavailable; it never bypasses pacing.

Defaults are in app/config.py and .env.example. Caps can be lowered with environment
variables, but cannot be raised past the conservative values above. Identity searches
are additionally paced at 30/minute. Akamai response headers can reduce our request
budget but never increase it. Larger PAPI burst buckets do not justify a faster
sustained request rate.

HTTP 429 and transient 5xx responses receive bounded retries. Retry-After supports
seconds and HTTP dates. Reporting hit/cost refill timestamps are also honored, and
cooldowns are shared with other workers. An IPBLOCK-BURST response (HTTP 400 or 403)
pauses all API families for at least 610 seconds. Ordinary validation/authorization
errors are not treated as rate limits. Unauthorized CP codes are still isolated and
reported separately from successful traffic.

These controls cover this app, not other programs using the same IP or account.
Reporting cost limits depend on the query; there is no single request-count setting
that guarantees the absence of cost-based 429s. Response-driven cooldowns handle them.
Large audits will take longer (about 750 ms per uncached PAPI request) and concurrent
audits share the same total budget. Existing saved reports are not rewritten.

## Verification

Run in a disposable Compose container, with the source mounted and pytest installed:

```sh
TEST_REDIS_URL=redis://redis:6379/0 python -m pytest tests/test_api_rate_limit.py -q
```

Tests use mocked Akamai HTTP responses and uniquely named Redis test keys. They cover
cross-client pacing, shared global cooldowns, reporting cost headers, bounded retries,
permission filtering, invalid configuration, and preventing unpaced calls if Redis fails.
The Redis checks skip unless TEST_REDIS_URL is explicitly supplied.

## Deployed verification, September 23, 2026

77 rate-limit, origin, lifecycle, and deletion regression checks passed in Docker.
Live DIRECTV validation used six PAPI group requests from two client instances and
queried all 861 CP codes from the affected report. PAPI requests were at least 0.752
seconds apart; reporting attempts (including permission retries) were at least 4.002
seconds apart. All nine traffic chunks completed, returning 445 traffic rows, of which
439 had positive edge bytes. Five CP codes were explicitly unauthorized. There were
no HTTP 429 or IPBLOCK-BURST responses in this validation.

Live headers advertised a PAPI bucket of 5000 and a reporting hit bucket of 40.
Configured sustained budgets remain 80/minute and 15/minute respectively.
