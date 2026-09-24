"""Redis-coordinated pacing shared by every API client and worker.

Use conservative deployment-wide budgets, even across different accounts/hosts.
No burst credit: each outgoing request, including retries, must acquire a slot.
Redis is required; an unavailable limiter never falls back to unpaced requests.
"""
import asyncio
import logging
import math
import time

from app.services.audit_log import event
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

logger = logging.getLogger(__name__)

_ACQUIRE = """
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local next_global = tonumber(redis.call('GET', KEYS[1]) or '0')
local next_api = tonumber(redis.call('GET', KEYS[2]) or '0')
local interval = math.max(tonumber(ARGV[2]), tonumber(redis.call('GET', KEYS[3]) or '0'))
local wait = math.max(next_global, next_api) - now
if wait > 0 then return math.ceil(wait) end
redis.call('SET', KEYS[1], now + tonumber(ARGV[1]), 'PX', tonumber(ARGV[1]))
redis.call('SET', KEYS[2], now + interval, 'PX', interval)
return 0
"""

_DEFER = """
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local until_at = now + tonumber(ARGV[1])
local previous = tonumber(redis.call('GET', KEYS[1]) or '0')
if until_at > previous then
    redis.call('SET', KEYS[1], until_at, 'PX', tonumber(ARGV[1]))
end
return 0
"""

_SLOWER = """
local previous = tonumber(redis.call('GET', KEYS[1]) or '0')
local interval = math.max(previous, tonumber(ARGV[1]))
redis.call('SET', KEYS[1], interval, 'EX', 3600)
return interval
"""


# HAPI and CPS advertise their own, lower limits (CPS: 35/minute). Separate
# scopes keep those headers from slowing PAPI; the global cap still covers all.
EDGEGRID_SCOPES = ('papi', 'hapi', 'cps')


def api_scope(path):
    for scope in EDGEGRID_SCOPES:
        if path.startswith(f'/{scope}/'):
            return scope
    if path.startswith('/reporting-api/'):
        return 'reporting'
    return 'identity'


def _number(value):
    try:
        value = float(value)
        return value if math.isfinite(value) else None
    except (TypeError, ValueError):
        return None


def _date_delay(value):
    """Parse Akamai refill dates (ISO/HTTP date or epoch seconds/milliseconds)."""
    if not value:
        return None
    number = _number(value)
    now = datetime.now(timezone.utc)
    if number is not None:
        if number > 1e12:
            number /= 1000
        return max(0.0, number - now.timestamp())
    try:
        date = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        try:
            date = parsedate_to_datetime(value)
        except (ValueError, TypeError, OverflowError):
            return None
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    return max(0.0, (date - now).total_seconds())


def retry_after_delay(headers):
    raw = headers.get('retry-after')
    seconds = _number(raw)
    if seconds is not None:
        return max(0.0, seconds)
    return _date_delay(raw)


def quota_delay(headers, exhausted=False):
    """Honor both reporting hit and cost budgets; never retry before either refill."""
    delays = []
    for prefix in ('akamai-sync-ratelimit', 'akamai-sync-costratelimit'):
        remaining = _number(headers.get(prefix + '-remaining'))
        if exhausted or (remaining is not None and remaining <= 0):
            delay = _date_delay(headers.get(prefix + '-next'))
            if delay is None:
                delay = _date_delay(headers.get(prefix + '-reset'))
            if delay is not None:
                delays.append(delay)
    remaining = _number(headers.get('x-ratelimit-remaining'))
    if remaining is not None and remaining <= 0:
        delays.append(_date_delay(headers.get('x-ratelimit-reset')) or 60.0)
    return max(delays, default=0.0)


def is_waf_rate_block(resp):
    # Do not retry ordinary validation failures, permissions errors or other WAF rules.
    return resp.status_code in (400, 403) and 'ipblock-burst' in resp.text.lower()


class AkamaiRateLimiter:
    def __init__(self, redis, settings, prefix='akamai:limits:v1'):
        self.redis = redis
        self.prefix = prefix
        self.global_interval = math.ceil(1000 / settings.akamai_global_requests_per_second)
        self.intervals = {
            'papi': math.ceil(60000 / settings.papi_requests_per_minute),
            'hapi': math.ceil(60000 / settings.papi_requests_per_minute),
            'cps': math.ceil(60000 / (35 * 0.8)),
            'reporting': math.ceil(60000 / settings.reporting_requests_per_minute),
            'identity': 2000,
        }
        self._seen_headers = set()
        self._last_wait_notice = {}

    async def acquire(self, scope):
        while True:
            wait_ms = await self.redis.eval(
                _ACQUIRE, 3, f'{self.prefix}:global', f'{self.prefix}:{scope}',
                f'{self.prefix}:{scope}:interval', self.global_interval, self.intervals[scope],
            )
            if wait_ms <= 0:
                return
            now = time.monotonic()
            if wait_ms >= 5000 and now - self._last_wait_notice.get(scope, float("-inf")) >= 30:
                self._last_wait_notice[scope] = now
                event(f"Waiting for the shared {scope} API budget: at least {math.ceil(wait_ms / 1000)}s remaining.", "warning")
            # Recheck shared state after waking; another process may extend a cooldown.
            await asyncio.sleep(min(wait_ms / 1000, 30.0))

    async def defer(self, scope, seconds):
        await self.redis.eval(
            _DEFER, 1, f'{self.prefix}:{scope}', max(1, math.ceil(seconds * 1000)),
        )

    async def observe(self, scope, resp):
        headers = resp.headers
        relevant = {k: v for k, v in headers.items() if 'ratelimit' in k or k == 'retry-after'}
        if relevant and scope not in self._seen_headers:
            logger.info('Akamai %s rate headers: %s', scope, relevant)
            self._seen_headers.add(scope)
        # Never increase our configured budget based on a burst-capacity header.
        header = 'x-ratelimit-limit' if scope in EDGEGRID_SCOPES else 'akamai-sync-ratelimit-limit'
        limit = _number(headers.get(header))
        if limit is not None and limit > 0:
            interval = max(self.intervals[scope], math.ceil(60000 / (limit * 0.8)))
            await self.redis.eval(_SLOWER, 1, f'{self.prefix}:{scope}:interval', interval)
        delay = quota_delay(headers, exhausted=resp.status_code == 429)
        if delay > 0:
            await self.defer(scope, delay + 1)
