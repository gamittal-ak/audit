"""Shared limiter integration checks use only uniquely named Redis keys.
No tests send requests to Akamai. Set TEST_REDIS_URL for Redis integration checks.
"""
import asyncio
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import os
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
import uuid

import httpx
import pytest
import redis.asyncio as aioredis
from pydantic import ValidationError

from app.config import Settings
from app.services.akamai_client import AkamaiClient, _reporting_forbidden
from app.services.rate_limit import (
    AkamaiRateLimiter, api_scope, is_waf_rate_block, quota_delay, retry_after_delay,
)


def run(coro):
    return asyncio.run(coro)


def fake_client(responses):
    sent = []
    def handle(request):
        sent.append(request)
        return responses.pop(0)
    client = AkamaiClient('https://example.test', None, asyncio.Semaphore(3))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
    client._limiter = SimpleNamespace(acquire=AsyncMock(), observe=AsyncMock(), defer=AsyncMock())
    return client, sent


@pytest.mark.parametrize('status', [429, 500, 502, 503, 504])
def test_papi_retry_is_paced_and_sets_shared_cooldown(status):
    async def check():
        c, sent = fake_client([httpx.Response(status, headers={'Retry-After': '90'}),
                               httpx.Response(200, json={'groups': []})])
        assert await c.get_groups('test') == {'groups': []}
        assert len(sent) == 2
        assert c._limiter.acquire.await_count == 2
        c._limiter.defer.assert_awaited_once_with('papi', 90.0)
        await c._client.aclose()
    run(check())


@pytest.mark.parametrize('status', [400, 403])
def test_waf_block_retries_after_global_cooldown(status):
    async def check():
        c, sent = fake_client([httpx.Response(status, json={'detail': 'WAF deny rule IPBLOCK-BURST4-54013'}),
                               httpx.Response(200, json={'data': [{'cpcode': 10}]})])
        result = await c.get_traffic('waf-test', [10])
        assert result['status'] == 'ok'
        assert len(sent) == 2
        c._limiter.defer.assert_awaited_once_with('global', 610.0)
        assert 'waf-test' not in _reporting_forbidden
        await c._client.aclose()
    run(check())


def test_validation_error_is_not_retried():
    async def check():
        c, sent = fake_client([httpx.Response(400, json={'detail': 'Invalid filter'})])
        result = await c.get_traffic('validation-test', [10])
        assert result['status'] == 'api_error'
        assert len(sent) == 1
        c._limiter.defer.assert_not_awaited()
        await c._client.aclose()
    run(check())


def test_partial_permission_error_preserves_authorized_traffic():
    async def check():
        c, sent = fake_client([
            httpx.Response(403, json={'detail': 'Some of the requested objects are unauthorized: [10]'}),
            httpx.Response(200, json={'data': [{'cpcode': 11}]}),
        ])
        result = await c.get_traffic('partial-test', [10, 11])
        assert result['status'] == 'partial'
        assert result['data'] == [{'cpcode': 11}]
        assert result['cpcode_statuses'] == {'10': 'forbidden'}
        assert c._limiter.acquire.await_count == 2
        assert 'partial-test' not in _reporting_forbidden
        await c._client.aclose()
    run(check())


def test_exhausted_retry_budget_is_bounded_and_keeps_cooldown():
    async def check():
        c, sent = fake_client([httpx.Response(429) for _ in range(2)])
        result = await c.get_traffic('exhausted-test', [10], _max_retries=2)
        assert result['status'] == 'rate_limited'
        assert result['cpcode_statuses'] == {'10': 'rate_limited'}
        assert len(sent) == c._limiter.acquire.await_count == c._limiter.defer.await_count == 2
        await c._client.aclose()
    run(check())


def test_redis_failure_prevents_outgoing_request():
    async def check():
        c, sent = fake_client([])
        c._limiter.acquire.side_effect = ConnectionError('Redis unavailable')
        with pytest.raises(ConnectionError):
            await c.get_groups('test')
        assert not sent
        await c._client.aclose()
    run(check())


def test_retry_after_and_cost_refill_dates():
    now = datetime.now(timezone.utc)
    assert retry_after_delay(httpx.Headers({'Retry-After': '90'})) == 90
    assert 88 <= retry_after_delay(httpx.Headers({'Retry-After': format_datetime(now + timedelta(seconds=90))})) <= 90
    headers = httpx.Headers({
        'akamai-sync-ratelimit-remaining': '0',
        'akamai-sync-ratelimit-next': (now + timedelta(seconds=30)).isoformat(),
        'akamai-sync-costratelimit-remaining': '0',
        'akamai-sync-costratelimit-next': str(int((now + timedelta(seconds=120)).timestamp() * 1000)),
    })
    assert 118 <= quota_delay(headers) <= 120
    assert quota_delay(httpx.Headers({'akamai-sync-costratelimit-next': 'bad-date'}), exhausted=True) == 0
    assert retry_after_delay(httpx.Headers({'Retry-After': 'nan'})) is None


def test_configuration_cannot_exceed_safe_caps():
    for field, value in [('papi_requests_per_minute', 100), ('reporting_requests_per_minute', 20),
                         ('akamai_global_requests_per_second', 12), ('akamai_waf_cooldown_seconds', 60),
                         ('papi_requests_per_minute', 0)]:
        with pytest.raises(ValidationError):
            Settings(_env_file=None, **{field: value})


@pytest.mark.parametrize('path,scope', [('/papi/v1/groups','papi'), ('/hapi/v1/edge-hostnames','papi'), ('/cps/v2/enrollments','papi'),
    ('/reporting-api/v2/reports/delivery/traffic/current/data','reporting'),
    ('/identity-management/v3/api-clients/self/account-switch-keys','identity')])
def test_every_api_family_is_paced(path, scope):
    assert api_scope(path) == scope


async def redis_case(check):
    url = os.environ.get('TEST_REDIS_URL')
    if not url:
        pytest.skip('Set TEST_REDIS_URL to run real Redis coordination tests')
    clients = [aioredis.from_url(url) for _ in range(3)]
    prefix = 'test:akamai-rate:' + uuid.uuid4().hex
    settings = Settings(_env_file=None)
    limiters = [AkamaiRateLimiter(r, settings, prefix) for r in clients]
    try:
        await check(limiters)
    finally:
        keys = [k async for k in clients[0].scan_iter(prefix + ':*')]
        if keys:
            await clients[0].delete(*keys)
        for r in clients:
            await r.aclose()


def test_concurrent_workers_share_sustained_papi_budget():
    async def check(limiters):
        times = []
        async def send(limiter):
            await limiter.acquire('papi')
            times.append(time.monotonic())
        await asyncio.gather(*(send(limiters[i % 3]) for i in range(9)))
        gaps = [b-a for a,b in zip(sorted(times),sorted(times)[1:])]
        assert min(gaps) >= 0.73, gaps  # 80/min => 750 ms; small scheduler tolerance.
        assert max(times)-min(times) >= 5.9
    run(redis_case(check))


def test_reporting_spacing_shared_between_credentials():
    async def check(limiters):
        times = []
        async def send(limiter):
            await limiter.acquire('reporting')
            times.append(time.monotonic())
        await asyncio.gather(*(send(limiter) for limiter in limiters))
        assert max(times)-min(times) >= 7.9  # 15/min => 4 seconds apart.
    run(redis_case(check))


def test_cooldown_applies_to_already_waiting_requests_and_cannot_be_shortened():
    async def check(limiters):
        await limiters[0].acquire('papi')
        started = time.monotonic()
        waiting = asyncio.create_task(limiters[1].acquire('papi'))
        await asyncio.sleep(0.1)
        await limiters[2].defer('global', 1.5)
        await limiters[0].defer('global', 0.1)
        await waiting
        assert time.monotonic()-started >= 1.55
    run(redis_case(check))


def test_ip_pacing_is_shared_across_api_families():
    async def check(limiters):
        started = time.monotonic()
        await limiters[0].acquire('papi')
        await limiters[1].acquire('reporting')
        await limiters[2].acquire('identity')
        assert time.monotonic()-started >= 0.98
    run(redis_case(check))


def test_server_headers_can_lower_but_never_raise_budget():
    async def check(limiters):
        l = limiters[0]
        await l.observe('papi',httpx.Response(200,headers={'X-RateLimit-Limit':'5000'}))
        key = l.prefix + ':papi:interval'
        assert int(await l.redis.get(key)) == 750
        await l.observe('papi',httpx.Response(200,headers={'X-RateLimit-Limit':'50'}))
        assert int(await l.redis.get(key)) == 1500
        await limiters[1].observe('papi',httpx.Response(200,headers={'X-RateLimit-Limit':'5000'}))
        assert int(await l.redis.get(key)) == 1500
    run(redis_case(check))


def test_cost_budget_exhaustion_pauses_other_reporting_clients():
    async def check(limiters):
        now = datetime.now(timezone.utc)
        await limiters[0].observe('reporting',httpx.Response(200,headers={
            'akamai-sync-costratelimit-remaining':'0',
            'akamai-sync-costratelimit-next':(now + timedelta(seconds=1)).isoformat(),
        }))
        started = time.monotonic()
        await limiters[1].acquire('reporting')
        assert time.monotonic()-started >= 1.8
    run(redis_case(check))
