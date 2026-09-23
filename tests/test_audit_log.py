"""Task isolation, bounded Redis storage and authenticated progress rendering."""
import asyncio
import json
import os
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
import redis
import redis.asyncio as aioredis
from starlette.requests import Request

from app.services import audit_log
from app.routers import reports
from app.tasks import report_task


def request(auth=True):
    return Request({"type": "http", "method": "GET", "path": "/", "headers": [], "session": {"authenticated": auth}})


@pytest.fixture
def activity_store(monkeypatch):
    url = os.environ.get("TEST_REDIS_URL")
    if not url:
        pytest.skip("Set TEST_REDIS_URL for activity storage integration")
    monkeypatch.setattr(audit_log, "get_settings", lambda: SimpleNamespace(redis_url=url))
    client = redis.Redis.from_url(url, decode_responses=True)
    task_ids = ["test-activity-" + uuid.uuid4().hex for _ in range(2)]
    yield client, task_ids, url
    client.delete(*(audit_log.log_key(tid) for tid in task_ids))
    client.close()


def test_concurrent_audits_are_isolated_and_context_is_cleared(activity_store):
    client, ids, _ = activity_store
    async def job(tid):
        with audit_log.audit_activity(tid):
            for n in range(4):
                await asyncio.sleep(0)
                audit_log.event(f"{tid} entry {n}")
    async def check():
        await asyncio.gather(*(job(tid) for tid in ids))
    asyncio.run(check())
    audit_log.event("outside an audit")
    for tid in ids:
        entries = [json.loads(line) for line in client.lrange(audit_log.log_key(tid), 0, -1)]
        assert len(entries) == 4
        assert all(entry["message"].startswith(tid) for entry in entries)
        assert len({e["id"] for e in entries}) == 4


def test_activity_is_bounded_expires_and_sanitizes_control_characters(activity_store):
    client, ids, _ = activity_store
    with audit_log.audit_activity(ids[0]):
        for n in range(audit_log.MAX_ENTRIES + 10):
            audit_log.event(f"event {n}")
        audit_log.event("a\n\r\x1b" + "x" * 1000)
    entries = [json.loads(line) for line in client.lrange(audit_log.log_key(ids[0]), 0, -1)]
    assert len(entries) == audit_log.MAX_ENTRIES
    assert entries[0]["message"] == "event 11"
    assert len(entries[-1]["message"]) == 600
    assert all(ord(c) >= 32 for c in entries[-1]["message"])
    assert 0 < client.ttl(audit_log.log_key(ids[0])) <= audit_log.LOG_TTL


def test_activity_failure_does_not_fail_or_repeatedly_delay_audit(monkeypatch):
    client = Mock()
    client.pipeline.side_effect = redis.ConnectionError("fixture unavailable")
    monkeypatch.setattr(audit_log.Redis, "from_url", lambda *a, **kw: client)
    with audit_log.audit_activity("test"):
        audit_log.event("first")
        audit_log.event("second")
    client.pipeline.assert_called_once()
    client.close.assert_called_once()
    assert audit_log._current.get() is None


def test_task_success_and_failure_record_outcome_and_clear_context(activity_store, monkeypatch):
    client, ids, _ = activity_store
    monkeypatch.setattr(report_task, "_async_run_report", AsyncMock(return_value={"done": True}))
    report_task.run_report.push_request(id=ids[0])
    try:
        assert report_task.run_report.run("unused", "Fixture") == {"done": True}
    finally:
        report_task.run_report.pop_request()
    monkeypatch.setattr(report_task, "_async_run_report", AsyncMock(side_effect=RuntimeError("private raw failure")))
    report_task.run_report.push_request(id=ids[1])
    try:
        with pytest.raises(RuntimeError):
            report_task.run_report.run("unused", "Fixture")
    finally:
        report_task.run_report.pop_request()
    assert audit_log._current.get() is None
    good = client.lrange(audit_log.log_key(ids[0]), 0, -1)
    bad = client.lrange(audit_log.log_key(ids[1]), 0, -1)
    assert json.loads(good[-1])["level"] == "success"
    assert json.loads(bad[-1])["level"] == "error"
    assert "private raw failure" not in "".join(bad)


def test_read_activity_ignores_corrupt_entries(activity_store):
    client, ids, url = activity_store
    with audit_log.audit_activity(ids[0]):
        audit_log.event("valid")
    client.rpush(audit_log.log_key(ids[0]), "invalid json", "{}", "null")
    async def check():
        reader = aioredis.from_url(url)
        try:
            return await audit_log.read_activity(reader, ids[0])
        finally:
            await reader.aclose()
    assert [e["message"] for e in asyncio.run(check())] == ["valid"]


def test_status_requires_auth_before_reading_any_task(monkeypatch):
    result = Mock()
    monkeypatch.setattr(reports.celery_app, "AsyncResult", result)
    response = asyncio.run(reports.get_status("private", request(False)))
    assert response.status_code == 401
    assert response.headers["HX-Redirect"] == "/login"
    result.assert_not_called()


@pytest.mark.parametrize("state", ["PROGRESS", "FAILURE", "REVOKED"])
def test_status_renders_only_selected_task_and_escapes_messages(monkeypatch, state):
    raw = json.dumps({"id": "one", "time": "12:34:56", "level": "warning", "message": "<script>alert(1)</script>"})
    store = SimpleNamespace(lrange=AsyncMock(return_value=[raw]), aclose=AsyncMock())
    monkeypatch.setattr(reports, "_redis", AsyncMock(return_value=store))
    monkeypatch.setattr(reports.celery_app, "AsyncResult", lambda tid: SimpleNamespace(state=state, info={"pct": 30, "step": "Collecting"}))
    response = asyncio.run(reports.get_status("selected", request()))
    html = response.body.decode()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert '<script>alert' not in html
    assert ('hx-trigger="every 2s"' in html) == (state == "PROGRESS")
    store.lrange.assert_awaited_once_with(audit_log.log_key("selected"), -audit_log.MAX_ENTRIES, -1)
    store.aclose.assert_awaited_once()


def test_status_keeps_polling_when_activity_is_unavailable(monkeypatch):
    monkeypatch.setattr(reports, "_redis", AsyncMock(side_effect=redis.ConnectionError()))
    monkeypatch.setattr(reports.celery_app, "AsyncResult", lambda tid: SimpleNamespace(state="PROGRESS", info={"pct": 42, "step": "Fetching traffic"}))
    response = asyncio.run(reports.get_status("test", request()))
    html = response.body.decode()
    assert "42%" in html and 'hx-trigger="every 2s"' in html
    assert "Activity is temporarily unavailable" in html


def test_full_pipeline_records_property_progress_without_changing_results(activity_store, monkeypatch, tmp_path):
    client, ids, url = activity_store
    settings = SimpleNamespace(redis_url=url, edgerc_path="unused", edgerc_section="default", edgerc_reporting_section="reporting", concurrency_limit=2, reports_base_dir=str(tmp_path))
    monkeypatch.setattr(report_task, "get_settings", lambda: settings)
    monkeypatch.setattr(report_task, "auth_from_edgerc", lambda *args: ("https://unused.test", None))
    class Api:
        def __init__(self, *args): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get_groups(self, *args):
            return {"groups":{"items":[{"groupId":"g1","groupName":"Example group","contractIds":["c1"]}]}}
        async def get_properties(self, *args):
            return {"properties":{"items":[{"propertyId":"one","propertyName":"First"},{"propertyId":"two","propertyName":"Second"}]}}
    monkeypatch.setattr(report_task, "AkamaiClient", Api)
    monkeypatch.setattr(report_task, "_process_property", AsyncMock(side_effect=[{"id":"one","name":"First","cpcodes":[]}, None]))
    def excel(source, output):
        from pathlib import Path
        Path(output).write_text("test workbook")
    monkeypatch.setattr(report_task, "generate_excel", excel)
    task = SimpleNamespace(request=SimpleNamespace(id=ids[0]), update_state=Mock())
    try:
        with audit_log.audit_activity(ids[0]):
            result = asyncio.run(report_task._async_run_report(task, "unused", "Fixture"))
        from pathlib import Path
        saved = json.loads(Path(result["json_path"]).read_text())
        assert [p["id"] for g in saved["report"] for p in g["properties"]] == ["one"]
        entries = [json.loads(line) for line in client.lrange(audit_log.log_key(ids[0]), 0, -1)]
        assert any("Analysed 1/2" in e["message"] for e in entries)
        assert any("Analysed 2/2" in e["message"] and e["level"] == "warning" for e in entries)
        percentages = [call.kwargs["meta"]["pct"] for call in task.update_state.call_args_list]
        assert percentages == sorted(percentages)
    finally:
        client.delete("task:" + ids[0])


def test_retry_events_report_wait_without_raw_responses(monkeypatch):
    from test_api_rate_limit import fake_client
    import httpx
    from app.services import akamai_client
    events = []
    monkeypatch.setattr(akamai_client, "event", lambda message, level="info": events.append(message))
    async def check():
        api, _ = fake_client([httpx.Response(429, headers={"Retry-After":"90"}, text="sensitive raw body"), httpx.Response(200, json={"groups":[]})])
        try:
            await api.get_groups("private-account-key")
        finally:
            await api._client.aclose()
    asyncio.run(check())
    assert any("90s" in message and "Retry" in message for message in events)
    assert all("private-account-key" not in message and "sensitive raw body" not in message for message in events)


def test_deleting_report_removes_its_activity(monkeypatch):
    from test_report_deletion import FakeRedis, FakePipeline
    store = FakeRedis({"finished":{"account_name":"Fixture"}})
    deleted = []
    def record_delete(self, key):
        deleted.append(key)
        return self
    monkeypatch.setattr(FakePipeline, "delete", record_delete)
    monkeypatch.setattr(reports, "_redis", AsyncMock(return_value=store))
    monkeypatch.setattr(reports.celery_app, "AsyncResult", lambda tid: SimpleNamespace(state="SUCCESS"))
    monkeypatch.setattr(reports, "_delete_report_files", lambda *args: None)
    result = asyncio.run(reports._delete_tasks(["finished"]))
    assert result["deleted_ids"] == ["finished"]
    assert audit_log.log_key("finished") in deleted
