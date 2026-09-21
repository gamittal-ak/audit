"""Deletion regressions use fake Redis/Celery and temporary files only."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from app.routers import reports

class FakePipeline:
    def __init__(self, store): self.store=store; self.ids=[]
    async def __aenter__(self): return self
    async def __aexit__(self,*args): pass
    def zrem(self,key,tid): self.ids.append(tid); return self
    def delete(self,key): return self
    async def execute(self): self.store.removed.extend(self.ids)

class FakeRedis:
    def __init__(self, meta): self.meta=meta; self.removed=[]; self.closed=False
    async def hgetall(self,key): return self.meta.get(key.split(":",1)[1],{})
    def pipeline(self,transaction=True): return FakePipeline(self)
    async def aclose(self): self.closed=True

def test_delete_reports_preserves_failures_and_running_tasks(monkeypatch):
    store=FakeRedis({key:{"account_name":"Example"} for key in ("good","bad","running")})
    monkeypatch.setattr(reports,"_redis",AsyncMock(return_value=store))
    monkeypatch.setattr(reports.celery_app,"AsyncResult",lambda tid:SimpleNamespace(state="PROGRESS" if tid=="running" else "SUCCESS"))
    calls=[]
    def clean(tid,meta):
        calls.append(tid)
        if tid=="bad": raise OSError("fixture failure")
    monkeypatch.setattr(reports,"_delete_report_files",clean)
    result=asyncio.run(reports._delete_tasks(["good","bad","running","missing","good"]))
    assert result["deleted_ids"]==["good"]
    assert {item["task_id"] for item in result["failed"]}=={"bad","running","missing"}
    assert calls==["good","bad"]
    assert store.removed==["good"] and store.closed

def test_delete_expired_celery_result_uses_stored_report(monkeypatch,tmp_path):
    json_file=tmp_path/"report.json";json_file.write_text("{}")
    store=FakeRedis({"saved":{"json_path":str(json_file)}})
    monkeypatch.setattr(reports,"_redis",AsyncMock(return_value=store))
    monkeypatch.setattr(reports.celery_app,"AsyncResult",lambda tid:SimpleNamespace(state="PENDING"))
    monkeypatch.setattr(reports,"_delete_report_files",lambda *args:None)
    result=asyncio.run(reports._delete_tasks(["saved"]))
    assert result["deleted_ids"]==["saved"]

def test_report_file_cleanup_removes_pair_and_rejects_outside_paths(monkeypatch,tmp_path):
    report_dir=tmp_path/"reports";report_dir.mkdir()
    report=report_dir/"report_sample.json";report.write_text("{}")
    workbook=report.with_suffix(".xlsx");workbook.write_bytes(b"fixture")
    outside=tmp_path/"unrelated.json";outside.write_text("{}")
    forgotten=[]
    result=SimpleNamespace(info={},forget=lambda:forgotten.append(True))
    monkeypatch.setattr(reports,"get_settings",lambda:SimpleNamespace(reports_base_dir=str(report_dir)))
    monkeypatch.setattr(reports.celery_app,"AsyncResult",lambda tid:result)
    with pytest.raises(ValueError):
        reports._delete_report_files("bad",{"json_path":str(outside)})
    assert outside.exists() and not forgotten
    reports._delete_report_files("good",{"json_path":str(report)})
    assert not report.exists() and not workbook.exists()
    assert forgotten==[True]

def test_cleanup_errors_are_not_reported_as_success(monkeypatch,tmp_path):
    report_dir=tmp_path/"reports";report_dir.mkdir()
    report=report_dir/"report_sample.json";report.write_text("{}")
    monkeypatch.setattr(reports,"get_settings",lambda:SimpleNamespace(reports_base_dir=str(report_dir)))
    monkeypatch.setattr(reports.celery_app,"AsyncResult",lambda tid:SimpleNamespace(info={},forget=lambda:None))
    def fail(*args,**kwargs): raise PermissionError("fixture")
    monkeypatch.setattr(Path,"unlink",fail)
    with pytest.raises(PermissionError):
        reports._delete_report_files("bad",{"json_path":str(report)})

def test_delete_requires_session_and_valid_payload():
    class Request:
        def __init__(self,session,body): self.session=session;self.body=body
        async def json(self): return self.body
    response=asyncio.run(reports.delete_selected_tasks(Request({},{"task_ids":["one"]})))
    assert response.status_code==401
    for payload in ({},[],{"task_ids":"one"},{"task_ids":[None]}):
        response=asyncio.run(reports.delete_selected_tasks(Request({"authenticated":True},payload)))
        assert response.status_code==400
