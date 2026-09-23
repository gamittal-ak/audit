"""Browser regressions against a local, synthetic report. Never calls audit APIs."""
import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape

ROOT = Path(__file__).resolve().parents[1]
ENV = Environment(loader=FileSystemLoader(str(ROOT / "app/templates")), autoescape=select_autoescape())

def report_context(legacy=False):
    def prop(name, ident, hostname, days):
        return dict(name=name,id=ident,productionVersion=4,stagingVersion=5,
                    origin=["origin." + hostname],hostnames=[dict(cnameFrom=hostname,cnameTo=hostname+".edgekey.net",map="a123",type="ESSL",slot="123",cert={"expiration":"Oct 12 12:00:00 2026 GMT","issuer":"Example CA"})],
                    cpcodes=[dict(cpcode=[12345 if ident=="prp_1" else 67890],description=["Website delivery"],product=["Ion"],traffic={"bytesOffload":0 if ident=="prp_1" else 95,"cacheHitPct":90,"edgeBytes":100,"originBytes":20,"midgressBytes":10})],
                    cert_expiry_days=days,cert_expiry="Oct 12 12:00:00 2026 GMT",cert_type="DV",cert_issuer="Example CA",min_tls="TLS 1.2",
                    last_activated="2026-09-20T12:00:00Z",activated_by="Audit operator",adv_override_exists=False,custom_override_exists=False,count_custom_behavior=0,sro=False,site_shield="",CW_QR=[])
    groups = [
      dict(groupname="Digital platforms",groupid=1,contractid="ctr_ABC",properties=[prop("www.example.com","prp_1","www.example.com",12),prop("api.example.com","prp_2","api.example.com",120)]),
      dict(groupname="Media delivery",groupid=2,contractid="ctr_ABC",properties=[prop("video.example.com","prp_3","video.example.com",80)]),
      dict(groupname="Unused group",groupid=3,contractid="ctr_ABC",properties=[])]
    origins=[]; certs=[]; actions=[]
    for i in range(60):
        host=f"origin-{i}.example.com"
        origins.append(dict(property_name="www.example.com",property_id="prp_1",property_version=4,akamai_network="PRODUCTION",rule_path="default / Delivery",resolved_hostname=host,origin_hostname=host,origin_type="CUSTOMER",uses_https=True,effective_sni=host,trust_description="Platform trust store",observation_status="unreachable" if i==2 else "observed"))
        certs.append(dict(origin_hostname=host,property_name="www.example.com",akamai_network="PRODUCTION",source="live_leaf",subject_cn=host,issuer_org="Example CA",issuer_cn="Example CA",not_after="2026-10-12T00:00:00Z",days_remaining=-2 if i==0 else 12 if i==1 else 100,is_expired=i==0,is_not_yet_valid=False,key_algorithm="RSA",key_size=2048,sha256_fingerprint="ABCD"*16))
    for i in range(2):
        actions.append(dict(severity="critical" if i==0 else "warning",property_name="www.example.com",origin_hostname=f"origin-{i}.example.com",akamai_network="PRODUCTION",finding="Certificate expired" if i==0 else "Certificate expires soon",days_remaining=-2 if i==0 else 12,recommendation="Renew the origin certificate and verify the deployed chain."))
    return dict(request=None,account_name="Example Digital",task_id="demo",report=groups,
       chart_json=json.dumps({"properties":[p for g in groups for p in g["properties"]]}),
       origin_coverage={} if legacy else dict(total_origins=60,probed=59,http_only=0,unreachable=1,skipped=0,unresolved=0,expired=1,expiring_30d=1,actions_critical=1,actions_warning=1),
       origin_inventory=[] if legacy else origins,origin_certificates=[] if legacy else certs,origin_actions=[] if legacy else actions)

def renewal_context():
    from test_origin_lifecycle import saved_report
    from app.services.origin_findings import prepare_origin_report
    context=report_context()
    data=prepare_origin_report(saved_report())
    for key in ("origin_inventory","origin_certificates","origin_coverage","origin_findings_summary","audit_timestamp"):
        context[key]=data[key]
    context["origin_actions"]=data["origin_action_groups"]
    return context

def task_context():
    tasks=[dict(task_id="one",account_name="Example Digital",started_at="2026-09-21 15:40 UTC",cancelled=False,state="SUCCESS",pct=100,step=""),
           dict(task_id="two",account_name="Media Network",started_at="2026-09-21 14:30 UTC",cancelled=False,state="SUCCESS",pct=100,step=""),
           dict(task_id="three",account_name="Active Account",started_at="2026-09-21 16:00 UTC",cancelled=False,state="PROGRESS",pct=48,step="Collecting origin certificates")]
    return dict(tasks=tasks,any_running=True,request=None)

def test_templates_render_legacy_empty_and_new_reports():
    for legacy in (False,True):
        result=ENV.get_template("partials/report_view.html").render(**report_context(legacy))
        assert 'id="properties-panel"' in result
        assert 'id="origins-panel"' in result
        if legacy:
            assert "Origin data was not collected" in result
        else:
            assert "Origin certificate findings" in result
    ctx=report_context(True); ctx["report"]=[]; ctx["chart_json"]='{"properties":[]}'
    ENV.get_template("partials/report_view.html").render(**ctx)
    for name in ENV.list_templates():
        ENV.get_template(name)

@pytest.fixture(scope="module")
def preview_server():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_GET(self):
            path=urlparse(self.path).path
            if path.startswith("/static/"):
                file=ROOT/"app"/path.lstrip("/")
                if not file.is_file(): self.send_error(404); return
                body=file.read_bytes()
                kind="text/css" if path.endswith(".css") else "application/javascript"
            else:
                kind="text/html; charset=utf-8"
                if path=="/":
                    body=ENV.get_template("index.html").render(request=None).encode()
                elif path=="/api/tasks/recent":
                    body=ENV.get_template("partials/task_list.html").render(**task_context()).encode()
                elif path=="/api/accounts/search":
                    kind="application/json"
                    body=json.dumps([{"accountName":"Example Digital","accountSwitchKey":"account-123"}]).encode()
                elif path.startswith("/report/"):
                    body=ENV.get_template("report.html").render(request=None,task_id=path.split("/")[-1]).encode()
                elif path.startswith("/api/reports/"):
                    body=ENV.get_template("partials/report_view.html").render(**(renewal_context() if "renewal" in path else report_context("legacy" in path))).encode()
                else:
                    self.send_error(404); return
            self.send_response(200);self.send_header("Content-Type",kind);self.end_headers();self.wfile.write(body)
        def do_POST(self):
            # Tests cannot delete real reports.
            data=json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            body=json.dumps({"ok":True,"deleted_ids":data["task_ids"],"deleted":len(data["task_ids"]),"failed":[]}).encode()
            self.send_response(200);self.send_header("Content-Type","application/json");self.end_headers();self.wfile.write(body)
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()

@pytest.fixture(scope="module")
def browser():
    playwright=pytest.importorskip("playwright.sync_api")
    with playwright.sync_playwright() as manager:
        browser=manager.chromium.launch(args=["--no-sandbox"])
        yield browser
        browser.close()

def test_report_navigation_search_origins_and_mobile(browser,preview_server):
    page=browser.new_page(viewport={"width":1440,"height":1000},ignore_https_errors=True)
    errors=[];page.on("pageerror",lambda error:errors.append(str(error)))
    page.goto(preview_server+"/report/demo")
    page.wait_for_selector('[data-initialized="true"]')
    assert page.locator("#properties-panel").is_visible()
    assert not page.locator("#origins-panel").is_visible()
    before=page.locator("#group-2").evaluate("(el)=>el.classList.contains('show')")
    page.locator("#propSearch").fill("video.example.com")
    assert page.locator('[data-property]:visible').count()==1
    assert "Hostname:" in page.locator(".property-match:visible").inner_text() or "Property:" in page.locator(".property-match:visible").inner_text()
    page.locator("#propSearchScope").select_option("Hostname")
    page.locator(".property-summary:visible").click()
    assert page.locator('[data-property]:visible [id$="-hn"]').is_visible()
    assert page.locator(".search-highlight:visible").count()>0
    page.locator("#propSearchClear").click()
    assert page.locator("#group-2").evaluate("(el)=>el.classList.contains('show')")==before
    page.locator("#propSearch").fill("nothing-matches-here")
    assert page.locator("#noResultsMsg").is_visible()
    page.locator("#noResultsMsg button").click()
    page.get_by_role("button",name="Origin certificate findings",exact=False).click()
    assert page.locator("#origin-actions").is_visible()
    page.locator("#origin-actions .origin-filter").select_option("critical")
    assert page.locator("#origin-actions [data-origin-row]:visible").count()==1
    page.locator("#origin-inventory-tab").click()
    page.locator("#origin-inventory .origin-search").fill("origin-23.")
    assert page.locator("#origin-inventory [data-origin-row]:visible").count()==1
    page.locator("#origin-certificates-tab").click()
    page.locator("#origin-certificates .origin-filter").select_option("expired")
    assert page.locator("#origin-certificates [data-origin-row]:visible").count()==1
    page.locator("#origin-certificates .origin-filter").select_option("")
    page.locator("#origin-certificates").get_by_role("button",name="Sort by Days",exact=True).click()
    assert page.locator("#origin-certificates tbody tr").first.locator("td").nth(6).inner_text()=="-2"
    page.screenshot(path="/tmp/audit-ui-origins-desktop.png",full_page=True)
    page.locator("#properties-tab").click()
    page.locator(".property-summary").first.click()
    page.screenshot(path="/tmp/audit-ui-report-desktop.png",full_page=True)
    page.locator("#traffic-tab").click()
    page.wait_for_timeout(300)
    assert page.locator("#chartTopEdge").bounding_box()["width"]>100
    page.set_viewport_size({"width":390,"height":844})
    page.locator("#origins-tab").click()
    page.screenshot(path="/tmp/audit-ui-report-mobile.png",full_page=True)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    page.goto(preview_server+"/report/legacy")
    page.wait_for_selector('[data-initialized="true"]')
    page.locator("#origins-tab").click()
    assert page.get_by_text("Origin data was not collected",exact=True).is_visible()
    assert not errors,errors
    page.close()

def test_history_selection_refresh_filter_and_delete(browser,preview_server):
    page=browser.new_page(viewport={"width":1440,"height":1000},ignore_https_errors=True)
    errors=[];page.on("pageerror",lambda error:errors.append(str(error)))
    page.goto(preview_server+"/")
    page.wait_for_selector(".task-item")
    page.locator('.task-cb[value="one"]').check()
    # Exercise the same fragment refresh as the five-second poll.
    page.evaluate("htmx.ajax('GET','/api/tasks/recent',{target:'#task-list',swap:'outerHTML'})")
    page.wait_for_timeout(500)
    assert page.locator('.task-cb[value="one"]').is_checked()
    page.locator("#filter-account").fill("Media")
    assert page.locator(".task-item:visible").count()==1
    assert page.locator(".task-cb:checked").count()==0
    page.locator("#select-all").check()
    page.locator("#btn-delete-sel").click()
    assert page.locator("#delete-dialog").is_visible()
    assert "Media Network" in page.locator("#delete-list").inner_text()
    assert "Example Digital" not in page.locator("#delete-list").inner_text()
    page.get_by_role("button",name="Keep reports").click()
    page.locator("#filter-account").fill("")
    page.locator("#search-input").fill("Example")
    page.wait_for_selector(".account-result")
    assert page.get_by_role("button",name="Run audit").is_visible()
    assert page.locator('[name="traffic_days"]').input_value()=="15"
    page.screenshot(path="/tmp/audit-ui-home-desktop.png",full_page=True)
    # Failure leaves confirmation and selection available for retry.
    page.locator('.task-cb[value="one"]').check()
    page.locator("#btn-delete-sel").click()
    page.route("**/api/tasks/delete-selected",lambda route:route.fulfill(status=503,content_type="application/json",body='{"error":"Deletion temporarily unavailable."}'))
    page.locator("#delete-confirm").click()
    page.wait_for_selector("#delete-error:visible")
    assert page.locator("#delete-dialog").is_visible()
    page.unroute("**/api/tasks/delete-selected")
    page.locator("#delete-confirm").click()
    page.wait_for_selector("#history-message:visible")
    assert "1 report deleted" in page.locator("#history-message").inner_text()
    page.set_viewport_size({"width":390,"height":844})
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    page.screenshot(path="/tmp/audit-ui-home-mobile.png",full_page=True)
    assert not errors,errors
    page.close()

def test_grouped_renewal_review_is_neutral_and_references_are_searchable(browser,preview_server):
    page=browser.new_page(viewport={"width":1440,"height":1000},ignore_https_errors=True)
    errors=[];page.on("pageerror",lambda error:errors.append(str(error)))
    page.goto(preview_server+"/report/renewal")
    page.wait_for_selector('[data-initialized="true"]')
    banner=page.get_by_role("button",name="Origin certificate findings",exact=False)
    assert "0 critical" in banner.inner_text() and "1 renewal review" in banner.inner_text()
    assert "coverage" in banner.get_attribute("class")
    banner.click()
    rows=page.locator("#origin-actions [data-origin-row]")
    assert rows.count()==1 and "table-warning" not in (rows.first.get_attribute("class") or "")
    assert "Short-lived certificate" in rows.first.inner_text()
    assert "live_leaf" not in rows.first.locator(".finding-description > strong").inner_text()
    page.locator("#origin-actions .finding-details summary").click()
    assert page.locator(".finding-references li:visible").count()==3
    assert "default > VOD-DR" in rows.first.inner_text()
    page.locator("#origin-actions .origin-search").fill("VOD-DR")
    assert page.locator("#origin-actions [data-origin-row]:visible").count()==1
    page.locator("#origin-actions .origin-filter").select_option("warning")
    assert page.locator("#origin-actions [data-origin-row]:visible").count()==0
    page.locator("#origin-actions").get_by_role("button",name="Reset",exact=True).click()
    page.screenshot(path="/tmp/audit-renewal-findings.png",full_page=True)
    page.locator("#origin-certificates-tab").click()
    page.locator("#origin-certificates .origin-filter").select_option("renewal-review")
    assert page.locator("#origin-certificates [data-origin-row]:visible").count()==3
    assert page.locator("#origin-certificates tr.table-warning").count()==0
    assert "does not validate its trust chain" in page.locator("#origins-panel").inner_text()
    page.set_viewport_size({"width":390,"height":844})
    page.wait_for_function("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not errors,errors
    page.close()


def test_live_activity_polling_scroll_retention_and_mobile(browser, preview_server):
    page = browser.new_page(viewport={"width":1440,"height":1000}, ignore_https_errors=True)
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    state = {"start":0,"end":90,"done":False}
    def activity_response(route):
        if state["done"]:
            body = ENV.get_template("partials/report_view.html").render(**report_context())
        else:
            body = ENV.get_template("partials/progress.html").render(
                request=None,task_id="live",pct=42,step="Analysing properties",
                logs_available=True,log_limit=300,
                activity=[dict(id=str(i),time="12:34:56",level="warning" if i%10==0 else "info",
                message=f"Property {i}: checking configuration and certificates" + (" - waiting for shared API budget" if i%10==0 else "")) for i in range(state["start"],state["end"])])
        route.fulfill(status=200,content_type="text/html",body=body)
    page.route("**/api/reports/live/status", activity_response)
    page.goto(preview_server + "/report/live")
    page.wait_for_selector('#audit-log-output[data-initialized="true"]')
    log = page.locator("#audit-log-output")
    assert log.evaluate("el => el.scrollHeight - el.clientHeight - el.scrollTop") < 2
    # A real HTMX status refresh adds a new entry and continues following it.
    state["end"] = 91
    page.wait_for_selector('[data-log-id="90"]')
    assert log.evaluate("el => el.scrollHeight - el.clientHeight - el.scrollTop") < 2
    page.screenshot(path="/tmp/audit-ui-live-logs-desktop.png", full_page=True)
    # Reading older lines must survive a poll, including removal of older entries.
    log.evaluate("el => el.scrollTop = 700")
    page.wait_for_function("document.getElementById('audit-log-follow').getAttribute('aria-pressed') === 'false'")
    anchor = log.evaluate("el => {const l=Array.from(el.children).find(x=>x.offsetTop-el.offsetTop+x.offsetHeight>el.scrollTop); return {id:l.dataset.logId,offset:l.offsetTop-el.offsetTop-el.scrollTop}}")
    state["start"] = 5
    state["end"] = 92
    page.wait_for_selector('[data-log-id="91"]')
    offset = page.locator('[data-log-id="'+anchor["id"]+'"]').evaluate("el=>el.offsetTop-document.getElementById('audit-log-output').offsetTop-document.getElementById('audit-log-output').scrollTop")
    assert abs(offset-anchor["offset"]) < 2
    assert page.locator("#audit-log-follow").get_attribute("aria-pressed") == "false"
    page.get_by_role("button", name="Follow latest").click()
    assert log.evaluate("el => el.scrollHeight - el.clientHeight - el.scrollTop") < 2
    # Pausing explicitly also survives refresh without disturbing button focus.
    page.get_by_role("button", name="Auto-scroll on").click()
    state["end"] = 93
    page.wait_for_selector('[data-log-id="92"]')
    assert page.locator("#audit-log-follow").get_attribute("aria-pressed") == "false"
    assert page.evaluate("document.activeElement.id") == "audit-log-follow"
    page.set_viewport_size({"width":390,"height":844})
    page.screenshot(path="/tmp/audit-ui-live-logs-mobile.png", full_page=True)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    state["done"] = True
    page.wait_for_selector("#properties-panel")
    assert page.locator("#audit-log-output").count() == 0
    assert not page.locator("#report-content").get_attribute("hx-trigger")
    assert not errors, errors
    page.close()
