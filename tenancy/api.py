"""
===================================================================
نقاط وصول المنصة (/api/v1) — كل شيء داخل سياق المنشأة
===================================================================
المنشأة تُستنتج من المفتاح فقط (auth.dashboard_tenant)، ولا تأخذ أي نقطة
معرّف منشأة من الرابط أو الجسم. التحقيقات مفهرسة بـ (المنشأة، الحادثة)،
وحادثة منشأة أخرى ترجع 404 حتى لا يُكشف وجودها. أدوات الوكيل تُبنى فوق
بيانات المنشأة، وجدارها المحاكى يأخذ قائمة السماح من إعداداتها.
===================================================================
"""

import ipaddress
import json
import random
import secrets
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse, urlsplit

import anthropic
import pandas as pd
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sandbox_firewall import SimulatedFirewall

from agent.analyst import MODEL, AgentError, chat, proposal_public, run_investigation
from agent.log_tools import LogWorkspace
from agent.scenarios import ATTACK_FAMILIES, build_incident
from agent.store import Run
from agent.tools import ENFORCING, ToolError, Workspace, decide
from campaign.linker import link
from campaign.workspace import CampaignWorkspace, campaign_view
from ingest.anomaly import AnomalyDetector
from ingest.pipeline import SOURCES, process_batch
from monitor.service import Monitor
from netdetect.detect import forecast, process_flows
from netdetect.validate import MAX_COMPRESSED, BatchError, decompress, validate
from netdetect.workspace import NetWorkspace
from notify.service import Notifier, enabled_channels
from tenancy.approvals import ApprovalTokens
from tenancy.auth import RateLimiter, StreamTokens, dashboard_tenant, ingest_tenant
from tenancy.registry import Registry
from tenancy.store import TenantStore


@dataclass
class Platform:
    registry: Registry
    store: TenantStore
    resources: Callable          # () -> agent.tools.Resources
    act_sample: pd.DataFrame
    windows: pd.DataFrame
    client: Callable             # () -> عميل Claude أو DemoClient
    live: Callable               # () -> هل يوجد مفتاح Claude
    tokens: StreamTokens = field(default_factory=StreamTokens)
    signups: RateLimiter = field(default_factory=RateLimiter)
    ingests: RateLimiter = field(default_factory=lambda: RateLimiter(limit=60, window=60))
    runs: dict = field(default_factory=dict)        # (tenant_id, incident_id) -> Run
    current: dict = field(default_factory=dict)     # tenant_id -> incident_id
    queues: dict = field(default_factory=dict)      # tenant_id -> طابور حوادث السجلات
    lock: threading.Lock = field(default_factory=threading.Lock)
    tenant_locks: dict = field(default_factory=dict)  # tenant_id -> قفل معالجة الدفعات
    notifier: Notifier = None
    approvals: ApprovalTokens = None
    public_url: str = "http://localhost:8001"     # روابط الموافقة تُبنى منه
    allow_private_webhooks: bool = True             # False في أي نشر (حماية من SSRF)
    allow_private_targets: bool = True              # مواقع المراقبة الداخلية؛ False في أي نشر
    monitor: Monitor = None

    def __post_init__(self):
        self.notifier = self.notifier or Notifier(self.store)
        self.approvals = self.approvals or ApprovalTokens(self.registry.path)
        self.monitor = self.monitor or Monitor(self.store, self.notifier, allow_private=self.allow_private_targets)
        self.notifier.on_result = lambda tid, data, response: _executor_result(self, tid, data, response)
        self.monitor.on_incident = lambda tid, incident_id: _link(self, tid, incident_id)


MAX_INGEST_BYTES = 5 * 1024 * 1024
MAX_INGEST_LINES = 20_000


class SignupReq(BaseModel):
    name: str


class SettingsReq(BaseModel):
    webhook_url: str | None = None
    allowlist: list[str] = []
    telegram_token: str | None = None       # None = بلا تغيير، "" = مسح
    telegram_chat_id: str | None = None


class TestReq(BaseModel):
    channel: str


class IncidentReq(BaseModel):
    incident_id: str


class DecideReq(IncidentReq):
    proposal_id: int
    decision: str


class ChatReq(IncidentReq):
    message: str


router = APIRouter(prefix="/api/v1")


def _platform(request: Request) -> Platform:
    return request.app.state.platform


def _run(p, tenant, incident_id):
    run = p.runs.get((tenant.id, incident_id))
    if run is None:
        raise HTTPException(404, "حادثة غير موجودة")
    return run


# ===================================================================
# المنشأة
# ===================================================================
@router.post("/tenants", status_code=201)
def signup(req: SignupReq, request: Request):
    p = _platform(request)
    if not p.signups.allow(request.client.host if request.client else "unknown"):
        raise HTTPException(429, "محاولات تسجيل كثيرة، حاول بعد ساعة")
    try:
        tenant, keys = p.registry.create(req.name)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    p.store.dir(tenant.id)
    return {"tenant_id": tenant.id, "name": tenant.name, **keys}


def _public_settings(s):
    """الإعدادات كما تُعرض: رمز Telegram مُقنّع ولا يُرجع كاملًا أبدًا."""
    token = s.get("telegram_token")
    return {"webhook_url": s.get("webhook_url"), "allowlist": s.get("allowlist", []),
            "webhook_secret": s.get("webhook_secret"), "telegram_chat_id": s.get("telegram_chat_id"),
            "telegram_token": ("••••" + token[-4:]) if token else None}


def _resolves_private(url):
    try:
        infos = socket.getaddrinfo(urlsplit(url).hostname, None)
    except (socket.gaierror, UnicodeError):
        return True
    return any(ipaddress.ip_address(i[4][0]).is_private or ipaddress.ip_address(i[4][0]).is_loopback
               or ipaddress.ip_address(i[4][0]).is_link_local for i in infos)


@router.get("/me")
def me(request: Request, tenant=Depends(dashboard_tenant)):
    return {"tenant_id": tenant.id, "name": tenant.name, "created_at": tenant.created_at,
            "settings": _public_settings(_platform(request).store.settings(tenant.id))}


@router.put("/settings")
def update_settings(req: SettingsReq, request: Request, tenant=Depends(dashboard_tenant)):
    url = (req.webhook_url or "").strip() or None
    if url:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise HTTPException(422, "رابط الـ Webhook يجب أن يبدأ بـ http:// أو https://")
    allowlist = []
    for ip in (s.strip() for s in req.allowlist):
        if not ip:
            continue
        try:
            allowlist.append(str(ipaddress.ip_address(ip)))
        except ValueError:
            raise HTTPException(422, f"عنوان IP غير صالح: {ip}") from None
    p = _platform(request)
    if url and not p.allow_private_webhooks and _resolves_private(url):
        raise HTTPException(422, "رابط الـ Webhook يشير إلى عنوان داخلي أو لا يمكن الوصول إليه")
    settings = {"webhook_url": url, "allowlist": allowlist}
    if url and not p.store.settings(tenant.id).get("webhook_secret"):
        settings["webhook_secret"] = secrets.token_urlsafe(32)
    if req.telegram_token is not None:
        settings["telegram_token"] = req.telegram_token.strip() or None
    if req.telegram_chat_id is not None:
        settings["telegram_chat_id"] = req.telegram_chat_id.strip() or None
    p.store.save_settings(tenant.id, settings)
    return _public_settings(p.store.settings(tenant.id))


@router.post("/settings/webhook-secret/rotate")
def rotate_webhook_secret(request: Request, tenant=Depends(dashboard_tenant)):
    secret = secrets.token_urlsafe(32)
    _platform(request).store.save_settings(tenant.id, {"webhook_secret": secret})
    return {"webhook_secret": secret}


@router.post("/keys/rotate")
def rotate_keys(request: Request, tenant=Depends(dashboard_tenant)):
    return _platform(request).registry.rotate(tenant.id)


# ===================================================================
# المحلل الذكي داخل سياق المنشأة
# ===================================================================
@router.get("/agent/status")
def agent_status(request: Request, tenant=Depends(dashboard_tenant)):
    p = _platform(request)
    cur = p.runs.get((tenant.id, p.current.get(tenant.id)))
    return {"mode": "live" if p.live() else "demo", "model": MODEL,
            "running": bool(cur and cur.status == "running")}


@router.post("/agent/investigate")
def agent_investigate(request: Request, family: str = "random", tenant=Depends(dashboard_tenant)):
    """حادثة محاكاة في سياق المنشأة. تحقيق واحد في كل مرة لكل منشأة."""
    p = _platform(request)
    cur = p.runs.get((tenant.id, p.current.get(tenant.id)))
    if cur and cur.status == "running":
        return {"incident_id": cur.incident.id, "already_running": True}
    choices = ATTACK_FAMILIES + ["BENIGN"]
    if family == "random":
        family = random.choice(choices)
    if family not in choices:
        raise HTTPException(422, f"نوع غير معروف: {family}")
    inc = build_incident(p.act_sample, p.windows, family, seed=random.randrange(10**6))
    firewall = SimulatedFirewall(allowlist=p.store.settings(tenant.id)["allowlist"])
    ws = Workspace(inc, p.resources(), firewall=firewall)
    run = Run(inc, ws, save_dir=p.store.runs_dir(tenant.id))
    p.runs[(tenant.id, inc.id)] = run
    p.current[tenant.id] = inc.id
    threading.Thread(target=_investigate, args=(p, tenant.id, ws, run), daemon=True).start()
    return {"incident_id": inc.id}


@router.post("/agent/stream-token")
def agent_stream_token(req: IncidentReq, request: Request, tenant=Depends(dashboard_tenant)):
    p = _platform(request)
    _run(p, tenant, req.incident_id)
    return {"token": p.tokens.issue(tenant.id, req.incident_id)}


@router.get("/agent/stream/{incident_id}")
def agent_stream(incident_id: str, token: str, request: Request):
    """خطوات التحقيق كـ Server-Sent Events. المصادقة برمز البث لا بمفتاح اللوحة."""
    p = _platform(request)
    tenant_id = p.tokens.consume(token, incident_id)
    if tenant_id is None:
        raise HTTPException(403, "رمز البث غير صالح أو منتهٍ")
    run = p.runs.get((tenant_id, incident_id))
    if run is None:
        raise HTTPException(404, "حادثة غير موجودة")

    def events():
        sent = 0
        while True:
            batch = run.wait_events(sent, timeout=15)
            if not batch:
                yield ": keep-alive\n\n"
                continue
            for ev in batch:
                yield f"event: {ev['type']}\ndata: {json.dumps(ev, ensure_ascii=False, default=str)}\n\n"
                if ev["type"] == "done":
                    return
            sent += len(batch)

    return StreamingResponse(events(), media_type="text/event-stream")


@router.post("/agent/decide")
def agent_decide(req: DecideReq, request: Request, tenant=Depends(dashboard_tenant)):
    run = _run(_platform(request), tenant, req.incident_id)
    if req.decision not in ("approve", "reject"):
        raise HTTPException(422, "القرار يجب أن يكون approve أو reject")
    try:
        return _apply_decision(_platform(request), tenant.id, run, req.proposal_id, req.decision, "owner")
    except ToolError as e:
        return {"error": str(e)}


@router.post("/agent/chat")
def agent_chat(req: ChatReq, request: Request, tenant=Depends(dashboard_tenant)):
    p = _platform(request)
    run = _run(p, tenant, req.incident_id)
    if run.status == "running":
        return {"error": "المحلل ما زال يحقق، انتظر التقرير"}
    try:
        out = chat(p.client(), run.ws, run, req.message)
    except AgentError as e:
        return {"error": str(e)}
    except anthropic.APIError:
        return {"error": "تعذّر الوصول إلى خدمة Claude"}
    run.save()
    return out


# ===================================================================
# السجلات: الاستقبال والمصادر والحوادث وطابور التحقيق
# ===================================================================
def _investigate(p, tenant_id, ws, run):
    """يشغّل تحقيقًا، ثم يحدّث حالة حادثة السجلات، ويرسل التقرير، ويبدأ التالي في الطابور."""
    try:
        run_investigation(p.client(), ws, run)
        if hasattr(ws, "sync_incident_status"):     # حوادث السجلات والشبكة الحقيقية والحملات
            ws.sync_incident_status()
        joined = run.incident.kind in ("log", "network") and _link(p, tenant_id, run.incident.id)
        if not joined:          # عضو الحملة يصل صاحبه تقرير الحملة برابط موافقة واحد
            _notify_report(p, tenant_id, run)
    finally:
        run.settled.set()
        _start_next(p, tenant_id)


def _link(p, tenant_id, incident_id):
    """يربط الحادثة بحملة (الجزء 6)، ويضيف المنسّق للطابور إذا تغيّرت الحملة. ← معرّف الحملة أو None"""
    with p.lock:
        lock = p.tenant_locks.setdefault(tenant_id, threading.Lock())
    with lock:
        r = link(p.store.logs(tenant_id), incident_id, p.store.settings(tenant_id)["allowlist"])
    for merged in r.merged:
        run = p.runs.get((tenant_id, merged))
        if run is None:
            continue
        for pr in run.ws.proposals.values():
            if pr.status == "pending":
                pr.status, pr.rationale = "merged", f"دُمج في الحملة {r.campaign}"
        run.save()
    if r.changed:
        _enqueue(p, tenant_id, r.campaign)
    return r.campaign


def _start_next(p, tenant_id):
    with p.lock:
        cur = p.runs.get((tenant_id, p.current.get(tenant_id)))
        queue = p.queues.get(tenant_id)
        store = p.store.logs(tenant_id)
        while queue and store.incident(queue[0])["status"] == "merged":     # حملة دُمجت وهي تنتظر
            queue.popleft()
        if (cur and cur.status == "running") or not queue:
            return
        incident_id = queue.popleft()
        allowlist = p.store.settings(tenant_id)["allowlist"]
        kind = store.incident(incident_id)["kind"]
        if kind == "campaign":
            prev = p.runs.get((tenant_id, incident_id))
            ws = CampaignWorkspace(store, incident_id, lambda i: p.runs.get((tenant_id, i)),
                                   p.store.runs_dir(tenant_id), allowlist, previous=prev.ws if prev else None)
        elif kind == "network":
            ws = NetWorkspace(store, p.store.net(tenant_id), incident_id, p.resources(), allowlist)
        else:
            ws = LogWorkspace(store, incident_id, allowlist=allowlist,
                              detector=AnomalyDetector(p.store.anomaly_path(tenant_id)))
        run = Run(ws.incident, ws, save_dir=p.store.runs_dir(tenant_id))
        p.runs[(tenant_id, incident_id)] = run
        p.current[tenant_id] = incident_id
        store.set_incident_status(incident_id, "investigating")
    threading.Thread(target=_investigate, args=(p, tenant_id, ws, run), daemon=True).start()


def _enqueue(p, tenant_id, incident_id):
    with p.lock:
        queue = p.queues.setdefault(tenant_id, deque())
        if incident_id not in queue:
            queue.append(incident_id)
    _start_next(p, tenant_id)


def _process(p, tenant_id, source, text):
    with p.lock:
        lock = p.tenant_locks.setdefault(tenant_id, threading.Lock())
    with lock:      # دفعات المنشأة الواحدة بالتتابع (التدريب وتجميع الحوادث)
        return process_batch(p.store.logs(tenant_id), AnomalyDetector(p.store.anomaly_path(tenant_id)), source, text)


def _process_flows(p, tenant_id, body, encoding):
    batch = validate(decompress(body, encoding), now=time.time())
    with p.lock:
        lock = p.tenant_locks.setdefault(tenant_id, threading.Lock())
    with lock:
        return process_flows(p.store.net(tenant_id), p.store.logs(tenant_id), p.resources(), batch, time.time())


@router.post("/ingest/flows")
async def ingest_flows(request: Request, tenant=Depends(ingest_tenant)):
    """نافذة من وكيل الخادم: JSON (يُفضّل gzip) بملخصات التدفقات. مفتاح الاستقبال فقط."""
    p = _platform(request)
    if int(request.headers.get("content-length") or 0) > MAX_COMPRESSED:
        raise HTTPException(413, "الدفعة أكبر من 5MB")
    if not p.ingests.allow(tenant.id):
        raise HTTPException(429, "دفعات كثيرة، حاول بعد دقيقة")
    body = await request.body()
    if len(body) > MAX_COMPRESSED:
        raise HTTPException(413, "الدفعة أكبر من 5MB")
    try:
        out = await run_in_threadpool(_process_flows, p, tenant.id, body, request.headers.get("content-encoding"))
    except BatchError as e:
        raise HTTPException(e.status, str(e)) from None
    for incident_id, new in out["incidents"].items():
        if new:
            _enqueue(p, tenant.id, incident_id)
    return {"accepted": out["accepted"], "duplicate": out["duplicate"], "alerts_opened": out["alerts"],
            "incident_id": next(iter(out["incidents"]), None)}


@router.post("/ingest/{source}")
async def ingest(source: str, request: Request, tenant=Depends(ingest_tenant)):
    """سطور سجل خام (text/plain). مفتاح الاستقبال فقط."""
    if source not in SOURCES:
        raise HTTPException(404, "مصدر غير معروف: web أو firewall")
    p = _platform(request)
    if int(request.headers.get("content-length") or 0) > MAX_INGEST_BYTES:
        raise HTTPException(413, "الدفعة أكبر من 5MB")
    if not p.ingests.allow(tenant.id):
        raise HTTPException(429, "دفعات كثيرة، حاول بعد دقيقة")
    body = await request.body()
    if len(body) > MAX_INGEST_BYTES:
        raise HTTPException(413, "الدفعة أكبر من 5MB")
    text = body.decode("utf-8", errors="replace")
    if len(text.splitlines()) > MAX_INGEST_LINES:
        raise HTTPException(413, f"الدفعة أكثر من {MAX_INGEST_LINES} سطر")
    out = await run_in_threadpool(_process, p, tenant.id, source, text)
    for incident_id, new in out["incidents"].items():
        if new:
            _enqueue(p, tenant.id, incident_id)
    return {"accepted": out["accepted"], "rejected": out["rejected"], "alerts_opened": out["alerts"],
            "incident_id": next(iter(out["incidents"]), None)}


@router.get("/sources")
def sources(request: Request, tenant=Depends(dashboard_tenant)):
    p = _platform(request)
    store, net, now = p.store.logs(tenant.id), p.store.net(tenant.id), time.time()
    return {**store.source_stats(), "anomaly": AnomalyDetector(p.store.anomaly_path(tenant.id)).status(store),
            "agent": {**net.status(now), "forecast": forecast(net, p.resources(), now)}}


@router.get("/incidents")
def incidents(request: Request, tenant=Depends(dashboard_tenant)):
    store = _platform(request).store.logs(tenant.id)

    def types(inc):
        ids = [m["id"] for m in store.campaign_members(inc["id"])] if inc["kind"] == "campaign" else [inc["id"]]
        return sorted({a["type"] for i in ids for a in store.alerts(i)})
    return {"incidents": [{**inc, "types": types(inc)} for inc in store.incidents()]}


@router.get("/incidents/{incident_id}")
def incident(incident_id: str, request: Request, tenant=Depends(dashboard_tenant)):
    p = _platform(request)
    store = p.store.logs(tenant.id)
    inc = store.incident(incident_id)
    if inc is None:
        raise HTTPException(404, "حادثة غير موجودة")
    run = p.runs.get((tenant.id, incident_id))
    return {"incident": inc, "alerts": store.alerts(incident_id),
            "campaign": campaign_view(store, incident_id) if inc["kind"] == "campaign" else None,
            "investigation": incident_id if run else None,
            "queued": incident_id in p.queues.get(tenant.id, ()),
            "proposals": [proposal_public(pr) for pr in run.ws.proposals.values()] if run else []}


@router.post("/incidents/{incident_id}/investigate")
def reinvestigate(incident_id: str, request: Request, tenant=Depends(dashboard_tenant)):
    """تحقيق (جديد) في حادثة، مثلًا بعد إعادة تشغيل الخادم."""
    p = _platform(request)
    inc = p.store.logs(tenant.id).incident(incident_id)
    if inc is None:
        raise HTTPException(404, "حادثة غير موجودة")
    if inc["kind"] == "monitor":
        raise HTTPException(422, "حوادث المراقبة تُحل بإصلاح الموقع لا بالتحقيق")
    if inc["status"] == "merged":
        raise HTTPException(422, "دُمجت هذه الحملة في حملة أقدم")
    _enqueue(p, tenant.id, incident_id)
    return {"queued": True}


# ===================================================================
# التنبيهات ومسار القرار (الجزء 3)
# ===================================================================
EXECUTOR_AR = {"applied": "نُفّذ على خادمك", "dry_run": "تجربة: لم يُنفَّذ فعليًا",
               "refused": "رفضه خادمك", "duplicate": "وصل خادمك مسبقًا"}


def _tenant_name(p, tenant_id):
    tenant = p.registry.get(tenant_id)
    return tenant.name if tenant else ""


def _notify_report(p, tenant_id, run):
    """incident.report: الملخص والمقترحات المعلّقة، ولكل مقترح رابط موافقة لمرة واحدة."""
    report = run.report or {}
    proposals = [{"id": pr.id, "source_ip": pr.source_ip, "action": pr.action, "duration_min": pr.duration_min,
                  "approve_url": f"{p.public_url}/approve/{p.approvals.issue(tenant_id, run.incident.id, pr.id)}"}
                 for pr in run.ws.proposals.values() if pr.status == "pending" and pr.action in ENFORCING]
    if not proposals and not report:
        return
    p.notifier.emit(tenant_id, "incident.report", {
        "tenant_name": _tenant_name(p, tenant_id), "incident_id": run.incident.id, "kind": run.incident.kind,
        "status": run.status, "severity": report.get("severity", "medium"),
        "summary": report.get("summary_owner") or "توقّف المحلل؛ عرضنا مقترحات القواعد الثابتة في لوحة التحكم.",
        "findings": report.get("findings", []), "stages": report.get("stages", []), "proposals": proposals})


def _apply_decision(p, tenant_id, run, proposal_id, decision, approver):
    """مسار القرار الوحيد (اللوحة ورابط الموافقة): الحاجز ← حالة الحادثة ← التنفيذ ← النتيجة."""
    out = decide(run.ws, proposal_id, decision, approver=approver)
    if hasattr(run.ws, "sync_incident_status"):
        run.ws.sync_incident_status()
    pr = run.ws.proposals[proposal_id]
    if decision == "approve" and pr.status == "applied" and pr.action in ENFORCING:
        p.notifier.emit(tenant_id, "action.execute", {
            "incident_id": run.incident.id, "proposal_id": pr.id, "action": pr.action, "ip": pr.source_ip,
            "duration_min": pr.duration_min, "target": pr.target}, only="webhook")
    p.notifier.emit(tenant_id, "action.result", {
        "tenant_name": _tenant_name(p, tenant_id), "incident_id": run.incident.id, "proposal_id": pr.id,
        "source_ip": pr.source_ip, "action": pr.action, "decision": decision, "status": pr.status,
        "note": out.get("note", "")})
    run.save()
    return out


def _executor_result(p, tenant_id, data, response):
    run = p.runs.get((tenant_id, data.get("incident_id")))
    pr = run.ws.proposals.get(data.get("proposal_id")) if run else None
    if pr is None:
        return
    label = EXECUTOR_AR.get(response.get("status"), str(response.get("status")))
    pr.rationale = f"{label}: {response['detail']}" if response.get("detail") else label
    run.save()


@router.post("/notify/test")
def notify_test(req: TestReq, request: Request, tenant=Depends(dashboard_tenant)):
    p = _platform(request)
    if req.channel not in enabled_channels(p.store.settings(tenant.id)):
        raise HTTPException(422, "القناة غير مضبوطة في الإعدادات")
    ids = p.notifier.emit(tenant.id, "test", {"tenant_name": tenant.name}, only=req.channel)
    return {"queued": len(ids)}


@router.get("/deliveries")
def deliveries(request: Request, tenant=Depends(dashboard_tenant)):
    return {"deliveries": _platform(request).notifier.recent(tenant.id)}
