"""
===================================================================
صفحات روابط الموافقة (/approve/{token}) — بلا دخول، الرمز هو الهوية
===================================================================
GET يعرض صفحة تأكيد فقط ولا يغيّر شيئًا: Telegram وSlack يفتحان الروابط
تلقائيًا للمعاينة، فلو كان الفتح يوافق لنُفّذ حظر بلا قرار بشري.
POST بالقرار يستهلك الرمز (لمرة واحدة) ويمر بمسار القرار الوحيد.
===================================================================
"""

import html
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from agent.tools import ACTION_AR, ToolError
from tenancy.api import _apply_decision, _tenant_name

pages = APIRouter()

STATUS_AR = {"applied": "طُبّق الإجراء", "rejected": "رُفض المقترح", "refused": "رفضه حاجز الأمان",
             "covered": "مغطّى بقاعدة سابقة", "no_enforcement": "مراقبة فقط"}

_STYLE = """body{margin:0;min-height:100vh;display:grid;place-items:center;background:#05070d;color:#eaf0fb;
font-family:"IBM Plex Sans Arabic",system-ui,sans-serif;padding:16px}
.card{max-width:460px;width:100%;background:#111829;border:1px solid #1e2a44;border-radius:14px;padding:22px}
h1{font-size:1.2rem;margin:0 0 12px}.kv{display:flex;justify-content:space-between;gap:10px;padding:8px 0;
border-bottom:1px solid #172138;font-size:.9rem}.kv span:first-child{color:#9aa7c4}
code{font-family:"IBM Plex Mono",monospace;direction:ltr;unicode-bidi:isolate}p{color:#9aa7c4;font-size:.88rem}
form{display:flex;gap:10px;margin-top:18px}button{flex:1;border:0;border-radius:11px;padding:12px;font:inherit;
font-weight:700;cursor:pointer}.ok{background:#ff4d62;color:#fff}.no{background:#1e2a44;color:#eaf0fb}
.pick{outline:3px solid #38bdf8}"""


def _page(title, body, status=200):
    return HTMLResponse(f"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{html.escape(title)}</title>
<style>{_STYLE}</style></head><body><div class="card"><h1>{html.escape(title)}</h1>{body}</div></body></html>""",
                        status_code=status)


def _expired():
    return _page("انتهت صلاحية الرابط",
                 "<p>الرابط صالح لمرة واحدة ولمدة ساعة. افتح لوحة التحكم لمراجعة الحادثة.</p>", 410)


def _proposal(p, rec):
    run = p.runs.get((rec["tenant_id"], rec["incident_id"]))
    pr = run.ws.proposals.get(rec["proposal_id"]) if run else None
    return (run, pr) if pr is not None and pr.status == "pending" else (None, None)


@pages.get("/approve/{token}", response_class=HTMLResponse)
def approve_page(token: str, request: Request, d: str = ""):
    p = request.app.state.platform
    rec = p.approvals.peek(token)
    if rec is None:
        return _expired()
    run, pr = _proposal(p, rec)
    if pr is None:
        return _page("انتهت صلاحية المقترح", "<p>المقترح لم يعد معلّقًا. افتح لوحة التحكم.</p>", 410)
    e = html.escape
    return _page("قرار أمني بانتظارك", f"""
<div class="kv"><span>المنشأة</span><span>{e(_tenant_name(p, rec["tenant_id"]))}</span></div>
<div class="kv"><span>الحادثة</span><span><code>{e(rec["incident_id"])}</code></span></div>
<div class="kv"><span>الإجراء</span><span>{e(ACTION_AR.get(pr.action, pr.action))}</span></div>
<div class="kv"><span>العنوان</span><span><code>{e(pr.source_ip)}</code></span></div>
<div class="kv"><span>المدة</span><span>{pr.duration_min} دقيقة</span></div>
<p>{e("، ".join(pr.reasons))}</p>
<form method="post">
  <button class="ok{' pick' if d == 'approve' else ''}" name="decision" value="approve">وافق</button>
  <button class="no{' pick' if d == 'reject' else ''}" name="decision" value="reject">ارفض</button>
</form>""")


@pages.post("/approve/{token}", response_class=HTMLResponse)
async def approve_submit(token: str, request: Request):
    decision = parse_qs((await request.body()).decode()).get("decision", [""])[0]
    if decision not in ("approve", "reject"):
        return _page("طلب غير صالح", "<p>القرار يجب أن يكون موافقة أو رفضًا.</p>", 400)
    p = request.app.state.platform
    rec = p.approvals.consume(token)
    if rec is None:
        return _expired()
    run, pr = _proposal(p, rec)
    if pr is None:
        return _page("انتهت صلاحية المقترح", "<p>المقترح لم يعد معلّقًا. افتح لوحة التحكم.</p>", 410)
    try:
        out = _apply_decision(p, rec["tenant_id"], run, pr.id, decision, "owner-link")
    except ToolError as e:
        return _page("تعذّر تنفيذ القرار", f"<p>{html.escape(str(e))}</p>", 409)
    return _page(STATUS_AR.get(pr.status, pr.status),
                 f"<p>{html.escape(out.get('note', ''))}</p><p>يمكنك إغلاق هذه الصفحة.</p>")
