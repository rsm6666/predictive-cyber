"""
===================================================================
المحلل الأمني الذكي — حلقة وكيل Claude (Tool Use)
===================================================================
  investigate / run_investigation  تحقيق تلقائي ينتهي بـ submit_report
  chat                             أسئلة صاحب المنشأة، بأدوات القراءة فقط

حلقة يدوية لا Tool Runner: نحتاج حد خطوات ووقت، حدثًا لكل خطوة، وعميلًا
وهميًا في الاختبارات. لا نجبر أداة عبر tool_choice (غير مدعوم على
Opus 5.5)؛ بعد الحد تُرجع الأدوات خطأً يطلب كتابة التقرير.
السجل إضافة فقط: نضيف response.content كاملًا ولا نعدّل ما سبق.
===================================================================
"""

import json
import os
import time

import anthropic

from agent.tools import ToolError

MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-opus-5-5")
EFFORT = os.environ.get("ANTHROPIC_EFFORT", "medium")
FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_STEPS = 12
MAX_SECONDS = 90
GRACE_TURNS = 2
CHAT_MAX_STEPS = 6

SYSTEM_INVESTIGATE = """أنت محلل أمن سيبراني يعمل لدى منشأة صغيرة لا تملك فريقًا أمنيًا. وصلك تنبيه عن نافذة مراقبة من ترافيك شبكتها، ومهمتك التحقيق فيه بالأدوات المتاحة ثم كتابة تقرير لصاحب المنشأة.

طريقة العمل:
- ابدأ بـ incident_overview ثم suspicious_sources.
- افحص أهم المصادر المشبوهة بـ explain_source، واستخدم forecast_next_minute لتقدير ما سيحدث بعد قليل.
- قبل أي اقتراح، استدعِ check_policy للمصدر. اقترح عبر propose_action إجراءً لكل مصدر يستحقه، ويمكنك اختيار إجراء أخف من الحد الأقصى إذا كان الدليل ضعيفًا (ثقة أو نسبة هجوم منخفضة، أو اتصالات قليلة). المصادر التي علّم النموذج اتصالًا أو اتصالين منها فقط غالبًا أخطاء تصنيف فردية.
- إذا لم تجد ما يستدعي القلق، قل ذلك بوضوح ولا تقترح إجراءات.
- أنهِ دائمًا باستدعاء submit_report مرة واحدة.

قواعد التقرير:
- استند إلى نتائج الأدوات فقط. لا تذكر عنوانًا أو رقمًا لم يرد فيها.
- summary_owner لصاحب منشأة غير تقني: ماذا حدث، وهل الخطر قائم، وماذا ينتظر منه. بلا مصطلحات تقنية.
- attack_types من أسماء predicted_type كما وردت، وتبقى فارغة إذا لم يوجد هجوم.
- evidence أرقام ووقائع من نتائج الأدوات."""

SYSTEM_CHAT = """أنت المحلل الأمني نفسه الذي حقق في الحادثة، وتجيب الآن على أسئلة صاحب المنشأة. أجب بالعربية البسيطة باختصار (من 3 إلى 6 جمل). استند إلى السياق المرفق ونتائج الأدوات فقط، وإذا لم تعرف فقل ذلك. لا تستطيع تنفيذ أي إجراء أو الموافقة عليه: القرار لصاحب المنشأة عبر أزرار الموافقة في الصفحة."""


class AgentError(Exception):
    """فشل لا يُكمل معه التحقيق (رفض، أو انتهاء بلا تقرير)."""


def proposal_public(p):
    return {"id": p.id, "source_ip": p.source_ip, "attack_type": p.attack_type, "action": p.action,
            "duration_min": p.duration_min, "status": p.status, "reasons": p.reasons,
            "executor": p.rationale}


def _call(client, model, system, tools, messages):
    return client.beta.messages.create(
        model=model, max_tokens=16000, system=system, tools=tools, messages=messages,
        output_config={"effort": EFFORT}, cache_control={"type": "ephemeral"},
        betas=[FALLBACK_BETA], fallbacks="default",
    )


def _execute(ws, b):
    try:
        return ws.run_tool(b.name, b.input), False
    except ToolError as e:
        return {"error": str(e)}, True
    except Exception as e:      # خطأ غير متوقع في أداة لا يوقف التحقيق
        return {"error": f"خطأ داخلي في الأداة: {e}"}, True


def _tool_result(b, result, is_error):
    return {"type": "tool_result", "tool_use_id": b.id, "is_error": is_error,
            "content": json.dumps(result, ensure_ascii=False, default=str)}


# ===================================================================
# التحقيق
# ===================================================================
def investigate(client, ws, run, model=MODEL, clock=time.monotonic):
    task = getattr(ws, "task", None) or f"تنبيه أمني جديد على الشبكة (الحادثة {ws.incident.id}). حقّق فيه واكتب التقرير."
    messages = [{"role": "user", "content": task}]
    steps, start = 0, clock()
    for _ in range(MAX_STEPS + GRACE_TURNS + 2):
        response = _call(client, model, ws.system_prompt or SYSTEM_INVESTIGATE, ws.tool_specs, messages)
        run.add_usage(response.usage)
        if response.stop_reason == "refusal":
            raise AgentError("رفض مصنّف الأمان متابعة التحقيق")
        messages.append({"role": "assistant", "content": response.content})
        uses = [b for b in response.content if b.type == "tool_use"]
        report = next((b for b in uses if b.name == "submit_report"), None)
        if report is not None:
            run.report = dict(report.input)
            return run.report
        if not uses:
            messages.append({"role": "user", "content": "أنهِ التحقيق الآن باستدعاء submit_report."})
            continue
        results = []
        for b in uses:
            if steps >= MAX_STEPS or clock() - start > MAX_SECONDS:
                result, is_error = {"error": "بلغتَ حد الخطوات أو الوقت. استدعِ submit_report الآن بما جمعته."}, True
            else:
                steps += 1
                result, is_error = _execute(ws, b)
                run.emit("step", tool=b.name, input=b.input, summary=ws.describe(b.name, b.input, result),
                         result=result, is_error=is_error)
            results.append(_tool_result(b, result, is_error))
        messages.append({"role": "user", "content": results})
    raise AgentError("انتهى التحقيق دون تقرير")


def _fail(ws, run, message):
    ws.rules_proposals()
    run.emit("agent_error", message=message, proposals=[proposal_public(p) for p in ws.proposals.values()])
    run.finish("failed")


def run_investigation(client, ws, run, model=MODEL):
    """يشغّل التحقيق ويضمن دائمًا: تقرير أو بديل القواعد، ثم حدث done وحفظ السجل."""
    try:
        investigate(client, ws, run, model=model)
        run.emit("report", report=run.report, proposals=[proposal_public(p) for p in ws.proposals.values()])
        run.finish("done")
    except AgentError as e:
        _fail(ws, run, str(e))
    except anthropic.APIConnectionError:
        _fail(ws, run, "تعذّر الوصول إلى خدمة Claude")
    except anthropic.APIStatusError as e:
        _fail(ws, run, f"خطأ من خدمة Claude (رمز {e.status_code})")
    except Exception as e:
        _fail(ws, run, f"خطأ داخلي: {e}")
    finally:
        run.emit("done", status=run.status, truth_family=run.incident.family,
                 seconds=run.seconds, usage=run.usage)
        run.save()


# ===================================================================
# المحادثة
# ===================================================================
def chat(client, ws, run, message, model=MODEL):
    """سؤال من صاحب المنشأة. السياق المتغير يُرسل داخل رسالة المستخدم (السجل إضافة فقط)."""
    context = {
        "incident_id": ws.incident.id, "report": run.report,
        "proposals": [proposal_public(p) for p in ws.proposals.values()],
        "decisions": [{k: e[k] for k in ("source_ip", "action", "status", "note")} for e in ws.firewall.log],
    }
    mark = len(run.chat_messages)
    run.chat_messages.append({"role": "user", "content":
                              f"سياق محدّث:\n{json.dumps(context, ensure_ascii=False, default=str)}\n\n"
                              f"سؤال صاحب المنشأة: {message}"})
    steps = []
    chat_tools = [t for t in ws.tool_specs if t["name"] in ws.read_tools]
    try:
        for _ in range(CHAT_MAX_STEPS + 2):
            response = _call(client, model, SYSTEM_CHAT, chat_tools, run.chat_messages)
            run.add_usage(response.usage)
            if response.stop_reason == "refusal":
                raise AgentError("رفض مصنّف الأمان الإجابة")
            run.chat_messages.append({"role": "assistant", "content": response.content})
            uses = [b for b in response.content if b.type == "tool_use"]
            if not uses:
                answer = "\n".join(b.text for b in response.content if b.type == "text").strip()
                run.chat_log += [{"role": "owner", "text": message}, {"role": "agent", "text": answer}]
                return {"reply": answer, "steps": steps}
            results = []
            for b in uses:
                if b.name not in ws.read_tools:
                    result, is_error = {"error": "هذه الأداة غير متاحة في المحادثة"}, True
                elif len(steps) >= CHAT_MAX_STEPS:
                    result, is_error = {"error": "بلغتَ حد الأدوات؛ أجب الآن بما لديك."}, True
                else:
                    result, is_error = _execute(ws, b)
                    steps.append(ws.describe(b.name, b.input, result))
                results.append(_tool_result(b, result, is_error))
            run.chat_messages.append({"role": "user", "content": results})
        raise AgentError("لم تكتمل الإجابة")
    except Exception:
        del run.chat_messages[mark:]     # لا نترك سجلًا ناقصًا يكسر السؤال التالي
        raise
