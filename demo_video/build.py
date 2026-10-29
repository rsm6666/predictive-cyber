"""
===================================================================
تركيب فيديو العرض من لقطات record.mjs — 1920×1080، 30 إطارًا/ث، H.264
===================================================================
كل مشهد: لقطاته بأوقاتها الحقيقية ← مقطع بمدته الثابتة + نصف ثانية للانتقال.
الانتقال تلاشٍ 0.5 ث يبدأ عند وقت بداية المشهد التالي في voice_script.md،
فيوضع كل ملف صوتي عند وقته المكتوب بلا حساب.

  python demo_video/build.py
الناتج: demo_video/out/demo.mp4

مع الصوت: ضع ملفات المقاطع 01.mp3 … 10.mp3 في demo_video/out/voice/ (بترتيب السكربت)،
فيطول كل مشهد عند الحاجة ليتسع لصوته (يثبت آخر إطار)، ويُوضع كل مقطع عند بداية
مشهده بعد LEAD، بصوت موحّد (loudnorm). الناتج: demo_video/out/demo_voiced.mp4
===================================================================
"""

import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
FRAMES, CLIPS = HERE / "out" / "frames", HERE / "out" / "clips"
FADE = 0.5
VOICE = HERE / "out" / "voice"
LEAD, TAIL = 0.3, 0.6           # قبل الكلام وبعده داخل المشهد
VOICE_OFFSETS = {"06_campaign": (0, 18)}   # مقطع الحملة يحمل مشهدَي السكربت 6 و7
ORDER = ["01_title", "02_problem", "03_sources", "04_models", "05_monitor", "06_campaign", "08_decision",
         "09_results", "10_closing"]


def ffmpeg(*args):
    subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", *args], check=True)


def seconds(path):
    out = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(path)],
                         capture_output=True, text=True, check=True)
    return float(out.stdout)


def voice_plan():
    """← ({المشهد: مدته الجديدة}، [(الملف، بدايته داخل المشهد، المشهد)]) أو (None، []) بلا أصوات."""
    files = sorted(VOICE.glob("*.mp3")) if VOICE.exists() else []
    if not files:
        return None, []
    want = sum(len(VOICE_OFFSETS.get(s, (0,))) for s in ORDER)
    assert len(files) == want, f"المطلوب {want} مقطعًا صوتيًا، والموجود {len(files)}"
    durs, placed, it = {}, [], iter(files)
    for scene in ORDER:
        meta = json.loads((FRAMES / scene / "frames.json").read_text())
        offsets, end = VOICE_OFFSETS.get(scene, (0,)), meta["dur"]
        for k, off in enumerate(offsets):
            f = next(it)
            limit = offsets[k + 1] if k + 1 < len(offsets) else None
            if limit is not None:
                assert off + LEAD + seconds(f) <= limit, f"{f.name} أطول من مكانه في {scene}"
            else:
                end = max(end, off + LEAD + seconds(f) + TAIL)
            placed.append((f, off + LEAD, scene))
        durs[scene] = end
    return durs, placed


def clip(scene, dur=None):
    meta = json.loads((FRAMES / scene / "frames.json").read_text())
    start, rec = meta["start"], meta["dur"]
    dur = dur or rec
    frames = sorted(meta["frames"], key=lambda f: f["t"])
    lines = []
    for i, f in enumerate(frames):
        if f["t"] >= start + rec:
            break
        nxt = frames[i + 1]["t"] if i + 1 < len(frames) else start + rec
        lines += [f"file '{f['f']}'", f"duration {max(min(nxt, start + rec) - f['t'], 0.001):.4f}"]
    lines.append(lines[-2])                       # concat يتجاهل مدة السطر الأخير
    listing = CLIPS / f"{scene}.txt"
    listing.write_text("\n".join(lines) + "\n")
    out = CLIPS / f"{scene}.mp4"
    ffmpeg("-f", "concat", "-safe", "0", "-i", str(listing),
           "-vf", f"scale=1920:1080:flags=lanczos,fps=30,tpad=stop_mode=clone:stop_duration={dur - rec + FADE + 1},format=yuv420p",
           "-t", f"{dur + FADE:.3f}", "-c:v", "libx264", "-preset", "slow", "-crf", "15", "-an", str(out))
    return out, dur


def main():
    CLIPS.mkdir(parents=True, exist_ok=True)
    durs, placed = voice_plan()
    clips = [clip(s, durs and durs[s]) for s in ORDER]
    inputs = [arg for c, _ in clips for arg in ("-i", str(c))]
    chain, label, offset, starts = [], "0:v", 0.0, [0.0]
    for i, (_, dur) in enumerate(clips[:-1], start=1):
        offset += dur
        starts.append(offset)
        out = f"v{i}"
        chain.append(f"[{label}][{i}:v]xfade=transition=fade:duration={FADE}:offset={offset:.3f}[{out}]")
        label = out
    ffmpeg(*inputs, "-filter_complex", ";".join(chain), "-map", f"[{label}]", "-c:v", "libx264",
           "-preset", "slow", "-crf", "17", "-pix_fmt", "yuv420p", "-movflags", "+faststart",
           str(HERE / "out" / "demo.mp4"))
    total = sum(d for _, d in clips) + FADE
    print(f"demo.mp4: {int(total // 60)}:{total % 60:04.1f}")
    for s, t in zip(ORDER, starts):
        print(f"  {int(t // 60)}:{int(t % 60):02d}  {s}")
    if placed:
        mix(placed, dict(zip(ORDER, starts)), total)


def mix(placed, starts, total):
    """كل مقطع عند بداية مشهده + LEAD، بصوت موحّد، فوق demo.mp4."""
    inputs = [arg for f, _, _ in placed for arg in ("-i", str(f))]
    parts = []
    for i, (_, off, scene) in enumerate(placed, start=1):
        ms = int((starts[scene] + off) * 1000)
        parts.append(f"[{i - 1}:a]loudnorm=I=-16:TP=-1.5:LRA=11,aresample=48000,adelay={ms}|{ms}[a{i}]")
    labels = "".join(f"[a{i}]" for i in range(1, len(placed) + 1))
    parts.append(f"{labels}amix=inputs={len(placed)}:normalize=0:duration=longest,apad=whole_dur={total:.3f}[aout]")
    track = HERE / "out" / "voice_track.wav"          # خطوتان: الدمج مع نسخ الفيديو في أمر واحد يقطع الصوت
    ffmpeg(*inputs, "-filter_complex", ";".join(parts), "-map", "[aout]", str(track))
    ffmpeg("-i", str(HERE / "out" / "demo.mp4"), "-i", str(track), "-map", "0:v", "-map", "1:a", "-c:v", "copy",
           "-c:a", "aac", "-b:a", "192k", "-t", f"{total:.3f}", "-movflags", "+faststart",
           str(HERE / "out" / "demo_voiced.mp4"))
    print("demo_voiced.mp4: " + "، ".join(f"{f.stem}@{starts[s] + o:.1f}s" for f, o, s in placed))


if __name__ == "__main__":
    main()
