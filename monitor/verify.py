"""
التحقق من ملكية الموقع قبل الفحص العميق، بإحدى طريقتين:
ملف /.well-known/pc-verification.txt يحوي الرمز، أو سجل TXT على _pc-verify.<المضيف>.
"""

FILE_PATH = "/.well-known/pc-verification.txt"


def dns_name(host):
    return f"_pc-verify.{host}"


def verify_file(origin, token, get):
    r = get(origin + FILE_PATH)
    return r.error is None and r.status == 200 and token in "".join(r.body.decode(errors="replace").split())


def _dnspython_txt(name):
    import dns.resolver
    return [b"".join(rdata.strings).decode(errors="replace") for rdata in dns.resolver.resolve(name, "TXT", lifetime=5)]


def verify_dns(host, token, resolve_txt=None):
    """صحيح/خطأ، أو None إن لم تكن مكتبة dnspython مثبتة."""
    if resolve_txt is None:
        try:
            import dns.resolver  # noqa: F401
        except ImportError:
            return None
        resolve_txt = _dnspython_txt
    try:
        return any(record.strip() == token for record in resolve_txt(dns_name(host)))
    except Exception:   # لا سجل، أو نطاق غير موجود، أو مهلة
        return False
