"""NetSentinel AI - proof-of-concept of the three gateway components (stdlib only).

Production plan: FastAPI + Pydantic on Cloud Run, Memorystore (Redis), Gemma classifier, Vertex AI.
This PoC proves the *policy logic*; it does NOT call Gemma, Redis or Vertex AI.
"""
import hashlib, json, re, time

# ------------------------------------------------------------------ 1. DUAL-RING CACHE
class DualRingCache:
    """Ring 0: shared, operator-registered static content only (system prompt, MCP tool schemas).
    Ring 1: per-session scratchpad for untrusted dynamic content. Never shared, TTL-bound, never promoted."""
    def __init__(self, ttl=300):
        self.ring0, self.ring1, self.ttl = {}, {}, ttl

    @staticmethod
    def key(text): return hashlib.sha256(text.encode()).hexdigest()

    def register_static(self, text):              # only called by operator at deploy time
        k = self.key(text); self.ring0[k] = text; return k

    def build_request(self, session, static_parts, dynamic_text):
        refs, sent = [], 0
        for part in static_parts:
            k = self.key(part)
            if k in self.ring0: refs.append(k)    # deduplicated: send hash reference, not tokens
            else: sent += len(part)               # unknown static content is NOT cached, sent as-is
        self.ring1[session] = (time.time() + self.ttl, dynamic_text)   # quarantined to this session
        return {"static_refs": refs, "dynamic": dynamic_text, "extra_chars": sent}

    def read_dynamic(self, session):
        exp, txt = self.ring1.get(session, (0, None))
        return txt if time.time() < exp else None

class NaiveCache:
    """Baseline: stores any prompt prefix in a shared table (the vulnerability we describe)."""
    def __init__(self): self.t = {}
    def put(self, prefix): self.t[hashlib.sha256(prefix.encode()).hexdigest()] = prefix
    def all_text(self): return " ".join(self.t.values())

# ------------------------------------------------------------------ 2. SEMANTIC PRE-FILTER (stage 1)
INJ = [r"ignore (all |any )?(the )?(previous|prior|above) (instructions|prompts?)", r"disregard .{0,30}(instructions|rules)",
       r"you are now\b", r"new (system )?instructions?:", r"system prompt", r"reveal .{0,30}(prompt|key|secret|credential)",
       r"<!--.*?-->", r"(send|post|upload|forward) .{0,60}(api[_ ]?key|password|token|credential)s?",
       r"(drop|truncate|delete from) .{0,20}(table|database)", r"do not (tell|inform|mention).{0,30}user",
       r"\bjailbreak\b", r"developer mode", r"base64"]
INJ_RE = [re.compile(p, re.I | re.S) for p in INJ]

def prefilter(text):
    return any(r.search(text) for r in INJ_RE)

# ------------------------------------------------------------------ 3. TOOL-CALL FIREBREAK
POLICY = {"tools": {"sql_query": {"allowed_tables": {"orders", "customers"}},
                    "http_get": {"allowed_hosts": {"api.internal.example.com"}},
                    "write_file": {"allowed_prefix": "/workspace/out/"}}}
_STMT_BAD = re.compile(r"\b(drop|truncate|alter|grant|revoke|create|insert|update|delete|merge|exec|attach|pragma)\b", re.I)

def firebreak(call):
    """call = {"tool": str, "args": dict}. Returns (allowed, reason). Fails closed."""
    try:
        tool, args = call["tool"], call["args"]
        if tool not in POLICY["tools"]: return False, "tool not allowlisted"
        p = POLICY["tools"][tool]
        if tool == "sql_query":
            q = re.sub(r"/\*.*?\*/|--[^\n]*", " ", args["query"], flags=re.S).strip().rstrip(";")
            if ";" in q: return False, "multiple statements"
            if not re.match(r"(?i)^select\b", q): return False, "only SELECT allowed"
            if _STMT_BAD.search(q): return False, "mutating keyword"
            tables = set(re.findall(r"(?i)\b(?:from|join)\s+([a-z_][a-z0-9_.]*)", q))
            if not tables or not tables <= p["allowed_tables"]: return False, "table not allowlisted"
            return True, "ok"
        if tool == "http_get":
            m = re.match(r"^https://([^/:@]+)(/|$)", args["url"])
            return (True, "ok") if m and m.group(1) in p["allowed_hosts"] else (False, "host not allowlisted")
        if tool == "write_file":
            path = args["path"]
            if ".." in path or not path.startswith(p["allowed_prefix"]): return False, "path outside sandbox"
            return True, "ok"
    except Exception as e:
        return False, f"malformed call ({type(e).__name__})"
    return False, "unhandled"
