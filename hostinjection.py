#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import concurrent.futures as cf
import json
import random
import re
import sys
import time
from typing import Dict, Iterable, List, Optional, Tuple
from threading import Lock

import requests
from requests.adapters import HTTPAdapter, Retry
import urllib3

# ---------- Colors ----------
RESET = "\033[0m"; BOLD = "\033[1m"
RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; BLUE = "\033[34m"

def info(msg: str): print(f"{BLUE}[i]{RESET} {msg}")
def warn(msg: str): print(f"{YELLOW}[!]{RESET} {msg}")
def good(msg: str): print(f"{GREEN}[+]{RESET} {msg}")
def bad(msg: str):  print(f"{RED}[-]{RESET} {msg}")
def vul(msg: str):  print(f"{BOLD}{RED}[Vulnerability]{RESET} {msg}")

# ---------- Argparse ----------
def build_parser():
    p = argparse.ArgumentParser(description="Host header injection scanner (pretty progress ON by default).")
    tgt = p.add_mutually_exclusive_group(required=True)
    tgt.add_argument("-u","--url", help="Single target URL (https://example.com)")
    tgt.add_argument("-l","--list", help="File with list of URLs (one per line)")
    p.add_argument("--headers", required=True, help="Headers file (like headers.txt) containing payload words")
    p.add_argument("-a","--attacker", required=True, help="Attacker/Host payload (e.g. evil.com)")

    p.add_argument("-m","--method", default="GET", choices=["GET","POST","HEAD"])
    p.add_argument("-b","--body", help="Raw request body for POST/PUT")
    p.add_argument("-H","--extra-headers", help="Extra static headers JSON file or 'Key: Val' lines")
    p.add_argument("-U","--user-agent", help="Custom User-Agent")
    p.add_argument("-p","--proxy", help="Proxy (http://127.0.0.1:8080 or socks5://...)")
    p.add_argument("-r","--redirects", action="store_true", help="Follow redirects")
    p.add_argument("-s","--ssl", action="store_true", help="Enable SSL verification")
    p.add_argument("--no-warn-ssl", action="store_true", help="Suppress InsecureRequestWarning when SSL verify is off")
    p.add_argument("-t","--threads", type=int, default=8, help="Concurrent workers (default: 8)")
    p.add_argument("-T","--timeout", type=float, default=12.0, help="Request timeout seconds")
    p.add_argument("-o","--output", help="Save findings to JSONL file")
    p.add_argument("-v","--verbose", action="store_true", help="Verbose logging")

    # Pretty progress defaults ON. Provide flag to disable.
    p.add_argument("--no-pretty", action="store_true",
                   help="Disable single-line pretty progress (use standard per-attempt lines)")
    p.add_argument("--allow-concurrent-progress", action="store_true",
                   help="Allow concurrent workers with pretty progress (output may jitter)")

    return p

# ---------- IO helpers ----------
def read_lines(path:str)->List[str]:
    with open(path,"r",encoding="utf-8",errors="ignore") as f:
        return [x.strip() for x in f if x.strip() and not x.strip().startswith("#")]

def load_targets(a)->List[str]:
    return [a.url.strip()] if a.url else read_lines(a.list)

def load_headers_file(path:str)->List[str]:
    headers_list = read_lines(path)
    uniq = list(dict.fromkeys(headers_list))
    random.shuffle(uniq)
    return uniq

def load_extra_headers(path: Optional[str])->Dict[str,str]:
    if not path: return {}
    with open(path,"r",encoding="utf-8",errors="ignore") as f:
        raw = f.read().strip()
    try:
        js = json.loads(raw)
        if isinstance(js, dict): return {str(k): str(v) for k,v in js.items()}
    except Exception:
        pass
    out={}
    for line in raw.splitlines():
        if ":" in line:
            k,v = line.split(":",1); out[k.strip()] = v.strip()
    return out

# ---------- HTTP session ----------
def build_session(a)->requests.Session:
    s = requests.Session()
    retries = Retry(total=2, backoff_factor=0.4,
                    status_forcelist=(429,500,502,503,504),
                    allowed_methods=frozenset(["GET","POST","HEAD"]))
    ad = HTTPAdapter(max_retries=retries, pool_connections=50, pool_maxsize=50)
    s.mount("http://", ad); s.mount("https://", ad)
    if a.proxy: s.proxies={"http":a.proxy,"https":a.proxy}
    if a.user_agent: s.headers.update({"User-Agent":a.user_agent})
    if not a.ssl and a.no_warn_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return s

# ---------- Payloads ----------
BASE_HEADER_KEYS = [
    "Host","X-Host","X-Forwarded-Host","X-Original-Host",
    "X-Forwarded-Server","X-Forwarded-For","Forwarded"
]

def gen_payloads(attacker:str, headers_list:Iterable[str])->List[str]:
    base = attacker.strip()
    s = {base, f"{base}:80", f"{base}:443", f"{base}."}
    for h in headers_list:
        h=h.strip()
        if not h: continue
        s.update({f"{h}.{base}", f"{h}-{base}", f"{base}-{h}"})
    return list(s)

def build_header_variants(payload:str)->List[Tuple[str,str]]:
    out=[]
    for k in BASE_HEADER_KEYS:
        kl=k.lower()
        if kl=="x-forwarded-for":
            out += [(k,payload),(k,"127.0.0.1"),(k,"127.0.0.1, "+payload)]
        elif kl=="forwarded":
            out += [(k,f"for=127.0.0.1;host={payload};proto=https"), (k,f"host={payload}")]
        else:
            out.append((k,payload))
    return out

# ---------- Detection ----------
REFLECT_RE = re.compile(r"[^\w]")
def normalize_ref(s:str)->str: return REFLECT_RE.sub("", s.lower())[:180]

def detect(resp:requests.Response, payload:str, verbose=False)->Dict[str,object]:
    sig = {
        "status": resp.status_code,
        "reflected_in_body": False,
        "reflected_in_headers": [],
        "location_poison": False,
        "cache_headers": {},
        "interesting_headers": {},
        "content_length": int(resp.headers.get("Content-Length","0")) if resp.headers.get("Content-Length") else len(resp.content),
    }
    np = normalize_ref(payload)
    try:
        txt = resp.text[:1_000_000]
        if np and normalize_ref(txt).find(np) != -1:
            sig["reflected_in_body"]=True
    except Exception:
        pass
    refl=[]
    for hk,hv in resp.headers.items():
        if np and normalize_ref(str(hv)).find(np)!=-1: refl.append(hk)
    sig["reflected_in_headers"]=refl
    loc = resp.headers.get("Location")
    if loc and (payload in loc or normalize_ref(loc).find(np)!=-1):
        sig["location_poison"]=True
    for ck in ["Cache-Control","Age","X-Cache","X-Cache-Status","Via","CF-Cache-Status","Vary","Surrogate-Key"]:
        if ck in resp.headers: sig["cache_headers"][ck]=resp.headers[ck]
    for hk in ["Server","Via","X-Served-By","X-Varnish","X-Akamai-Staging","X-Forwarded-Proto"]:
        if hk in resp.headers: sig["interesting_headers"][hk]=resp.headers[hk]
    if verbose:
        info(f"Status {sig['status']} reflect_body={sig['reflected_in_body']} hdrs={refl} loc={sig['location_poison']}")
    return sig

def is_hit(sig:Dict[str,object])->bool:
    return bool(sig["reflected_in_body"] or sig["reflected_in_headers"] or sig["location_poison"])

# ---------- Progress UI ----------
class Progress:
    def __init__(self, total:int, enable:bool):
        self.total = total; self.enable = enable
        self.lock = Lock(); self.idx = 0; self.last_line_len = 0

    def _carriage_print(self, s:str):
        sys.stdout.write("\r" + " " * self.last_line_len)
        sys.stdout.write("\r" + s)
        sys.stdout.flush()
        self.last_line_len = len(s)

    def next_start(self, header:str, payload:str):
        if not self.enable: print(f"→ TRY {header}: {payload}"); return
        with self.lock:
            self.idx += 1
            line = f"→ TRY [{self.idx}/{self.total}] {header}: {payload}"
            self._carriage_print(line)

    def tick_hit(self, header:str, payload:str, status:int):
        if not self.enable:
            print(f"  ✅ HIT via {header}: {payload} (status {status})"); return
        with self.lock:
            sys.stdout.write("\n"); sys.stdout.flush()
            print(f"  ✅ HIT via {header}: {payload} (status {status})")
            line = f"→ TRY [{self.idx}/{self.total}] {header}: {payload}"
            self._carriage_print(line)

    def finish(self):
        if self.enable:
            sys.stdout.write("\n"); sys.stdout.flush()

def preview(text:str, n:int=64)->str:
    t=str(text);  return (t[:n]+"…") if len(t)>n else t

# ---------- Core ----------
def try_one(session:requests.Session, url:str, method:str, base_headers:Dict[str,str],
            variant:Tuple[str,str], timeout:float, redirects:bool, verify_ssl:bool,
            body:Optional[str], verbose:bool, progress:Progress)->Tuple[Tuple[str,str],Dict[str,object]]:
    hk,hv = variant; hvp = preview(hv)
    progress.next_start(hk, hvp)
    headers = dict(base_headers); headers[hk]=hv
    resp = session.request(method=method, url=url, headers=headers,
                           data=(body.encode("utf-8") if body and method in ("POST","PUT","PATCH") else None),
                           allow_redirects=redirects, timeout=timeout, verify=verify_ssl)
    sig = detect(resp, hv, verbose=verbose)
    if is_hit(sig): progress.tick_hit(hk, hvp, sig["status"])
    return (hk,hv), sig

def scan_url(a, session, url:str, headers_list:List[str])->List[Dict[str,object]]:
    verify_ssl=a.ssl; redirects=a.redirects; timeout=a.timeout
    base_headers = load_extra_headers(a.extra_headers)
    if "User-Agent" not in base_headers and not a.user_agent:
        base_headers["User-Agent"]="HostInjection/1.0"

    payloads = gen_payloads(a.attacker, headers_list)
    variants=[]; [variants.extend(build_header_variants(p)) for p in payloads]
    total=len(variants)

    # pretty progress is ON by default unless user passed --no-pretty
    pretty = not a.no_pretty
    # if pretty + no allow concurrent, force sequential (workers=1) for clean UI
    workers = 1 if (pretty and not a.allow_concurrent_progress) else min(a.threads, 32)
    progress = Progress(total, enable=pretty)

    findings=[]; header_hits={}
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs=[ex.submit(try_one, session, url, a.method, base_headers, v,
                        timeout, redirects, verify_ssl, a.body, a.verbose, progress)
              for v in variants]
        for f in cf.as_completed(futs):
            try:
                (hk,hv), sig = f.result()
                if is_hit(sig):
                    findings.append({"url":url,"header":hk,"payload":hv,"signals":sig,"ts":int(time.time())})
                    header_hits.setdefault(hk, []).append(hv)
            except requests.exceptions.SSLError as e:
                bad(f"{url} SSL error: {e}")
            except requests.exceptions.RequestException as e:
                if a.verbose: warn(f"{url} request failed: {e}")
            except Exception as e:
                if a.verbose: warn(f"{url} unexpected: {e}")

    progress.finish()

    print(BOLD + f"Summary for {url}" + RESET)
    for hk in BASE_HEADER_KEYS:
        hits = header_hits.get(hk, [])
        if hits: print(f"  {GREEN}✓{RESET} {hk}: {len(hits)} hit(s)")
        else:    print(f"  - {hk}: 0 hits")
    print()
    return findings

# ---------- Main ----------
def main():
    a = build_parser().parse_args()
    if not a.ssl: warn("SSL verify OFF. Use --no-warn-ssl to suppress warnings.")
    if a.proxy: info(f"Proxy set: {a.proxy}")
    s = build_session(a)
    targets = load_targets(a)
    headers_list = load_headers_file(a.headers)

    all_findings=[]
    for url in targets:
        info(f"Scanning: {url}")
        all_findings += scan_url(a, s, url, headers_list)

    if a.output:
        with open(a.output,"a",encoding="utf-8") as f:
            for row in all_findings: f.write(json.dumps(row, ensure_ascii=False)+"\n")
        good(f"Findings saved: {a.output}")

    if all_findings:
        good(f"Total potential findings: {len(all_findings)}")
    else:
        info("No obvious signals found. Manual validation recommended.")

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt: print("\nInterrupted by user.")
