#!/usr/bin/env python3
"""
flowspec-api.py - Flowspec Solutions
API minima (stdlib) para o dashboard do Grafana operar o FlowSpec:
  GET  /rules                 -> regras ativas (estado do c2flowspec)
  POST /rules/remove          -> {"ip": "...", "motivo": "...", "dias": 7}   retira a regra e poe o IP na whitelist por N dias
  GET  /whitelist             -> lista da whitelist
  POST /whitelist/add         -> {"cidr": "...", "porta": 53, "proto": "udp", "motivo": "...", "dias": 0}  (dias=0 = permanente)
  POST /whitelist/remove      -> {"id": "..."}
  GET  /health

Autenticacao: header  X-Token: <TOKEN>   ou  ?token=<TOKEN>
Roda como servico (systemd). Porta padrao 8765, so em 127.0.0.1 ou IP interno.

Variaveis: TOKEN (obrigatoria), STATE (estado do c2flowspec), WLFILE (whitelist), GOBGP_BIN, BIND, PORT
"""
import os, sys, json, uuid, datetime, subprocess, ipaddress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

TOKEN  = os.environ.get("TOKEN", "")
STATE  = os.environ.get("STATE", "/var/lib/flowspec/c2flowspec.json")
WLFILE = os.environ.get("WLFILE", "/var/lib/flowspec/whitelist.json")
GOBGP  = os.environ.get("GOBGP_BIN", "gobgp")
BIND   = os.environ.get("BIND", "127.0.0.1")
PORT   = int(os.environ.get("PORT", "8765"))
if not TOKEN: sys.exit("Defina TOKEN (export TOKEN='...')")

def agora(): return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
def jload(p, default):
    try: return json.load(open(p))
    except Exception: return default
def jsave(p, d):
    os.makedirs(os.path.dirname(p), exist_ok=True); json.dump(d, open(p, "w"), indent=1, ensure_ascii=False)

def gobgp_del(ip):
    """Retira as regras do IP (as duas direcoes; ignora erro se ja nao existir)."""
    for s in ("destination", "source"):
        subprocess.run([GOBGP, "global", "rib", "-a", "ipv4-flowspec", "del", "match", s, f"{ip}/32", "then", "discard"], capture_output=True)
        # rate-limit: nao sabemos o bps usado; tentamos os comuns
        for bps in ("100000", "10000"):
            subprocess.run([GOBGP, "global", "rib", "-a", "ipv4-flowspec", "del", "match", s, f"{ip}/32", "then", "rate-limit", bps], capture_output=True)

def valida_cidr(c):
    return str(ipaddress.ip_network(c, strict=False))

class H(BaseHTTPRequestHandler):
    def _auth(self):
        q = parse_qs(urlparse(self.path).query)
        t = self.headers.get("X-Token") or (q.get("token") or [""])[0]
        return t == TOKEN
    def _json(self, code, obj):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Token"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        try: return json.loads(self.rfile.read(n) or b"{}")
        except Exception: return {}
    def log_message(self, *a): pass
    def do_OPTIONS(self): self._json(200, {})

    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/health": return self._json(200, {"ok": True, "hora": agora()})
        if not self._auth(): return self._json(401, {"erro": "token"})
        if p == "/rules":
            st = jload(STATE, {})
            rows = [{"ip": ip, **v} for ip, v in st.items()]
            rows.sort(key=lambda x: -x.get("cpes", 0))
            return self._json(200, rows)
        if p == "/whitelist":
            wl = jload(WLFILE, [])
            for w in wl: w["ativo"] = (not w.get("ate")) or w["ate"] > agora()
            return self._json(200, wl)
        return self._json(404, {"erro": "rota"})

    def do_POST(self):
        p = urlparse(self.path).path
        if not self._auth(): return self._json(401, {"erro": "token"})
        b = self._body()
        if p == "/rules/remove":
            ip = (b.get("ip") or "").strip()
            try: ipaddress.ip_address(ip)
            except Exception: return self._json(400, {"erro": "ip invalido"})
            st = jload(STATE, {}); gobgp_del(ip); st.pop(ip, None); jsave(STATE, st)
            dias = int(b.get("dias") or 7)
            wl = jload(WLFILE, [])
            wl.append({"id": uuid.uuid4().hex[:10], "cidr": f"{ip}/32", "porta": None, "proto": None,
                       "motivo": b.get("motivo") or "removido pelo operador", "criado_em": agora(),
                       "ate": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=dias)).replace(microsecond=0).isoformat() if dias > 0 else None})
            jsave(WLFILE, wl)
            return self._json(200, {"ok": True, "ip": ip, "whitelist_dias": dias})
        if p == "/whitelist/add":
            try: cidr = valida_cidr((b.get("cidr") or "").strip())
            except Exception: return self._json(400, {"erro": "cidr invalido"})
            porta = b.get("porta"); proto = (b.get("proto") or "").lower() or None
            if porta not in (None, "", 0):
                try: porta = int(porta); assert 1 <= porta <= 65535
                except Exception: return self._json(400, {"erro": "porta invalida"})
            else: porta = None
            if proto and proto not in ("tcp", "udp"): return self._json(400, {"erro": "proto deve ser tcp ou udp"})
            dias = int(b.get("dias") or 0)
            wl = jload(WLFILE, [])
            wl.append({"id": uuid.uuid4().hex[:10], "cidr": cidr, "porta": porta, "proto": proto,
                       "motivo": b.get("motivo") or "", "criado_em": agora(),
                       "ate": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=dias)).replace(microsecond=0).isoformat() if dias > 0 else None})
            jsave(WLFILE, wl)
            # se ja existe regra ativa para esse IP, retira agora
            st = jload(STATE, {}); net = ipaddress.ip_network(cidr, strict=False)
            for ip in [i for i in st if ipaddress.ip_address(i) in net and porta is None]:
                gobgp_del(ip); st.pop(ip, None)
            jsave(STATE, st)
            return self._json(200, {"ok": True, "cidr": cidr, "porta": porta, "proto": proto})
        if p == "/whitelist/remove":
            wl = jload(WLFILE, []); n = len(wl)
            wl = [w for w in wl if w.get("id") != b.get("id")]
            jsave(WLFILE, wl)
            return self._json(200, {"ok": True, "removidos": n - len(wl)})
        return self._json(404, {"erro": "rota"})

if __name__ == "__main__":
    print(f"flowspec-api em http://{BIND}:{PORT}", file=sys.stderr)
    ThreadingHTTPServer((BIND, PORT), H).serve_forever()
