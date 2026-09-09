#!/usr/bin/env python3
"""
flowspec-api.py - Flowspec Solutions
API minima (stdlib) para o dashboard do Grafana operar o FlowSpec:
  GET  /rules                 -> regras ativas (estado do c2flowspec)
  POST /rules/remove          -> {"chave": "CPE>C2:porta/proto", "motivo": "...", "dias": 7, "escopo": "vetor|destino"}
  GET  /whitelist             -> lista da whitelist
  POST /whitelist/add         -> {"cidr": "...", "porta": 53, "proto": "udp", "ip_lado": "origem|destino|qualquer", "porta_lado": "origem|destino|qualquer", "motivo": "...", "dias": 0}
  POST /whitelist/remove      -> {"id": "..."}
  POST /rules/clear           -> {"pausar_min": 60, "motivo": "..."}   PANICO: remove todas e pausa o c2flowspec
  POST /rules/resume          -> retoma (remove a pausa)
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
PAUSA  = os.environ.get("PAUSA",  "/var/lib/flowspec/pausa.json")
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

def gobgp_del_regras(regs):
    """Retira exatamente as regras salvas no estado (args do gobgp)."""
    for r in regs or []:
        subprocess.run([GOBGP, "global", "rib", "-a", "ipv4-flowspec", "del"] + r, capture_output=True)

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
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Token"); self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        try: return json.loads(self.rfile.read(n) or b"{}")
        except Exception: return {}
    def log_message(self, *a): pass
    def do_OPTIONS(self): self._json(200, {})

    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/health":
            pz = jload(PAUSA, {}); ativa = bool(pz.get("ate")) and pz["ate"] > agora()
            return self._json(200, {"ok": True, "hora": agora(), "pausado": ativa, "pausado_ate": pz.get("ate") if ativa else None})
        if not self._auth(): return self._json(401, {"erro": "token"})
        if p == "/rules":
            st = jload(STATE, {})
            rows = [{"chave": k, "cpe": v.get("cpe"), "c2": v.get("c2"), "porta": v.get("porta"), "proto": v.get("proto") or "*",
                     "flows": v.get("flows"), "fontes": v.get("fontes"), "acao": v.get("acao"), "desde": v.get("desde"), "ultimo": v.get("ultimo")} for k, v in st.items()]
            rows.sort(key=lambda x: -(x.get("flows") or 0))
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
            chave = (b.get("chave") or "").strip()
            st = jload(STATE, {})
            if chave not in st: return self._json(404, {"erro": "chave nao encontrada (use a coluna 'chave' da tabela)"})
            v = st[chave]; gobgp_del_regras(v.get("regras")); st.pop(chave, None); jsave(STATE, st)
            dias = int(b.get("dias") or 7); escopo = (b.get("escopo") or "vetor")
            wl = jload(WLFILE, [])
            # escopo 'vetor' = libera so este C2:porta/proto ; 'destino' = libera o C2 inteiro
            ent = {"id": uuid.uuid4().hex[:10], "cidr": f"{v['c2']}/32", "ip_lado": "destino", "porta_lado": "destino",
                   "porta": v.get("porta") if escopo == "vetor" else None, "proto": v.get("proto") if escopo == "vetor" else None,
                   "motivo": b.get("motivo") or f"removido pelo operador ({chave})", "criado_em": agora(),
                   "ate": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=dias)).replace(microsecond=0).isoformat() if dias > 0 else None}
            wl.append(ent); jsave(WLFILE, wl)
            return self._json(200, {"ok": True, "chave": chave, "whitelist": ent})
        if p == "/rules/clear":
            # PANICO: retira TODAS as regras, zera o estado e pausa o c2flowspec por N minutos
            st = jload(STATE, {}); n = 0
            for k, v in st.items(): gobgp_del_regras(v.get("regras")); n += 1
            jsave(STATE, {})
            minutos = int(b.get("pausar_min") or 60)
            ate = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=minutos)).replace(microsecond=0).isoformat()
            jsave(PAUSA, {"ate": ate, "motivo": b.get("motivo") or "panico pelo operador", "em": agora()})
            return self._json(200, {"ok": True, "removidas": n, "pausado_ate": ate})
        if p == "/rules/resume":
            try: os.remove(PAUSA)
            except FileNotFoundError: pass
            return self._json(200, {"ok": True, "pausa": "removida"})
        if p == "/whitelist/add":
            try: cidr = valida_cidr((b.get("cidr") or "").strip())
            except Exception: return self._json(400, {"erro": "cidr invalido"})
            porta = b.get("porta"); proto = (b.get("proto") or "").lower() or None
            if isinstance(porta, str): porta = porta.strip()
            if porta not in (None, "", 0, "0"):
                try: porta = int(porta); assert 1 <= porta <= 65535
                except Exception: return self._json(400, {"erro": "porta invalida"})
            else: porta = None
            if proto and proto not in ("tcp", "udp"): return self._json(400, {"erro": "proto deve ser tcp ou udp"})
            ip_lado = (b.get("ip_lado") or "qualquer").lower(); porta_lado = (b.get("porta_lado") or "destino").lower()
            if ip_lado not in ("origem", "destino", "qualquer") or porta_lado not in ("origem", "destino", "qualquer"):
                return self._json(400, {"erro": "ip_lado/porta_lado devem ser origem, destino ou qualquer"})
            try: dias = int(str(b.get("dias") or "0").strip() or 0)
            except Exception: dias = 0
            wl = jload(WLFILE, [])
            wl.append({"id": uuid.uuid4().hex[:10], "cidr": cidr, "porta": porta, "proto": proto,
                       "ip_lado": ip_lado, "porta_lado": porta_lado,
                       "motivo": b.get("motivo") or "", "criado_em": agora(),
                       "ate": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=dias)).replace(microsecond=0).isoformat() if dias > 0 else None})
            jsave(WLFILE, wl)
            # se ja existe regra ativa para esse IP, retira agora
            st = jload(STATE, {}); net = ipaddress.ip_network(cidr, strict=False)
            for k in list(st.keys()):
                v = st[k]; cobre = any(ipaddress.ip_address(x) in net for x in (v.get("cpe"), v.get("c2")) if x)
                if cobre and (porta is None or (v.get("porta") == porta and (proto is None or v.get("proto") == proto))):
                    gobgp_del_regras(v.get("regras")); st.pop(k, None)
            jsave(STATE, st)
            return self._json(200, {"ok": True, "cidr": cidr, "porta": porta, "proto": proto})
        if p == "/whitelist/remove":
            wl = jload(WLFILE, []); n = len(wl)
            wl = [w for w in wl if w.get("id") != b.get("id")]
            jsave(WLFILE, wl)
            return self._json(200, {"ok": True, "removidos": n - len(wl)})
        return self._json(404, {"erro": "rota"})

class Srv6(ThreadingHTTPServer):
    import socket as _s
    address_family = _s.AF_INET6      # dual-stack: atende IPv4 e IPv6 (Linux, bindv6only=0)

if __name__ == "__main__":
    srv = None
    if ":" in BIND:
        try: srv = Srv6((BIND, PORT), H); print(f"flowspec-api em http://[{BIND}]:{PORT} (dual-stack)", file=sys.stderr)
        except OSError as e: print(f"IPv6 indisponivel ({e}); caindo para IPv4 0.0.0.0", file=sys.stderr); BIND = "0.0.0.0"
    if srv is None:
        srv = ThreadingHTTPServer((BIND, PORT), H); print(f"flowspec-api em http://{BIND}:{PORT}", file=sys.stderr)
    srv.serve_forever()
