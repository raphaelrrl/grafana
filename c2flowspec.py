#!/usr/bin/env python3
"""
c2flowspec.py - Flowspec Solutions
Le os IPs de C2 detectados pelo c2scan (Elasticsearch, event.dataset=c2.findings)
e mantem regras BGP FlowSpec no GoBGP: anuncia novos, retira os expirados.

Fluxo:  c2scan -> Elastic (c2.findings) -> c2flowspec -> GoBGP -> peers FlowSpec (roteadores)

Uso:
  ES_PASS='...' ./c2flowspec.py --dry-run            # so mostra o que faria
  ES_PASS='...' ./c2flowspec.py                      # aplica
  ES_PASS='...' ./c2flowspec.py --categorias c2,anon # inclui Tor
  ES_PASS='...' ./c2flowspec.py --acao rate-limit --bps 100000   # limita em vez de descartar

Variaveis:
  ES_URL, ES_USER, ES_PASS, ES_CA, ES_INDEX (igual ao c2scan)
  WHITELIST  = CIDRs separados por virgula que NUNCA sao bloqueados (blocos do provedor, DNS)
  GOBGP_BIN  = caminho do gobgp (default: gobgp no PATH)
  STATE      = arquivo de estado (default /var/lib/flowspec/c2flowspec.json)
"""
import os, sys, ssl, json, base64, argparse, ipaddress, subprocess, datetime, urllib.request, urllib.error

ES_URL   = os.environ.get("ES_URL",  "https://127.0.0.1:9200")
ES_USER  = os.environ.get("ES_USER", "elastic")
ES_PASS  = os.environ.get("ES_PASS", "")
ES_CA    = os.environ.get("ES_CA",   "/etc/elasticsearch/certs/http_ca.crt")
ES_INDEX = os.environ.get("ES_INDEX","filebeat-*")
GOBGP    = os.environ.get("GOBGP_BIN","gobgp")
STATE    = os.environ.get("STATE","/var/lib/flowspec/c2flowspec.json")
# Nunca bloquear: blocos do provedor, resolvers, DNS publicos, RFC1918/CGNAT
WHITELIST_DEFAULT = "100.64.0.0/10,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,1.1.1.1/32,1.0.0.1/32,8.8.8.8/32,8.8.4.4/32,9.9.9.9/32,208.67.222.0/24,208.67.220.0/24"
WHITELIST = [ipaddress.ip_network(p.strip(), strict=False) for p in (os.environ.get("WHITELIST","") + "," + WHITELIST_DEFAULT).split(",") if p.strip()]

def log(m): print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {m}", file=sys.stderr)

# ---------------- Elasticsearch ----------------
def es_query(body):
    ctx = ssl.create_default_context(cafile=ES_CA) if os.path.exists(ES_CA) else ssl._create_unverified_context()
    auth = base64.b64encode(f"{ES_USER}:{ES_PASS.strip()}".encode()).decode()
    req = urllib.request.Request(f"{ES_URL}/{ES_INDEX}/_search", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"})
    try:
        with urllib.request.urlopen(req, timeout=120, context=ctx) as r: return json.load(r)
    except urllib.error.HTTPError as e:
        sys.exit(f"Elastic HTTP {e.code}: {e.read().decode()[:300]}")

def buscar_c2(horas, categorias, min_cpes):
    """IPs de C2 vistos nas ultimas N horas, com quantos CPEs distintos falaram com cada um."""
    body = {"size": 0,
      "query": {"bool": {"filter": [
          {"range": {"@timestamp": {"gte": f"now-{horas}h"}}},
          {"term": {"event.dataset": "c2.findings"}},
          {"term": {"event.action": "c2_contact"}},
          {"terms": {"threat.feed.name": categorias}}]}},
      "aggs": {"c2": {"terms": {"field": "destination.ip", "size": 10000},
               "aggs": {"cpes": {"cardinality": {"field": "source.ip"}},
                        "ultimo": {"max": {"field": "@timestamp"}},
                        "fontes": {"terms": {"field": "threat.indicator.provider", "size": 10}}}}}}
    r = es_query(body); out = {}
    for b in r["aggregations"]["c2"]["buckets"]:
        n = int(b["cpes"]["value"])
        if n < min_cpes: continue
        out[b["key"]] = {"cpes": n, "ultimo": b["ultimo"].get("value_as_string",""),
                         "fontes": "+".join(x["key"] for x in b["fontes"]["buckets"])}
    return out

# ---------------- GoBGP ----------------
def gobgp(args, dry):
    cmd = [GOBGP] + args
    if dry: log("DRY-RUN: " + " ".join(cmd)); return True
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0: log(f"gobgp ERRO: {' '.join(cmd)} -> {r.stderr.strip()}"); return False
    return True

PROTO_NUM = {"tcp": "6", "udp": "17"}
def regras(ip, acao, bps):
    """Lista de regras FlowSpec (args do gobgp) para um IP, respeitando whitelist parcial (porta/proto).
       Sem porta excluida: 2 regras (destino e origem). Com porta excluida P: 4 regras (porta <P e >P, nas duas direcoes)."""
    then = ["then", "discard"] if acao == "discard" else ["then", "rate-limit", str(bps)]
    exc = portas_excluidas(ip)
    out = []
    for sentido in ("dst", "src"):
        campo = "destination" if sentido == "dst" else "source"
        base = ["match", campo, f"{ip}/32"]
        if not exc:
            out.append(base + then); continue
        # trafego PARA o C2 usa destination-port; trafego VINDO do C2 usa source-port
        pcampo = "destination-port" if sentido == "dst" else "source-port"
        for porta, proto in exc:
            pr = ["protocol", PROTO_NUM[proto]] if proto in PROTO_NUM else []
            out.append(base + pr + [pcampo, f"<{porta}"] + then)
            out.append(base + pr + [pcampo, f">{porta}"] + then)
    return out

def anunciar(ip, acao, bps, dry):
    return all(gobgp(["global", "rib", "-a", "ipv4-flowspec", "add"] + r, dry) for r in regras(ip, acao, bps))

def retirar(ip, acao, bps, dry):
    return all(gobgp(["global", "rib", "-a", "ipv4-flowspec", "del"] + r, dry) for r in regras(ip, acao, bps))

# ---------------- estado ----------------
def carregar_estado():
    try: return json.load(open(STATE))
    except Exception: return {}
def salvar_estado(st):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    json.dump(st, open(STATE, "w"), indent=1)

WLFILE = os.environ.get("WLFILE", "/var/lib/flowspec/whitelist.json")
def carregar_wl():
    """Whitelist do dashboard (flowspec-api). Retorna (cidrs_totais, {ip_network: [(porta, proto), ...]})."""
    try: wl = json.load(open(WLFILE))
    except Exception: wl = []
    agora = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    totais, parciais = [], {}
    for w in wl:
        if w.get("ate") and w["ate"] < agora: continue        # expirada
        try: net = ipaddress.ip_network(w["cidr"], strict=False)
        except Exception: continue
        if w.get("porta"): parciais.setdefault(net, []).append((int(w["porta"]), (w.get("proto") or "").lower() or None))
        else: totais.append(net)
    return totais, parciais
WL_TOTAL, WL_PARCIAL = carregar_wl()

def na_whitelist(ip):
    a = ipaddress.ip_address(ip)
    return any(a in n for n in WHITELIST) or any(a in n for n in WL_TOTAL) or not a.is_global

def portas_excluidas(ip):
    """Portas que NAO devem ser bloqueadas para este IP (whitelist parcial)."""
    a = ipaddress.ip_address(ip); out = []
    for net, lst in WL_PARCIAL.items():
        if a in net: out += lst
    return out

# ---------------- main ----------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=24, help="janela dos achados no Elastic")
    ap.add_argument("--ttl", type=int, default=24, help="horas sem reaparecer para retirar a regra")
    ap.add_argument("--categorias", default="c2", help="categorias do c2scan a bloquear (c2,anon,hostil,malware)")
    ap.add_argument("--min-cpes", type=int, default=1, help="minimo de CPEs distintos falando com o IP")
    ap.add_argument("--max-regras", type=int, default=2000, help="teto de IPs anunciados (protege TCAM/CPU dos roteadores)")
    ap.add_argument("--acao", choices=["discard","rate-limit"], default="discard")
    ap.add_argument("--bps", type=int, default=100000, help="para --acao rate-limit (bytes/s)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if not ES_PASS: sys.exit("Defina ES_PASS")
    cats = [c.strip() for c in a.categorias.split(",") if c.strip()]

    achados = buscar_c2(a.hours, cats, a.min_cpes)
    estado  = carregar_estado()          # {ip: {"desde":..., "ultimo":..., "cpes":..., "fontes":...}}
    agora   = datetime.datetime.now(datetime.timezone.utc)
    novos = retirados = mantidos = ignorados = 0

    # 1) anunciar novos / atualizar vistos
    for ip, info in sorted(achados.items(), key=lambda x: -x[1]["cpes"]):
        if na_whitelist(ip): ignorados += 1; log(f"WHITELIST ignorado: {ip}"); continue
        if ip in estado:
            estado[ip].update({"ultimo": info["ultimo"], "cpes": info["cpes"], "fontes": info["fontes"], "visto": agora.isoformat()}); mantidos += 1
            continue
        if len(estado) >= a.max_regras: log(f"TETO {a.max_regras} atingido; {ip} nao anunciado"); continue
        if anunciar(ip, a.acao, a.bps, a.dry_run):
            estado[ip] = {"desde": agora.isoformat(), "visto": agora.isoformat(), **info}; novos += 1
            log(f"ANUNCIADO {ip}  cpes={info['cpes']}  fontes={info['fontes']}")

    # 2) retirar expirados (nao reapareceu ha mais de TTL horas)
    limite = agora - datetime.timedelta(hours=a.ttl)
    for ip in list(estado.keys()):
        visto = datetime.datetime.fromisoformat(estado[ip]["visto"])
        if ip not in achados and visto < limite:
            if retirar(ip, a.acao, a.bps, a.dry_run):
                del estado[ip]; retirados += 1; log(f"RETIRADO {ip} (expirou TTL {a.ttl}h)")

    if not a.dry_run: salvar_estado(estado)
    print(f"\nc2flowspec: novos={novos} mantidos={mantidos} retirados={retirados} whitelist={ignorados} | ativos={len(estado)} | acao={a.acao}{' (DRY-RUN)' if a.dry_run else ''}")

if __name__ == "__main__":
    main()
