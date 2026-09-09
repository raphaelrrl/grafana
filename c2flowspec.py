#!/usr/bin/env python3
"""
c2flowspec.py (v2) - Flowspec Solutions
Le os achados do c2scan (Elasticsearch, event.dataset=c2.findings) e mantem regras BGP FlowSpec
no GoBGP usando o VETOR COMPLETO de cada achado, para minimizar falso positivo:

   regra ida:   source = CPE/32  destination = C2/32  destination-port = P  protocol = X  -> discard
   regra volta: source = C2/32   destination = CPE/32 source-port = P       protocol = X  -> discard

So aquele fluxo especifico e descartado. Qualquer outro trafego para o mesmo IP passa.
Cada regra tem TTL (retirada se o par nao reaparece), teto global, whitelist (total e por porta) e dry-run.

Uso:
  ES_PASS='...' ./c2flowspec.py --dry-run
  ES_PASS='...' ./c2flowspec.py --categorias c2 --min-flows 3
  ES_PASS='...' ./c2flowspec.py --acao rate-limit --bps 10000

Variaveis: ES_URL ES_USER ES_PASS ES_CA ES_INDEX (como o c2scan), WHITELIST (CIDRs nunca bloqueados),
           WLFILE (whitelist do dashboard), GOBGP_BIN, STATE
"""
import os, sys, ssl, json, base64, argparse, ipaddress, subprocess, datetime, urllib.request, urllib.error

ES_URL   = os.environ.get("ES_URL",  "https://127.0.0.1:9200")
ES_USER  = os.environ.get("ES_USER", "elastic")
ES_PASS  = os.environ.get("ES_PASS", "")
ES_CA    = os.environ.get("ES_CA",   "/etc/elasticsearch/certs/http_ca.crt")
ES_INDEX = os.environ.get("ES_INDEX","filebeat-*")
GOBGP    = os.environ.get("GOBGP_BIN","gobgp")
STATE    = os.environ.get("STATE","/var/lib/flowspec/c2flowspec.json")
WLFILE   = os.environ.get("WLFILE","/var/lib/flowspec/whitelist.json")
WHITELIST_DEFAULT = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,1.1.1.1/32,1.0.0.1/32,8.8.8.8/32,8.8.4.4/32,9.9.9.9/32,208.67.222.0/24,208.67.220.0/24"
WHITELIST = [ipaddress.ip_network(p.strip(), strict=False) for p in (os.environ.get("WHITELIST","") + "," + WHITELIST_DEFAULT).split(",") if p.strip()]
PROTO_NUM = {"tcp": "6", "udp": "17", "icmp": "1"}

def log(m): print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {m}", file=sys.stderr)
def agora(): return datetime.datetime.now(datetime.timezone.utc)

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

def buscar_vetores(horas, categorias, min_flows):
    """Achados brutos: um vetor por (CPE, C2, porta, proto). Usa flowspec.portas/protos gravados pelo c2scan."""
    body = {"size": 5000, "_source": ["source.ip","destination.ip","destination.port","flowspec.portas","flowspec.protos","flowspec.flows","flowspec.fontes","@timestamp"],
      "query": {"bool": {"filter": [
          {"range": {"@timestamp": {"gte": f"now-{horas}h"}}},
          {"term": {"event.dataset": "c2.findings"}},
          {"term": {"event.action": "c2_contact"}},
          {"terms": {"threat.feed.name": categorias}}]}},
      "sort": [{"@timestamp": "desc"}]}
    r = es_query(body); vet = {}
    for h in r["hits"]["hits"]:
        d = h["_source"]; fs = d.get("flowspec", {})
        cpe = d.get("source", {}).get("ip"); c2 = d.get("destination", {}).get("ip")
        if not cpe or not c2: continue
        if int(fs.get("flows") or 0) < min_flows: continue
        portas = [p.strip() for p in str(fs.get("portas") or d.get("destination", {}).get("port") or "").split(",") if p.strip().isdigit()]
        protos = [p.strip() for p in str(fs.get("protos") or "").split(",") if p.strip() in PROTO_NUM]
        proto  = protos[0] if len(protos) == 1 else None    # so fixa protocolo se for inequivoco
        for p in portas or [None]:
            k = f"{cpe}>{c2}:{p or '*'}/{proto or '*'}"
            if k not in vet:
                vet[k] = {"cpe": cpe, "c2": c2, "porta": int(p) if p else None, "proto": proto,
                          "flows": int(fs.get("flows") or 0), "fontes": fs.get("fontes",""), "ultimo": d.get("@timestamp","")}
    return vet

# ---------------- whitelist ----------------
def carregar_wl():
    try: wl = json.load(open(WLFILE))
    except Exception: wl = []
    now = agora().replace(microsecond=0).isoformat()
    tot, par = [], {}
    for w in wl:
        if w.get("ate") and w["ate"] < now: continue
        try: net = ipaddress.ip_network(w["cidr"], strict=False)
        except Exception: continue
        if w.get("porta"): par.setdefault(net, []).append((int(w["porta"]), (w.get("proto") or "").lower() or None))
        else: tot.append(net)
    return tot, par
WL_TOTAL, WL_PARCIAL = carregar_wl()

def bloqueado_por_whitelist(v):
    """True se o vetor NAO pode ser bloqueado (IP na whitelist total, ou porta/proto liberados)."""
    c2 = ipaddress.ip_address(v["c2"])
    if not c2.is_global: return True                      # C2 nunca e IP privado
    if any(c2 in n for n in WHITELIST): return True       # DNS publicos etc.
    for ip in (v["cpe"], v["c2"]):
        a = ipaddress.ip_address(ip)
        if any(a in n for n in WL_TOTAL): return True
        for net, lst in WL_PARCIAL.items():
            if a in net and any((p == v["porta"]) and (pr is None or pr == v["proto"]) for p, pr in lst): return True
    return False

# ---------------- GoBGP ----------------
def gobgp(args, dry):
    cmd = [GOBGP] + args
    if dry: log("DRY-RUN: " + " ".join(cmd)); return True
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0: log(f"gobgp ERRO: {' '.join(cmd)} -> {r.stderr.strip()}"); return False
    return True

def regras(v, acao, bps):
    """Duas regras FlowSpec (ida e volta) com o vetor completo. Retorna lista de listas de args."""
    then = ["then", "discard"] if acao == "discard" else ["then", "rate-limit", str(bps)]
    pr = ["protocol", PROTO_NUM[v["proto"]]] if v.get("proto") else []
    ida   = ["match", "source", f"{v['cpe']}/32", "destination", f"{v['c2']}/32"] + pr
    volta = ["match", "source", f"{v['c2']}/32", "destination", f"{v['cpe']}/32"] + pr
    if v.get("porta"):
        ida   += ["destination-port", str(v["porta"])]
        volta += ["source-port", str(v["porta"])]
    return [ida + then, volta + then]

def aplicar(regs, op, dry):
    return all(gobgp(["global", "rib", "-a", "ipv4-flowspec", op] + r, dry) for r in regs)

# ---------------- estado ----------------
def carregar_estado():
    try: return json.load(open(STATE))
    except Exception: return {}
def salvar_estado(st):
    os.makedirs(os.path.dirname(STATE), exist_ok=True); json.dump(st, open(STATE, "w"), indent=1)

# ---------------- main ----------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--ttl", type=int, default=24, help="horas sem reaparecer para retirar")
    ap.add_argument("--categorias", default="c2")
    ap.add_argument("--min-flows", type=int, default=2, help="minimo de flows do par para bloquear")
    ap.add_argument("--max-regras", type=int, default=5000, help="teto de vetores (cada um = 2 regras FlowSpec)")
    ap.add_argument("--acao", choices=["discard","rate-limit"], default="discard")
    ap.add_argument("--bps", type=int, default=10000)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if not ES_PASS: sys.exit("Defina ES_PASS")
    import shutil
    if not a.dry_run and not shutil.which(GOBGP):
        sys.exit(f"gobgp nao encontrado ({GOBGP}). Este script precisa rodar no host do GoBGP (ou defina GOBGP_BIN=/caminho/gobgp). Use --dry-run para apenas simular.")
    cats = [c.strip() for c in a.categorias.split(",") if c.strip()]

    vet = buscar_vetores(a.hours, cats, a.min_flows)
    st = carregar_estado(); now = agora()
    novos = mant = ret = wl = 0

    for k, v in sorted(vet.items(), key=lambda x: -x[1]["flows"]):
        if bloqueado_por_whitelist(v): wl += 1; continue
        if k in st:
            st[k].update({"visto": now.isoformat(), "flows": v["flows"], "ultimo": v["ultimo"], "fontes": v["fontes"]}); mant += 1; continue
        if len(st) >= a.max_regras: log(f"TETO {a.max_regras}: {k} nao anunciado"); continue
        regs = regras(v, a.acao, a.bps)
        if aplicar(regs, "add", a.dry_run):
            st[k] = {**v, "chave": k, "desde": now.isoformat(), "visto": now.isoformat(), "acao": a.acao, "regras": regs}; novos += 1
            log(f"ANUNCIADO {k}  flows={v['flows']}  fontes={v['fontes']}")

    limite = now - datetime.timedelta(hours=a.ttl)
    for k in list(st.keys()):
        visto = datetime.datetime.fromisoformat(st[k]["visto"])
        if k not in vet and visto < limite:
            if aplicar(st[k].get("regras") or regras(st[k], st[k].get("acao","discard"), a.bps), "del", a.dry_run):
                del st[k]; ret += 1; log(f"RETIRADO {k} (TTL {a.ttl}h)")

    if not a.dry_run: salvar_estado(st)
    print(f"\nc2flowspec: novos={novos} mantidos={mant} retirados={ret} whitelist={wl} | vetores ativos={len(st)} (regras={2*len(st)}) | acao={a.acao}{' (DRY-RUN)' if a.dry_run else ''}")

if __name__ == "__main__":
    main()
