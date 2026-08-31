#!/usr/bin/env python3
"""
c2scan.py - cruza o NetFlow (Elasticsearch/Filebeat) com blocklists de C2 e lista
os IPs do bloco de clientes (CGNAT) que conversaram com C2 conhecido.

Uso:
  ES_PASS='senha' ./c2scan.py                     # ultimas 24h, saida em tabela
  ES_PASS='senha' ./c2scan.py --hours 72 --csv    # 72h, saida CSV
  ES_PASS='senha' ./c2scan.py --json              # JSON (integracao com Zabbix/n8n)
  ES_PASS='senha' ./c2scan.py --es-write          # grava no Elastic p/ o dashboard (usar no cron)

Fontes (abuse.ch): Feodo Tracker (C2 de botnets), ThreatFox (IOCs de malware), URLhaus (hosts de distribuicao).
Requer apenas python3. Roda no proprio servidor do Elastic.
"""
import os, sys, ssl, json, csv, argparse, urllib.request, base64, ipaddress, datetime, re

ES_URL   = os.environ.get("ES_URL",  "https://127.0.0.1:9200")
ES_USER  = os.environ.get("ES_USER", "elastic")
ES_PASS  = os.environ.get("ES_PASS", "")
ES_CA    = os.environ.get("ES_CA",   "/etc/elasticsearch/certs/http_ca.crt")
ES_INDEX = os.environ.get("ES_INDEX","filebeat-*")
PREFIX   = os.environ.get("PREFIXO", "100.64.0.0/10")

FONTES = {
    "feodo":     "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt",
    "threatfox": "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
    "urlhaus":   "https://urlhaus.abuse.ch/downloads/text_online/",
}
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "flowspec-c2scan/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")

def carregar_blocklists(fontes):
    ips = {}
    for nome, url in fontes.items():
        try:
            txt = fetch(url)
        except Exception as e:
            print(f"[aviso] {nome}: falha ao baixar ({e})", file=sys.stderr); continue
        n = 0
        for linha in txt.splitlines():
            if not linha or linha.startswith("#"): continue
            for ip in IP_RE.findall(linha):
                try:
                    a = ipaddress.ip_address(ip)
                    if a.is_global:
                        ips.setdefault(ip, set()).add(nome); n += 1
                except ValueError: pass
        print(f"[info] {nome}: {n} IPs", file=sys.stderr)
    return ips

def es_http(path, body=None, method="POST", ctype="application/json"):
    ctx = ssl.create_default_context(cafile=ES_CA) if os.path.exists(ES_CA) else ssl._create_unverified_context()
    auth = base64.b64encode(f"{ES_USER}:{ES_PASS.strip()}".encode()).decode()
    data = body.encode() if isinstance(body, str) else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(f"{ES_URL}{path}", data=data, method=method,
                                 headers={"Content-Type": ctype, "Authorization": f"Basic {auth}"})
    try:
        with urllib.request.urlopen(req, timeout=120, context=ctx) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        sys.exit(f"Elastic HTTP {e.code}: " + ("usuario/senha recusados (ES_USER/ES_PASS)" if e.code == 401 else e.read().decode()[:400]))

def es_query(body):
    return es_http(f"/{ES_INDEX}/_search", body)

def es_gravar(achados, horas):
    """Grava os achados no data stream do Filebeat (event.dataset=c2.findings) para o dashboard ler."""
    ds = es_http(f"/_data_stream/{ES_INDEX}", method="GET").get("data_streams", [])
    if not ds: sys.exit(f"nenhum data stream casando com {ES_INDEX}")
    alvo = os.environ.get("ES_OUT") or ds[0]["name"]
    agora = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    linhas = []
    for x in achados:
        doc = {"@timestamp": agora, "event": {"dataset": "c2.findings", "kind": "alert", "module": "flowspec", "action": "c2_contact"},
               "source": {"ip": x["cpe"]}, "destination": {"ip": x["c2"], "port": int(x["portas"].split(",")[0]) if x["portas"] else None},
               "network": {"bytes": x["bytes"], "packets": x["pacotes"]},
               "threat": {"indicator": {"provider": x["fontes"], "ip": x["c2"]}},
               "flowspec": {"flows": x["flows"], "janela_horas": horas, "ultimo_contato": x["ultimo_contato"], "portas": x["portas"]}}
        linhas.append(json.dumps({"create": {}})); linhas.append(json.dumps(doc))
    if not linhas:
        linhas = [json.dumps({"create": {}}), json.dumps({"@timestamp": agora, "event": {"dataset": "c2.heartbeat", "module": "flowspec"}, "flowspec": {"janela_horas": horas, "achados": 0}})]
    r = es_http(f"/{alvo}/_bulk", "\n".join(linhas) + "\n", ctype="application/x-ndjson")
    print(f"[info] gravados {len(achados)} achados em {alvo} (erros={r.get('errors')})", file=sys.stderr)

def buscar(ips, horas, lote=20000):
    """Para cada lote de IPs de C2, agrega source.ip (CPE) -> destination.ip (C2) com bytes/pacotes/flows."""
    achados = []
    lista = list(ips.keys())
    for i in range(0, len(lista), lote):
        parte = lista[i:i+lote]
        body = {
          "size": 0,
          "query": {"bool": {"filter": [
              {"range": {"@timestamp": {"gte": f"now-{horas}h"}}},
              {"term":  {"source.ip": PREFIX}},              # CIDR em campo ip
              {"terms": {"destination.ip": parte}}
          ]}},
          "aggs": {"cpe": {"terms": {"field": "source.ip", "size": 500, "order": {"bytes": "desc"}},
              "aggs": {"bytes": {"sum": {"field": "network.bytes"}},
                       "c2": {"terms": {"field": "destination.ip", "size": 50, "order": {"bytes": "desc"}},
                              "aggs": {"bytes": {"sum": {"field": "network.bytes"}},
                                       "pkts": {"sum": {"field": "network.packets"}},
                                       "portas": {"terms": {"field": "destination.port", "size": 5}},
                                       "ultimo": {"max": {"field": "@timestamp"}}}}}}}}
        r = es_query(body)
        for b in r["aggregations"]["cpe"]["buckets"]:
            for c in b["c2"]["buckets"]:
                achados.append({
                    "cpe": b["key"], "c2": c["key"],
                    "fontes": "+".join(sorted(ips.get(c["key"], []))),
                    "portas": ",".join(str(p["key"]) for p in c["portas"]["buckets"]),
                    "flows": c["doc_count"], "bytes": int(c["bytes"]["value"]), "pacotes": int(c["pkts"]["value"]),
                    "ultimo_contato": c["ultimo"].get("value_as_string", "")})
    achados.sort(key=lambda x: (-x["bytes"], x["cpe"]))
    return achados

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--csv", action="store_true"); ap.add_argument("--json", action="store_true")
    ap.add_argument("--fontes", default="feodo,threatfox,urlhaus")
    ap.add_argument("--es-write", action="store_true", help="grava os achados no Elastic (event.dataset=c2.findings)")
    a = ap.parse_args()
    if not ES_PASS: sys.exit("Defina ES_PASS")
    fontes = {k: v for k, v in FONTES.items() if k in a.fontes.split(",")}
    ips = carregar_blocklists(fontes)
    if not ips: sys.exit("Nenhuma blocklist carregada (sem acesso ao abuse.ch?)")
    achados = buscar(ips, a.hours)
    if a.es_write: es_gravar(achados, a.hours)
    if a.json:
        print(json.dumps({"gerado": datetime.datetime.now().isoformat(timespec="seconds"), "horas": a.hours,
                          "prefixo": PREFIX, "ips_blocklist": len(ips), "cpes": len({x['cpe'] for x in achados}),
                          "achados": achados}, ensure_ascii=False, indent=2)); return
    if a.csv:
        w = csv.DictWriter(sys.stdout, fieldnames=list(achados[0].keys()) if achados else ["cpe"]); w.writeheader(); w.writerows(achados); return
    print(f"\nblocklist: {len(ips)} IPs | janela: {a.hours}h | prefixo: {PREFIX}")
    if not achados: print("nenhum CPE com contato C2 no periodo.\n"); return
    print(f"CPEs com contato C2: {len({x['cpe'] for x in achados})}\n")
    print(f"{'CPE':16s} {'C2':16s} {'fonte':18s} {'portas':14s} {'flows':>6s} {'bytes':>11s} {'ultimo contato'}")
    for x in achados:
        print(f"{x['cpe']:16s} {x['c2']:16s} {x['fontes']:18s} {x['portas'][:14]:14s} {x['flows']:6d} {x['bytes']:11d} {x['ultimo_contato'][:19]}")
    print()

if __name__ == "__main__":
    main()
