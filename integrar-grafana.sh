#!/bin/bash
###############################################################################
# integrar-grafana.sh  -  Flowspec Solutions
#
# Roda na VM do GRAFANA (flowguard). NAO instala Grafana - ele ja existe.
# Faz: (1) branding white-label, (2) baixa e sincroniza os dashboards do
#      repositorio, remapeando os datasources pelos UIDs REAIS deste Grafana.
#
# NAO toca em Zabbix, MySQL nem no datasource elasticsearch ja configurado.
#
# Uso:  GRAFANA_PASS='senha-admin' ./integrar-grafana.sh
###############################################################################
set -euo pipefail

# =========================== AJUSTE AQUI =====================================
GRAFANA="${GRAFANA:-http://localhost:3000}"     # este Grafana usa porta 3000
GRAFANA_USER="${GRAFANA_USER:-admin}"
GRAFANA_PASS="${GRAFANA_PASS:-}"                 # export GRAFANA_PASS='...' antes
REPO="${REPO:-raphaelrrl/grafana}"               # repositorio dos dashboards/assets
BRANCH="${BRANCH:-main}"
DEST="${DEST:-/var/lib/grafana/dashboards}"      # pasta de provisioning
# =============================================================================

[ "$(id -u)" -eq 0 ] || { echo "Rode como root."; exit 1; }
[ -n "$GRAFANA_PASS" ] || { echo "Defina GRAFANA_PASS='senha-admin'."; exit 1; }

info() { echo -e "\n\033[0;36m== $1 ==\033[0m"; }

# Esta VM (flowguard) nao tem curl -> usamos wget, que ja esta instalado.
# Header Authorization (Basic preemptivo): o wget do Debian nao manda
# --user/--password sem desafio 401, entao montamos o header na mao.
GAUTH="Authorization: Basic $(printf '%s:%s' "$GRAFANA_USER" "$GRAFANA_PASS" | base64)"
gget() { wget -qO- --header="$GAUTH" "$@"; }

###############################################################################
info "1. Confirmar datasources existentes (nao alterar)"
###############################################################################
# So lista. O sync vai casar por TIPO, entao nao dependemos de UID fixo.
gget "$GRAFANA/api/datasources" | python3 -c "
import json,sys
ds=json.load(sys.stdin)
print('  datasources encontrados:')
for d in ds: print(f\"    {d['type']:40s} uid={d['uid']:20s} {d['name']}  {d.get('url','')}\")
" || { echo "Falha ao consultar a API do Grafana. Confira GRAFANA_PASS."; exit 1; }

###############################################################################
info "2. Provisioning de dashboards (pasta observada pelo Grafana)"
###############################################################################
# Cria o provider file se ainda nao existir (nao mexe em provider ja existente).
PROV=/etc/grafana/provisioning/dashboards/flowspec.yaml
mkdir -p "$DEST"
if [ ! -f "$PROV" ]; then
  tee "$PROV" > /dev/null << EOF
apiVersion: 1
providers:
  - name: 'flowspec'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: ${DEST}
EOF
  echo "  provider criado: $PROV"
else
  echo "  provider ja existe: $PROV (mantido)"
fi
chown -R grafana:grafana "$DEST"

###############################################################################
info "3. Baixar e sincronizar os dashboards (remapeando por TIPO de datasource)"
###############################################################################
# Baixa o repo por zip (sem depender da API do GitHub / sem rate limit),
# remapeia os UIDs de datasource dos JSON para os UIDs reais deste Grafana
# (casando por tipo; MySQL desambiguado pelo banco: zabbix x wanguard),
# deduplica por uid e grava na pasta de provisioning.
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
wget -q -O "$TMP/repo.zip" "https://codeload.github.com/$REPO/zip/refs/heads/$BRANCH"
unzip -q -j -o "$TMP/repo.zip" "*.json" -d "$TMP/json"
gget "$GRAFANA/api/datasources" > "$TMP/ds.json"

SRC="$TMP/json" DEST="$DEST" DS="$TMP/ds.json" python3 - << 'PY'
import json, os, re, sys, unicodedata, glob
src=os.environ["SRC"]; dest=os.environ["DEST"]; ds=json.load(open(os.environ["DS"]))
def by_type(t, db=None):
    c=[d for d in ds if d.get("type")==t]
    if db: c=[d for d in c if (d.get("jsonData",{}).get("database") or d.get("database") or "").lower()==db] or [d for d in c if db in d.get("name","").lower()] or c
    return c[0]["uid"] if c else None
LEGACY_MYSQL={"cfqk9ovp3fbpce":"zabbix","be7xq2m9kd4r0a":"wanguard"}
missing=set()
def target(t, uid_in, spec):
    if t=="mysql":
        dbn=(spec or {}).get("dataset") or LEGACY_MYSQL.get(uid_in) or "zabbix"; u=by_type("mysql", dbn.lower())
    elif t in ("datasource","grafana",None): return None
    else: u=by_type(t)
    if not u: missing.add(t)
    return u
def fix_ref(ref, t, spec):
    if not isinstance(ref,dict): return
    u=target(t, ref.get("name") or ref.get("uid"), spec)
    if u:
        if "name" in ref: ref["name"]=u
        if "uid" in ref: ref["uid"]=u
def walk(d):
    if "spec" in d:
        for e in d["spec"].get("elements",{}).values():
            for pq in e["spec"].get("data",{}).get("spec",{}).get("queries",[]):
                q=pq["spec"]["query"]; fix_ref(q.get("datasource"), q.get("group"), q.get("spec"))
        for v in d["spec"].get("variables",[]):
            q=v["spec"].get("query")
            if isinstance(q,dict): fix_ref(q.get("datasource"), q.get("group"), q.get("spec"))
            if v.get("kind")=="DatasourceVariable":
                u=target(v["spec"].get("pluginId"), (v["spec"].get("current") or {}).get("value"), None)
                if u and isinstance(v["spec"].get("current"),dict): v["spec"]["current"]["value"]=u
        for a in d["spec"].get("annotations",[]):
            q=a["spec"].get("query")
            if isinstance(q,dict): fix_ref(q.get("datasource"), q.get("group"), q.get("spec"))
    else:
        for p in d.get("panels",[]):
            for pp in [p]+p.get("panels",[]):
                dsr=pp.get("datasource")
                if isinstance(dsr,dict): fix_ref(dsr, dsr.get("type"), None)
                for tg in pp.get("targets",[]):
                    dsr=tg.get("datasource")
                    if isinstance(dsr,dict): fix_ref(dsr, dsr.get("type"), tg)
        for v in d.get("templating",{}).get("list",[]):
            dsr=v.get("datasource")
            if isinstance(dsr,dict): fix_ref(dsr, dsr.get("type"), None)
    return d
def slug(s):
    s=unicodedata.normalize("NFKD",s).encode("ascii","ignore").decode(); return re.sub(r"[^A-Za-z0-9]+","-",s).strip("-").lower() or "dashboard"
def num(x):
    try: return int(x)
    except: return 0
cands={}
for f in sorted(glob.glob(os.path.join(src,"*.json"))):
    b=os.path.basename(f)
    try: d=walk(json.load(open(f,encoding="utf-8")))
    except Exception as e: print(f"  IGNORADO: {b} -> {e}"); continue
    md=d.get("metadata",{}); uid=md.get("name") or d.get("uid"); title=d.get("spec",{}).get("title") or d.get("title") or uid
    if not uid: continue
    name=slug(title); key=(b==f"{name}.json", md.get("annotations",{}).get("grafana.app/updatedTimestamp",""), num(md.get("resourceVersion")), num(md.get("generation")), -len(b))
    cands.setdefault(uid,[]).append((key,b,name,d))
os.makedirs(dest,exist_ok=True)
for old in glob.glob(os.path.join(dest,"*.json")): os.remove(old)
for uid,lst in cands.items():
    lst.sort(key=lambda x:x[0], reverse=True); key,b,name,d=lst[0]
    for _,b2,_,_ in lst[1:]: print(f"  DUPLICADO {uid}: descartado {b2}")
    d.get("metadata",{}).get("annotations",{}).pop("grafana.app/folder",None)
    for k in ("folderUid","folderId","folderUID"): d.pop(k,None)
    json.dump(d, open(os.path.join(dest,f"{name}.json"),"w",encoding="utf-8"), ensure_ascii=False, indent=2)
    print(f"  OK  {name}.json")
print(f"\n  {len(cands)} dashboards em {dest}" + (f"\n  AVISO: sem datasource do tipo {sorted(missing)} neste Grafana" if missing else ""))
PY
chown -R grafana:grafana "$DEST"

echo ""
echo "Provisioning concluido. O Grafana recarrega em ate 10s."
echo "Confira: journalctl -u grafana-server --since '1 min ago' | grep -i provisioning.dashboard"
