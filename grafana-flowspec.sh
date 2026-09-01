#!/bin/bash
###############################################################################
# grafana-flowspec.sh  -  Flowspec Solutions
#
# Roda na VM do GRAFANA. Faz TUDO de uma vez:
#   A) BRANDING white-label (logo, favicon, fundo login/pos-login, titulos,
#      links, remocao do rodape, restricoes por papel Viewer)
#   B) DATASOURCES: so lista (nao altera os existentes)
#   C) DASHBOARDS: baixa do repo e provisiona, remapeando datasource por TIPO
#
# NAO instala Grafana, NAO toca Zabbix/MySQL/datasources existentes.
# Idempotente: pode rodar de novo sem duplicar nada.
#
# Uso:  GRAFANA_PASS='senha-admin' ./grafana-flowspec.sh
###############################################################################
set -uo pipefail   # sem -e: um sed que nao casa nao deve abortar o resto

# =========================== AJUSTE AQUI =====================================
GRAFANA="${GRAFANA:-http://localhost:3000}"
GRAFANA_USER="${GRAFANA_USER:-admin}"
GRAFANA_PASS="${GRAFANA_PASS:-}"
REPO="${REPO:-https://raw.githubusercontent.com/raphaelrrl/grafana/main}"
REPO_SLUG="${REPO_SLUG:-raphaelrrl/grafana}"
BRANCH="${BRANCH:-main}"
DEST="${DEST:-/var/lib/grafana/dashboards}"
GPUB="${GPUB:-/usr/share/grafana/public}"   # arvore public do grafana
# =============================================================================

[ "$(id -u)" -eq 0 ] || { echo "Rode como root."; exit 1; }
[ -n "$GRAFANA_PASS" ] || { echo "Defina GRAFANA_PASS='senha-admin'."; exit 1; }

info() { echo -e "\n\033[0;36m== $1 ==\033[0m"; }
GAUTH="Authorization: Basic $(printf '%s:%s' "$GRAFANA_USER" "$GRAFANA_PASS" | base64)"
gget() { wget -qO- --header="$GAUTH" "$@"; }

# ferramentas
command -v unzip >/dev/null || apt-get install -y unzip >/dev/null 2>&1
IM=$(command -v magick || command -v convert || true)   # imagemagick p/ redimensionar
[ -n "$IM" ] || { apt-get install -y imagemagick >/dev/null 2>&1; IM=$(command -v convert); }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

###############################################################################
info "A) BRANDING - baixando assets"
###############################################################################
wget -q -O "$TMP/logo.png" "$REPO/white_icon_transparent_background.png"
wget -q -O "$TMP/fav.png"  "$REPO/fav32.png"
wget -q -O "$TMP/bg_login.png" "$REPO/fundo_grafana-novo.png"
wget -q -O "$TMP/bg_app.png"   "$REPO/fundo_grafana-pos-login.png"

# --- Logo do card de login (grafana_icon.svg) -> PNG embutido em wrapper SVG
# (o destino e .svg; o grafana serve pelo content-type da extensao, entao
#  embutimos o PNG em base64 num SVG valido)
b64=$(base64 -w0 "$TMP/logo.png")
printf '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 512 512"><image width="512" height="512" preserveAspectRatio="xMidYMid meet" xlink:href="data:image/png;base64,%s"/></svg>' "$b64" > "$TMP/logo.svg"
find "$GPUB" -name 'grafana_icon*.svg' -exec cp "$TMP/logo.svg" {} \;
find "$GPUB" -name 'grafana_mask_icon*.svg' -exec cp "$TMP/logo.svg" {} \;

# --- Favicon e touch-icons
for t in $(find "$GPUB" -name 'fav32*.png'); do cp "$TMP/fav.png" "$t"; done
for t in $(find "$GPUB" -name 'apple-touch-icon*.png' -o -name 'touch-icon*.png'); do
  s=$(basename "$t" | grep -oE '[0-9]+x[0-9]+' | head -1); [ -n "$s" ] && $IM "$TMP/fav.png" -resize "$s" "$t" 2>/dev/null
done

# --- Fundo da tela de LOGIN (g8_login_dark/light) com width/height 100%
W=$(python3 -c "from struct import unpack;f=open('$TMP/bg_login.png','rb');d=f.read(33);w,h=unpack('>II',d[16:24]);print(w)")
H=$(python3 -c "from struct import unpack;f=open('$TMP/bg_login.png','rb');d=f.read(33);w,h=unpack('>II',d[16:24]);print(h)")
b64=$(base64 -w0 "$TMP/bg_login.png")
printf '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="100%%" height="100%%" viewBox="0 0 %s %s" preserveAspectRatio="xMidYMid slice"><image width="%s" height="%s" xlink:href="data:image/png;base64,%s"/></svg>' "$W" "$H" "$W" "$H" "$b64" > "$TMP/bg_login.svg"
find "$GPUB" -name 'g8_login_dark*.svg'  -exec cp "$TMP/bg_login.svg" {} \;
find "$GPUB" -name 'g8_login_light*.svg' -exec cp "$TMP/bg_login.svg" {} \;
find "$GPUB" -name 'g8_home_v2*.svg'     -exec cp "$TMP/bg_login.svg" {} \;

# --- Fundo POS-LOGIN: arquivo novo servido como estatico
Wp=$(python3 -c "from struct import unpack;f=open('$TMP/bg_app.png','rb');d=f.read(33);w,h=unpack('>II',d[16:24]);print(w)")
Hp=$(python3 -c "from struct import unpack;f=open('$TMP/bg_app.png','rb');d=f.read(33);w,h=unpack('>II',d[16:24]);print(h)")
b64=$(base64 -w0 "$TMP/bg_app.png")
printf '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="100%%" height="100%%" viewBox="0 0 %s %s" preserveAspectRatio="xMidYMid slice"><image width="%s" height="%s" xlink:href="data:image/png;base64,%s"/></svg>' "$Wp" "$Hp" "$Wp" "$Hp" "$b64" > "$GPUB/build/img/flowspec_app_bg.svg"

info "A) BRANDING - titulos, links e CSS"
# --- Titulos (Welcome to Grafana -> Flowspec)
find "$GPUB/build/" -name '*.js' -exec sed -i 's|AppTitle="Grafana"|AppTitle="Flowguard Anti-DDoS"|g' {} \;
find "$GPUB/build/" -name '*.js' -exec sed -i 's|LoginTitle="Welcome to Grafana"|LoginTitle="Flowspec Solutions"|g' {} \;
sed -i 's|<title>\[\[.AppTitle\]\]</title>|<title>Flowguard Anti-DDoS</title>|g' "$GPUB/views/index.html"

# --- Links grafana.com -> flowspec.net.br  (string literal, sem curinga)
find "$GPUB/build/" -name '*.js' -exec sed -i 's|https://grafana.com|https://flowspec.net.br|g' {} \;
find "$GPUB/build/" -name '*.js' -exec sed -i 's|https://community.grafana.com|https://flowspec.net.br|g' {} \;

# --- CSS no index.html: fundo login, fundo app, rodape oculto, restricoes Viewer
IDX="$GPUB/views/index.html"
# 1) marcar body como fs-viewer quando orgRole=Viewer (script)
grep -q 'FLOWSPEC-ROLE' "$IDX" || sed -i 's|</body>|<script>/*FLOWSPEC-ROLE*/(function(){var u=window.grafanaBootData\&\&window.grafanaBootData.user;if(u\&\&(u.orgRole==="Viewer"\|\|u.orgRole==="None")){document.body.classList.add("fs-viewer");}})();</script></body>|' "$IDX"
# 2) fundo pos-login (body) + contentores transparentes
grep -q 'FLOWSPEC-APP' "$IDX" || sed -i 's|</head>|<style>/*FLOWSPEC-APP*/ body.app-grafana{background:url("public/build/img/flowspec_app_bg.svg") center/cover no-repeat fixed !important;} .main-view, .main-view > div, [class*="page-wrapper"], [class*="pageContent"]{background:transparent !important;}</style></head>|' "$IDX"
# 3) rodape oculto (Documentation/Support/Community/versao)
grep -q 'FLOWSPEC-FOOTER' "$IDX" || sed -i 's|</head>|<style>/*FLOWSPEC-FOOTER*/ footer{display:none !important;}</style></head>|' "$IDX"
# 4) esconder Share/Export/Help e itens de menu SO para Viewer
grep -q 'FLOWSPEC-UI' "$IDX" || sed -i 's|</head>|<style>/*FLOWSPEC-UI*/ body.fs-viewer [data-testid*="new share button"], body.fs-viewer [data-testid*="new export button"], body.fs-viewer [data-testid*="share-button"], body.fs-viewer button[aria-label="Help"], body.fs-viewer li:has(a[href^="/alerting"]), body.fs-viewer li:has(a[href^="/drilldown"]), body.fs-viewer li:has(a[href^="/bookmarks"]), body.fs-viewer li:has(a[href*="starred"]), body.fs-viewer *:has(> a[href^="/playlists"]), body.fs-viewer *:has(> a[href^="/library-panels"]), body.fs-viewer *:has(> a[href^="/dashboard/snapshots"]) {display:none !important;}</style></head>|' "$IDX"

# --- publicBaseUrl e sanitize no grafana.ini (idempotente)
GINI=/etc/grafana/grafana.ini
IPGRF=$(hostname -I | awk '{print $1}')
grep -qE '^;?\s*disable_sanitize_html' "$GINI" && sed -i 's/^;\?\s*disable_sanitize_html.*/disable_sanitize_html = true/' "$GINI" || sed -i '/^\[panels\]/a disable_sanitize_html = true' "$GINI"

###############################################################################
info "B) DATASOURCES existentes (nao alterar)"
###############################################################################
gget "$GRAFANA/api/datasources" > "$TMP/ds.json"
python3 -c "import json;[print(f\"  {d['type']:38s} {d['uid']:18s} {d['name']}\") for d in json.load(open('$TMP/ds.json'))]" \
  || { echo "  Falha na API do Grafana - confira GRAFANA_PASS."; exit 1; }

###############################################################################
info "C) DASHBOARDS - provisioning + remapeamento por tipo"
###############################################################################
PROV=/etc/grafana/provisioning/dashboards/flowspec.yaml
mkdir -p "$DEST"
[ -f "$PROV" ] || tee "$PROV" > /dev/null << EOF
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

wget -q -O "$TMP/repo.zip" "https://codeload.github.com/$REPO_SLUG/zip/refs/heads/$BRANCH"
unzip -q -j -o "$TMP/repo.zip" "*.json" -d "$TMP/json"

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
print(f"\n  {len(cands)} dashboards em {dest}" + (f"\n  AVISO: sem datasource do tipo {sorted(missing)} (paineis desses tipos ficam vazios)" if missing else ""))
PY
chown -R grafana:grafana "$DEST" 2>/dev/null

###############################################################################
info "REINICIANDO o Grafana"
###############################################################################
systemctl restart grafana-server
echo ""
echo "Feito. Faça Ctrl+Shift+R no navegador (cache dos assets e agressivo)."
echo "Confira dashboards: journalctl -u grafana-server --since '1 min ago' | grep -i provisioning.dashboard"
