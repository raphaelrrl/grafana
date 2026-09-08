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
# Porta do Grafana: le do grafana.ini (http_port); se nao houver, 3000. Sobrescreva com GRAFANA=http://host:porta
_GP=$(grep -E '^\s*http_port\s*=' /etc/grafana/grafana.ini 2>/dev/null | grep -oE '[0-9]+' | tail -1)
GRAFANA="${GRAFANA:-http://localhost:${_GP:-3000}}"
GRAFANA_USER="${GRAFANA_USER:-admin}"
GRAFANA_PASS="${GRAFANA_PASS:-}"
REPO="${REPO:-https://raw.githubusercontent.com/raphaelrrl/grafana/main}"
REPO_SLUG="${REPO_SLUG:-raphaelrrl/grafana}"
BRANCH="${BRANCH:-main}"
CHAMADO_URL="${CHAMADO_URL:-https://flowspec.net.br}"   # destino do item "Abrir chamado" no menu do Viewer
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
grep -q 'FLOWSPEC-APP' "$IDX" || sed -i 's|</head>|<style>/*FLOWSPEC-APP*/ body.app-grafana{background:url("public/build/img/flowspec_app_bg.svg") center/cover no-repeat fixed !important;} .main-view, .main-view > div, [class*="page-wrapper"], [class*="pageContent"]{background:transparent !important;}</style>\n</head>|' "$IDX"
# 3) rodape oculto (Documentation/Support/Community/versao)
grep -q 'FLOWSPEC-FOOTER' "$IDX" || sed -i 's|</head>|<style>/*FLOWSPEC-FOOTER*/ footer{display:none !important;}</style>\n</head>|' "$IDX"
# 4) esconder Share/Export/Help e itens de menu SO para Viewer
grep -q 'FLOWSPEC-UI' "$IDX" || sed -i 's|</head>|<style>/*FLOWSPEC-UI*/ body.fs-viewer [data-testid*="new share button"], body.fs-viewer [data-testid*="new export button"], body.fs-viewer [data-testid*="share-button"], body.fs-viewer button[aria-label="Help"], body.fs-viewer li:has(a[href^="/alerting"]), body.fs-viewer li:has(a[href^="/drilldown"]), body.fs-viewer li:has(a[href^="/bookmarks"]), body.fs-viewer li:has(a[href*="starred"]), body.fs-viewer *:has(> a[href^="/playlists"]), body.fs-viewer *:has(> a[href^="/library-panels"]), body.fs-viewer *:has(> a[href^="/dashboard/snapshots"]) {display:none !important;}</style>\n</head>|' "$IDX"
  # menu do usuario: esconde Profile / Notification history / Change theme SO para Viewer
  sed -i 's#<style>/\*FLOWSPEC-UMENU\*/[^<]*</style>##' "$IDX"
  sed -i 's|</head>|<style>/*FLOWSPEC-UMENU*/ body.fs-viewer li:has(> a[href="/profile"]), body.fs-viewer a[href="/profile"], body.fs-viewer li:has(> a[href^="/profile/notifications"]), body.fs-viewer a[href^="/profile/notifications"], body.fs-viewer li:has(> a[href^="/dashboard/public"]), body.fs-viewer li:has(> a[href^="/dashboard/recently-deleted"]), body.fs-viewer li:has(> a[href^="/playlists"]), body.fs-viewer li:has(> a[href^="/library-panels"]), body.fs-viewer li:has(> a[href^="/dashboard/snapshots"]), body.fs-viewer *:has(> input[placeholder^="Search"]), body.fs-viewer button[aria-label*="Search"], body.fs-viewer [role="dialog"]:has(input[placeholder^="Search or jump"]), body.fs-viewer [role="dialog"]:has(input[placeholder^="Pesquisar"]) {display:none !important;}</style>\n</head>|' "$IDX"
  # "Dashboards" -> "Abrir chamado" (site Flowspec) SO para Viewer; some com subitens
  sed -i 's#<script>/\*FLOWSPEC-CHAMADO\*/[^<]*</script>##' "$IDX"
  sed -i "s#</body>#<script>/*FLOWSPEC-CHAMADO*/(function(){var U=\"${CHAMADO_URL}\";function ren(){document.querySelectorAll(\"a[href^='/dashboards']\").forEach(function(a){a.dataset.fs=\"1\";var w=document.createTreeWalker(a,NodeFilter.SHOW_TEXT),n;while((n=w.nextNode())){if(n.nodeValue.trim()===\"Dashboards\")n.nodeValue=\"Abrir chamado\";}});document.querySelectorAll(\"[role='menu'] li, [role='menu'] a, [role='menu'] button, nav li, nav a, aside li, aside a\").forEach(function(el){var t=el.textContent.trim();if(/^(change theme|alterar tema|notification history|hist[oó]rico de notifica|profile|perfil|shared dashboards|dashboards compartilhados|recently deleted|exclu[ií]dos recentemente|playlists|library panels|pain[eé]is de biblioteca|snapshots|bookmarks|favoritos|starred|alerting|alertas)$/i.test(t)){var li=el.closest(\"li\")||el;li.style.setProperty(\"display\",\"none\",\"important\");}});}function f(){if(!document.body.classList.contains(\"fs-viewer\"))return;ren();}f();new MutationObserver(f).observe(document.body,{childList:true,subtree:true,characterData:true});document.addEventListener(\"click\",function(e){if(!document.body.classList.contains(\"fs-viewer\"))return;var a=e.target.closest\&\&e.target.closest(\"a[href^='/dashboards']\");if(!a)return;e.preventDefault();e.stopImmediatePropagation();window.open(U,\"_blank\",\"noopener\");},true);document.addEventListener(\"keydown\",function(e){if(!document.body.classList.contains(\"fs-viewer\"))return;if((e.ctrlKey||e.metaKey)\&\&(e.key===\"k\"||e.key===\"K\")){e.preventDefault();e.stopImmediatePropagation();}},true);})();</script></body>#" "$IDX"
  # Pagina 404 (Dashboard not found): traduz e remove o botao Community Help (vale para todos os papeis)
  sed -i 's#<script>/\*FLOWSPEC-404\*/[^<]*</script>##' "$IDX"
  sed -i "s#</body>#<script>/*FLOWSPEC-404*/(function(){var M={\"Dashboard not found\":\"Dashboard n\u00e3o encontrado\",\"We're looking but can't seem to find this dashboard. Please check the URL and try again.\":\"N\u00e3o encontramos este dashboard. Verifique o endere\u00e7o e tente novamente.\",\"Back to Home\":\"Voltar ao in\u00edcio\",\"Page not found\":\"P\u00e1gina n\u00e3o encontrada\",\"Not found\":\"N\u00e3o encontrado\",\"Sorry for the inconvenience\":\"Desculpe o transtorno\",\"Please try again or contact your administrator\":\"Tente novamente ou contate o administrador\"};function f(){var w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT),n;while((n=w.nextNode())){var t=n.nodeValue.trim();if(M[t]){n.nodeValue=n.nodeValue.replace(t,M[t]);}}document.querySelectorAll(\"a,button\").forEach(function(el){var t=el.textContent.trim();if(/^(community help|ajuda da comunidade)$/i.test(t)){el.style.setProperty(\"display\",\"none\",\"important\");}});}f();new MutationObserver(f).observe(document.body,{childList:true,subtree:true});})();</script></body>#" "$IDX"

# --- publicBaseUrl e sanitize no grafana.ini (idempotente)
GINI=/etc/grafana/grafana.ini
IPGRF=$(hostname -I | awk '{print $1}')
grep -qE '^;?\s*disable_sanitize_html' "$GINI" && sed -i 's/^;\?\s*disable_sanitize_html.*/disable_sanitize_html = true/' "$GINI" || sed -i '/^\[panels\]/a disable_sanitize_html = true' "$GINI"

# Branding gravado em disco: reinicia AGORA para carregar (antes de qualquer chamada a API).
systemctl restart grafana-server
# Espera o Grafana responder na porta (ate 60s) - logo apos restart/reinstall ele demora.
for i in $(seq 1 30); do
  wget -qO- --timeout=2 "$GRAFANA/api/health" 2>/dev/null | grep -q '"database"' && break
  sleep 2
done
wget -qO- --timeout=2 "$GRAFANA/api/health" 2>/dev/null | grep -q '"database"' || echo "  AVISO: Grafana nao respondeu em 60s; a etapa de dashboards pode falhar."

###############################################################################
info "B) DATASOURCES existentes (nao alterar)"
###############################################################################
gget "$GRAFANA/api/datasources" > "$TMP/ds.json"
if ! python3 -c "import json;[print(f\"  {d['type']:38s} {d['uid']:18s} {d['name']}\") for d in json.load(open('$TMP/ds.json'))]" 2>/dev/null; then
  echo "  Falha na API do Grafana (senha errada ou servico ainda subindo). Branding JA foi aplicado; dashboards NAO provisionados."
  echo "  Rode de novo em 1 minuto: GRAFANA_PASS='...' $0"
  rm -rf "$TMP"; exit 1
fi

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
    # HOME NOC como pagina inicial da organizacao (o Viewer entra direto no menu de modulos)
    HOME_UID="${HOME_UID:-aecn8csqbwdmob}"
    wget -qO- --header="$GAUTH" --header="Content-Type: application/json" --method=PUT \
      --body-data="{\"homeDashboardUID\":\"${HOME_UID}\"}" "$GRAFANA/api/org/preferences" >/dev/null 2>&1 \
      && echo "  Home da organizacao definido: dashboard ${HOME_UID}" || echo "  AVISO: nao consegui definir o home (verifique permissao de admin)."


###############################################################################
info "REINICIANDO o Grafana"
###############################################################################
systemctl restart grafana-server
echo ""
echo "Feito. Faça Ctrl+Shift+R no navegador (cache dos assets e agressivo)."
echo "Confira dashboards: journalctl -u grafana-server --since '1 min ago' | grep -i provisioning.dashboard"
