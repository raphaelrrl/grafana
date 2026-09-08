#!/bin/bash
###############################################################################
#  flowspec-full-install.sh   -   Flowspec Solutions
#  ---------------------------------------------------------------------------
#  Instalacao COMPLETA da solucao num UNICO host:
#     Elasticsearch + Kibana + Filebeat(netflow)  (coleta + analise)
#     Grafana (branding white-label + dashboards)
#     Zabbix (branding white-label)               (se ja instalado)
#     c2scan (deteccao de C2/botnet) + cron
#
#  FILOSOFIA (aprendida na homologacao):
#   - AUDITA antes de instalar. Nao reinstala o que ja existe (preserva dados).
#   - Nao toca em Zabbix/MySQL/Grafana que ja estejam em producao.
#   - Senhas do Elastic/Kibana sao GERADAS pelos comandos nativos e capturadas.
#   - Idempotente onde possivel. Para no primeiro erro real de instalacao.
#
#  Uso:
#     chmod +x flowspec-full-install.sh
#     ./flowspec-full-install.sh                 # tudo
#     ./flowspec-full-install.sh --so-branding   # so branding (grafana+zabbix)
#     ./flowspec-full-install.sh --so-c2scan     # so o c2scan+cron
#     ./flowspec-full-install.sh --auditar       # so audita, nao instala
#
#  Variaveis de ambiente (opcionais, tem default):
#     IP_HOST=192.168.x.x        # IP onde ES/Kibana escutam (auto se vazio)
#     GRAFANA_PASS=...           # senha admin do grafana (p/ dashboards)
#     REPO=https://raw.githubusercontent.com/raphaelrrl/grafana/main
#     REPO_SLUG=raphaelrrl/grafana
###############################################################################

# NAO usar 'set -e' global: queremos tratar cada etapa e continuar auditoria.
# Em blocos de instalacao criticos ativamos 'set -e' localmente.
set -uo pipefail

# ============================ PARAMETROS ======================================
REPO="${REPO:-https://raw.githubusercontent.com/raphaelrrl/grafana/main}"
REPO_SLUG="${REPO_SLUG:-raphaelrrl/grafana}"
BRANCH="${BRANCH:-main}"
CHAMADO_URL="${CHAMADO_URL:-https://flowspec.net.br}"   # destino do item "Abrir chamado" no menu do Viewer
_GP=$(grep -E '^\s*http_port\s*=' /etc/grafana/grafana.ini 2>/dev/null | grep -oE '[0-9]+' | tail -1)
GRAFANA_URL="${GRAFANA_URL:-http://localhost:${_GP:-3000}}"   # porta lida do grafana.ini
GRAFANA_USER="${GRAFANA_USER:-admin}"
GRAFANA_PASS="${GRAFANA_PASS:-}"
DASH_DEST="${DASH_DEST:-/var/lib/grafana/dashboards}"
ZBX_NAME="${ZBX_NAME:-Flowguard}"
MODO="${1:-tudo}"

# ============================ CORES/LOG =======================================
if [ -t 1 ]; then
  V="\033[0;32m"; A="\033[0;33m"; R="\033[0;31m"; C="\033[0;36m"; Z="\033[0m"
else V=""; A=""; R=""; C=""; Z=""; fi
titulo(){ echo -e "\n${C}=============== $1 ===============${Z}"; }
ok(){    echo -e "  ${V}[ OK ]${Z}  $1"; }
info(){  echo -e "  ${C}[INFO]${Z} $1"; }
aviso(){ echo -e "  ${A}[AVISO]${Z} $1"; }
erro(){  echo -e "  ${R}[ERRO]${Z} $1"; }
fatal(){ echo -e "  ${R}[FATAL]${Z} $1"; exit 1; }

[ "$(id -u)" -eq 0 ] || fatal "Rode como root."

# ============================ HELPERS =========================================
pkg(){ dpkg -l "$1" 2>/dev/null | grep -q '^ii'; }
svc_existe(){ systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "$1.service"; }
svc_ativo(){ systemctl is-active --quiet "$1"; }
# grafana nesta stack nao tem curl garantido -> usamos wget com header Basic
GAUTH=""; [ -n "$GRAFANA_PASS" ] && GAUTH="Authorization: Basic $(printf '%s:%s' "$GRAFANA_USER" "$GRAFANA_PASS" | base64)"
gget(){ wget -qO- --header="$GAUTH" "$@"; }

###############################################################################
#  ETAPA 0 - AUDITORIA (sempre roda; nao altera nada)
###############################################################################
auditar(){
  titulo "0. AUDITORIA DO AMBIENTE"
  local BLOQ=0

  # --- SO (homologado: Debian 12/13, Ubuntu 24.04/26.04) ---
  if [ -r /etc/os-release ]; then . /etc/os-release
    info "SO: $PRETTY_NAME"
    case "$ID:$VERSION_ID" in
      debian:12|debian:13|ubuntu:26.04|ubuntu:24.04) ok "Base homologada.";;
      *) aviso "Base fora das testadas; repo 8.x da Elastic deve funcionar, valide.";;
    esac
  fi

  # --- RAM (ES pede >=4GB; com Zabbix+Grafana junto, <8GB exige limitar JVM) ---
  RAM_MB=$(awk '/MemTotal/{printf "%d",$2/1024}' /proc/meminfo)
  info "RAM: ${RAM_MB} MB"
  if [ "$RAM_MB" -lt 4000 ]; then erro "RAM < 4GB. ES + Zabbix + Grafana juntos vao dar OOM."; BLOQ=$((BLOQ+1))
  elif [ "$RAM_MB" -lt 8000 ]; then aviso "RAM 4-8GB: vou limitar a JVM do ES a metade da RAM."; fi

  # --- Disco (indice netflow cresce rapido) ---
  DISCO=$(df -BG --output=avail / 2>/dev/null | tail -1 | tr -dc '0-9')
  info "Disco livre em / : ${DISCO} GB"
  [ "${DISCO:-0}" -lt 20 ] && aviso "Menos de 20GB livres; planeje retencao (ILM)."

  # --- Aplicacoes existentes (nao tocar) ---
  if pkg zabbix-server-mysql || svc_existe zabbix-server; then
    ZV=$(zabbix_server -V 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    ok "Zabbix presente (${ZV:-?}) - sera preservado; aplico so branding."
    TEM_ZABBIX=1
  else info "Zabbix ausente."; TEM_ZABBIX=0; fi

  if pkg grafana || svc_existe grafana-server; then
    GV=$(dpkg -l grafana 2>/dev/null | awk '/^ii/{print $3}')
    ok "Grafana presente (${GV:-?}) - preservado; aplico branding+dashboards."
    TEM_GRAFANA=1
  else info "Grafana ausente - sera instalado."; TEM_GRAFANA=0; fi

  svc_ativo mariadb || svc_ativo mysql && ok "Banco (MariaDB/MySQL) ativo - usado pelo Zabbix, NAO alterado."

  # --- Stack de coleta: instala so o que faltar ---
  for c in elasticsearch kibana filebeat; do
    if pkg "$c"; then
      aviso "$c JA instalado ($(dpkg -l $c|awk '/^ii/{print $3}')) - preservar, nao reinstalar."
      eval "TEM_${c^^}=1"
    else ok "$c ausente - livre para instalar."; eval "TEM_${c^^}=0"; fi
  done
  for dir in /var/lib/elasticsearch /var/lib/kibana; do
    [ -d "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ] && aviso "$dir tem dados anteriores - nao apagar."
  done

  # --- Conflito de portas (dono java=ES, MainThread=kibana sao esperados) ---
  checa_porta(){ local p="$1" esp="$2"; local l; l=$(ss -tlnp 2>/dev/null|grep -E "[:.]$p ")
    if [ -n "$l" ]; then local d; d=$(echo "$l"|grep -oE 'users:\(\("[^"]+'|grep -oE '"[^"]+'|tr -d '"'|head -1)
      if echo "$d"|grep -qiE "$esp|java|MainThread|node"; then ok "Porta $p usada por '$d' (esperado)."
      else erro "Porta $p OCUPADA por '$d' (esperava $esp)."; BLOQ=$((BLOQ+1)); fi
    else ok "Porta $p livre."; fi; }
  checa_porta 9200 elasticsearch
  checa_porta 5601 kibana
  ss -ulnp 2>/dev/null|grep -qE '[:.]2055 ' && aviso "UDP 2055 ja em uso (filebeat?)." || ok "UDP 2055 (netflow) livre."

  # --- Repo Elastic duplicado (quebra apt update) ---
  N=$(grep -rl 'artifacts.elastic.co' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null|grep -c .)
  [ "${N:-0}" -gt 1 ] && aviso "Repo Elastic em >1 arquivo (risco de Duplicate sources)."

  # --- Conectividade (repo + blocklists) ---
  wget -q -T8 -O /dev/null "https://artifacts.elastic.co/packages/8.x/apt/dists/stable/Release" 2>/dev/null \
    && ok "Alcanca repositorio Elastic 8.x" || aviso "Sem acesso a artifacts.elastic.co - libere saida HTTPS antes de instalar."
  wget -q -T8 -O /dev/null "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt" 2>/dev/null \
    && ok "Alcanca abuse.ch (blocklists)" || aviso "Sem acesso ao abuse.ch - c2scan sem blocklist ate liberar."

  export TEM_ZABBIX TEM_GRAFANA TEM_ELASTICSEARCH TEM_KIBANA TEM_FILEBEAT RAM_MB
  [ "$BLOQ" -gt 0 ] && return 1 || return 0
}

###############################################################################
#  ETAPA 1 - STACK DE COLETA (Elasticsearch + Kibana + Filebeat/netflow)
###############################################################################
instalar_stack(){
  titulo "1. STACK DE COLETA (Elastic/Kibana/Filebeat)"
  set -e   # nesta etapa, erro real deve abortar (nao deixar host meio-configurado)

  # IP onde ES/Kibana escutam (auto se nao informado)
  IP_HOST="${IP_HOST:-$(hostname -I | awk '{print $1}')}"
  info "IP para ES/Kibana: $IP_HOST"

  # --- 1.0 Dependencias + repositorio Elastic (entrada UNICA) ---
  apt-get update
  apt-get install -y apt-transport-https gnupg curl wget unzip
  mkdir -p /usr/share/keyrings
  [ -f /usr/share/keyrings/elasticsearch-keyring.gpg ] || \
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
  if ! grep -rq 'artifacts.elastic.co/packages/8.x' /etc/apt/sources.list.d/ /etc/apt/sources.list 2>/dev/null; then
    echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
      > /etc/apt/sources.list.d/elastic-8.x.list
  fi
  apt-get update

  # helper: seta chave no yml (substitui comentada/ativa; cria no fim se nao existir)
  setkv(){ local F="$1" K="$2" Vv="$3" E; E=$(echo "$K"|sed 's/\./\\./g')
    if grep -qE "^#?\s*${E}:" "$F"; then sed -i "s|^#\?\s*${E}:.*|${K}: ${Vv}|" "$F"
    else echo "${K}: ${Vv}" >> "$F"; fi; }

  # --- 1.1 Elasticsearch (so se ausente) ---
  if [ "${TEM_ELASTICSEARCH:-0}" = "1" ]; then aviso "ES ja instalado - preservando."
  else apt-get install -y elasticsearch; fi

  ESY=/etc/elasticsearch/elasticsearch.yml
  setkv "$ESY" cluster.name   "flow-huawei-mikrotik-cisco-juniper-frr"
  setkv "$ESY" node.name      "flow-01"
  setkv "$ESY" http.port      "9200"
  setkv "$ESY" network.host   "$IP_HOST"
  setkv "$ESY" discovery.type "single-node"
  # single-node exige que initial_master_nodes NAO esteja ativo
  sed -i 's/^\s*cluster\.initial_master_nodes:/#cluster.initial_master_nodes:/' "$ESY"
  # Limitar JVM se RAM < 8GB (nao competir com Zabbix/Grafana)
  if [ "${RAM_MB:-0}" -lt 8000 ]; then
    H=$(( RAM_MB/2/1024 )); [ "$H" -lt 1 ] && H=1
    mkdir -p /etc/elasticsearch/jvm.options.d
    printf -- "-Xms%sg\n-Xmx%sg\n" "$H" "$H" > /etc/elasticsearch/jvm.options.d/flowspec-heap.options
    info "JVM do ES limitada a ${H}g (RAM baixa)."
  fi
  systemctl enable elasticsearch
  systemctl restart elasticsearch
  sleep 8

  # --- 1.2 Senha do 'elastic' (GERADA pelo comando nativo, capturada) ---
  info "Gerando senha do usuario 'elastic' (comando nativo)..."
  ELASTIC_PW=$(/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -b -s)
  echo -e "  ${V}SENHA elastic: ${ELASTIC_PW}${Z}"
  echo "$ELASTIC_PW" > /root/.es_pass; chmod 600 /root/.es_pass
  info "Senha salva em /root/.es_pass (usada pelo filebeat e pelo c2scan)."

  # --- 1.3 Kibana (so se ausente) ---
  if [ "${TEM_KIBANA:-0}" = "1" ]; then aviso "Kibana ja instalado - preservando."
  else apt-get install -y kibana; fi
  cp -R /etc/elasticsearch/certs/ /etc/kibana/
  chown -R root:kibana /etc/kibana/certs
  chmod 640 /etc/kibana/certs/http_ca.crt

  KIBANA_PW=$(/usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -b -s)
  echo -e "  ${V}SENHA kibana_system: ${KIBANA_PW}${Z}"
  KBY=/etc/kibana/kibana.yml
  setkv "$KBY" server.port "5601"
  setkv "$KBY" server.host '"::"'
  setkv "$KBY" server.name '"kibana-flow"'
  sed -i 's|^#\?\s*elasticsearch\.hosts:.*|elasticsearch.hosts: ["https://localhost:9200"]|' "$KBY" || echo 'elasticsearch.hosts: ["https://localhost:9200"]' >> "$KBY"
  setkv "$KBY" elasticsearch.username '"kibana_system"'
  setkv "$KBY" elasticsearch.password "\"${KIBANA_PW}\""
  setkv "$KBY" server.publicBaseUrl "\"http://${IP_HOST}:5601\""
  sed -i 's|^#\?\s*elasticsearch\.ssl\.certificateAuthorities:.*|elasticsearch.ssl.certificateAuthorities: [ "/etc/kibana/certs/http_ca.crt" ]|' "$KBY" \
    || echo 'elasticsearch.ssl.certificateAuthorities: [ "/etc/kibana/certs/http_ca.crt" ]' >> "$KBY"
  systemctl enable kibana
  systemctl restart kibana

  # --- 1.4 Filebeat + modulo netflow (so se ausente) ---
  if [ "${TEM_FILEBEAT:-0}" = "1" ]; then aviso "Filebeat ja instalado - preservando."
  else apt-get install -y filebeat; fi
  cp -R /etc/elasticsearch/certs/ /etc/filebeat/

  # modulo netflow: internal_networks INCLUINDO CGNAT 100.64/10 (private nao cobre)
  tee /etc/filebeat/modules.d/netflow.yml > /dev/null << 'NFEOF'
- module: netflow
  log:
    enabled: true
    var:
      netflow_host: 0.0.0.0
      netflow_port: 2055
      internal_networks:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        - 100.64.0.0/10
      max_message_size: 10MiB
      protocols: [v5, v9, ipfix]
      expiration_timeout: 30m
      queue_size: 8192
      detect_sequence_reset: true
NFEOF

  # filebeat.yml: saida ES via HTTPS+CA, usuario elastic + senha capturada
  FBY=/etc/filebeat/filebeat.yml
  sed -i 's|^\s*#\?\s*host: "localhost:5601"|  host: "localhost:5601"|' "$FBY"
  sed -i 's|^\s*#\?\s*protocol: "https"|  protocol: "https"|' "$FBY"
  sed -i 's|^\s*#\?\s*username: "elastic"|  username: "elastic"|' "$FBY"
  sed -i "s|^\s*#\?\s*password: \"changeme\"|  password: \"${ELASTIC_PW}\"|" "$FBY"
  grep -qE '^\s{2}ssl\.certificate_authorities' "$FBY" || \
    sed -i "/^  password: \"${ELASTIC_PW}\"/a\\  ssl.certificate_authorities: [\"/etc/filebeat/certs/http_ca.crt\"]" "$FBY"

  filebeat test config
  filebeat test output || aviso "filebeat test output falhou - verifique CA/senha."
  filebeat modules enable netflow
  filebeat setup || aviso "filebeat setup teve erro - rode manualmente depois."
  systemctl enable --now filebeat

  set +e
  ok "Stack de coleta instalado. ES=$IP_HOST:9200  Kibana=$IP_HOST:5601"
}

###############################################################################
#  ETAPA 2 - c2scan (deteccao de C2/botnet) + cron
###############################################################################
instalar_c2scan(){
  titulo "2. c2scan (deteccao de C2/botnet)"
  # Baixa o c2scan do repo (versao com autodescoberta do data stream)
  wget -qO /root/c2scan.py "$REPO/c2scan.py" || { erro "download do c2scan falhou."; return 1; }

  # Senha do elastic (de /root/.es_pass, gerada na etapa do stack)
  [ -r /root/.es_pass ] || { aviso "sem /root/.es_pass - rode a etapa do stack antes, ou crie o arquivo."; return 1; }

  IP_HOST="${IP_HOST:-$(hostname -I | awk '{print $1}')}"
  CA=/etc/elasticsearch/certs/http_ca.crt

  # Primeira execucao (24h) para popular
  info "Primeira varredura (24h)..."
  ES_URL="https://${IP_HOST}:9200" ES_CA="$CA" ES_PASS="$(cat /root/.es_pass)" \
    python3 /root/c2scan.py --hours 24 --scan --es-write || aviso "c2scan retornou erro (sem flow ainda?)."

  # Cron: de hora em hora, janela de 2h (sobreposta), com scan e todas as fontes
  CRON_LINE='15 * * * * ES_URL="https://'"${IP_HOST}"':9200" ES_CA="'"$CA"'" ES_PASS=$(cat /root/.es_pass) python3 /root/c2scan.py --hours 2 --scan --es-write >> /var/log/c2scan.log 2>&1'
  ( crontab -l 2>/dev/null | grep -v c2scan; echo "$CRON_LINE" ) | crontab -
  ok "c2scan instalado e agendado (cron a cada hora, janela 2h)."
}

###############################################################################
#  ETAPA 3 - BRANDING + DASHBOARDS do GRAFANA
###############################################################################
instalar_grafana(){
  titulo "3. GRAFANA (branding + dashboards)"
  GPUB=/usr/share/grafana/public
  [ -d "$GPUB" ] || { aviso "Grafana public nao encontrado ($GPUB) - pulei branding."; return 1; }

  IM=$(command -v magick || command -v convert || true)
  [ -n "$IM" ] || { apt-get install -y imagemagick >/dev/null 2>&1; IM=$(command -v convert); }

  local T; T=$(mktemp -d)
  wget -q -O "$T/logo.png" "$REPO/white_icon_transparent_background.png"
  wget -q -O "$T/fav.png"  "$REPO/fav32.png"
  wget -q -O "$T/bglogin.png" "$REPO/fundo_grafana-novo.png"
  wget -q -O "$T/bgapp.png"   "$REPO/fundo_grafana-pos-login.png"

  # --- logo (PNG embutido em wrapper SVG, pois destino e .svg) ---
  b=$(base64 -w0 "$T/logo.png")
  printf '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 512 512"><image width="512" height="512" preserveAspectRatio="xMidYMid meet" xlink:href="data:image/png;base64,%s"/></svg>' "$b" > "$T/logo.svg"
  find "$GPUB" -name 'grafana_icon*.svg' -exec cp "$T/logo.svg" {} \;
  find "$GPUB" -name 'grafana_mask_icon*.svg' -exec cp "$T/logo.svg" {} \;
  find "$GPUB" -name 'grot-not-found*.svg' -exec cp "$T/logo.svg" {} \;   # mascote da pagina 404 -> logo Flowspec

  # --- favicon ---
  for t in $(find "$GPUB" -name 'fav32*.png'); do cp "$T/fav.png" "$t"; done

  # --- fundo LOGIN (com width/height 100% para preencher) ---
  W=$(python3 -c "from struct import unpack;d=open('$T/bglogin.png','rb').read(33);w,h=unpack('>II',d[16:24]);print(w)")
  H=$(python3 -c "from struct import unpack;d=open('$T/bglogin.png','rb').read(33);w,h=unpack('>II',d[16:24]);print(h)")
  b=$(base64 -w0 "$T/bglogin.png")
  printf '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="100%%" height="100%%" viewBox="0 0 %s %s" preserveAspectRatio="xMidYMid slice"><image width="%s" height="%s" xlink:href="data:image/png;base64,%s"/></svg>' "$W" "$H" "$W" "$H" "$b" > "$T/bglogin.svg"
  find "$GPUB" -name 'g8_login_dark*.svg'  -exec cp "$T/bglogin.svg" {} \;
  find "$GPUB" -name 'g8_login_light*.svg' -exec cp "$T/bglogin.svg" {} \;

  # --- fundo POS-LOGIN (arquivo novo servido) ---
  Wp=$(python3 -c "from struct import unpack;d=open('$T/bgapp.png','rb').read(33);w,h=unpack('>II',d[16:24]);print(w)")
  Hp=$(python3 -c "from struct import unpack;d=open('$T/bgapp.png','rb').read(33);w,h=unpack('>II',d[16:24]);print(h)")
  b=$(base64 -w0 "$T/bgapp.png")
  printf '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="100%%" height="100%%" viewBox="0 0 %s %s" preserveAspectRatio="xMidYMid slice"><image width="%s" height="%s" xlink:href="data:image/png;base64,%s"/></svg>' "$Wp" "$Hp" "$Wp" "$Hp" "$b" > "$GPUB/build/img/flowspec_app_bg.svg"

  # --- titulos e links ---
  find "$GPUB/build/" -name '*.js' -exec sed -i 's|AppTitle="Grafana"|AppTitle="Flowguard Anti-DDoS"|g' {} \;
  find "$GPUB/build/" -name '*.js' -exec sed -i 's|LoginTitle="Welcome to Grafana"|LoginTitle="Flowspec Solutions"|g' {} \;
  sed -i 's|<title>\[\[.AppTitle\]\]</title>|<title>Flowguard Anti-DDoS</title>|g' "$GPUB/views/index.html"
  find "$GPUB/build/" -name '*.js' -exec sed -i 's|https://grafana.com|https://flowspec.net.br|g' {} \;
  find "$GPUB/build/" -name '*.js' -exec sed -i 's|https://community.grafana.com|https://flowspec.net.br|g' {} \;

  # --- CSS no index.html (idempotente por marcador) ---
  IDX="$GPUB/views/index.html"
  # fundo de LOGIN (via CSS, pois o Grafana 13 nao usa a imagem direto)
  grep -q 'FLOWSPEC-LOGIN-BG' "$IDX" || sed -i 's|</head>|<style>/*FLOWSPEC-LOGIN-BG*/ body:has(.signin-container){background:url("public/build/img/g8_login_dark.svg") center/cover no-repeat fixed !important;}</style>\n</head>|' "$IDX"
  # fundo POS-LOGIN
  grep -q 'FLOWSPEC-APP' "$IDX" || sed -i 's|</head>|<style>/*FLOWSPEC-APP*/ body.app-grafana{background:url("public/build/img/flowspec_app_bg.svg") center/cover no-repeat fixed !important;} .main-view, .main-view > div, [class*="page-wrapper"], [class*="pageContent"]{background:transparent !important;}</style>\n</head>|' "$IDX"
  # rodape oculto
  grep -q 'FLOWSPEC-FOOTER' "$IDX" || sed -i 's|</head>|<style>/*FLOWSPEC-FOOTER*/ footer{display:none !important;}</style>\n</head>|' "$IDX"
  # marca body como fs-viewer para orgRole=Viewer
  grep -q 'FLOWSPEC-ROLE' "$IDX" || sed -i 's|</body>|<script>/*FLOWSPEC-ROLE*/(function(){var u=window.grafanaBootData\&\&window.grafanaBootData.user;if(u\&\&(u.orgRole==="Viewer"\|\|u.orgRole==="None")){document.body.classList.add("fs-viewer");}})();</script></body>|' "$IDX"
  # esconde Share/Export/Help/menus SO para Viewer
  grep -q 'FLOWSPEC-UI' "$IDX" || sed -i 's|</head>|<style>/*FLOWSPEC-UI*/ body.fs-viewer [data-testid*="new share button"], body.fs-viewer [data-testid*="new export button"], body.fs-viewer button[aria-label="Help"], body.fs-viewer li:has(a[href^="/alerting"]), body.fs-viewer li:has(a[href^="/drilldown"]), body.fs-viewer li:has(a[href^="/bookmarks"]), body.fs-viewer li:has(a[href*="starred"]) {display:none !important;}</style>\n</head>|' "$IDX"
  # menu do usuario: esconde Profile / Notification history / Change theme SO para Viewer
  sed -i 's#<style>/\*FLOWSPEC-UMENU\*/[^<]*</style>##' "$IDX"
  sed -i 's|</head>|<style>/*FLOWSPEC-UMENU*/ body.fs-viewer li:has(> a[href="/profile"]), body.fs-viewer a[href="/profile"], body.fs-viewer li:has(> a[href^="/profile/notifications"]), body.fs-viewer a[href^="/profile/notifications"], body.fs-viewer li:has(> a[href^="/dashboard/public"]), body.fs-viewer li:has(> a[href^="/dashboard/recently-deleted"]), body.fs-viewer li:has(> a[href^="/playlists"]), body.fs-viewer li:has(> a[href^="/library-panels"]), body.fs-viewer li:has(> a[href^="/dashboard/snapshots"]), body.fs-viewer *:has(> input[placeholder^="Search"]), body.fs-viewer button[aria-label*="Search"], body.fs-viewer [role="dialog"]:has(input[placeholder^="Search or jump"]), body.fs-viewer [role="dialog"]:has(input[placeholder^="Pesquisar"]) {display:none !important;}</style>\n</head>|' "$IDX"
  # "Dashboards" -> "Abrir chamado" (site Flowspec) SO para Viewer; some com subitens
  sed -i 's#<script>/\*FLOWSPEC-CHAMADO\*/[^<]*</script>##' "$IDX"
  sed -i "s#</body>#<script>/*FLOWSPEC-CHAMADO*/(function(){var U=\"${CHAMADO_URL}\";function ren(){document.querySelectorAll(\"a[href^='/dashboards']\").forEach(function(a){a.dataset.fs=\"1\";var w=document.createTreeWalker(a,NodeFilter.SHOW_TEXT),n;while((n=w.nextNode())){if(n.nodeValue.trim()===\"Dashboards\")n.nodeValue=\"Abrir chamado\";}});document.querySelectorAll(\"[role='menu'] li, [role='menu'] a, [role='menu'] button, nav li, nav a, aside li, aside a\").forEach(function(el){var t=el.textContent.trim();if(/^(change theme|alterar tema|notification history|hist[oó]rico de notifica|profile|perfil|shared dashboards|dashboards compartilhados|recently deleted|exclu[ií]dos recentemente|playlists|library panels|pain[eé]is de biblioteca|snapshots|bookmarks|favoritos|starred|alerting|alertas)$/i.test(t)){var li=el.closest(\"li\")||el;li.style.setProperty(\"display\",\"none\",\"important\");}});}function f(){if(!document.body.classList.contains(\"fs-viewer\"))return;ren();}f();new MutationObserver(f).observe(document.body,{childList:true,subtree:true,characterData:true});document.addEventListener(\"click\",function(e){if(!document.body.classList.contains(\"fs-viewer\"))return;var a=e.target.closest\&\&e.target.closest(\"a[href^='/dashboards']\");if(!a)return;e.preventDefault();e.stopImmediatePropagation();window.open(U,\"_blank\",\"noopener\");},true);document.addEventListener(\"keydown\",function(e){if(!document.body.classList.contains(\"fs-viewer\"))return;if((e.ctrlKey||e.metaKey)\&\&(e.key===\"k\"||e.key===\"K\")){e.preventDefault();e.stopImmediatePropagation();}},true);})();</script></body>#" "$IDX"
  # Pagina 404 (Dashboard not found): traduz e remove o botao Community Help (vale para todos os papeis)
  sed -i 's#<script>/\*FLOWSPEC-404\*/[^<]*</script>##' "$IDX"
  sed -i "s#</body>#<script>/*FLOWSPEC-404*/(function(){var M={\"Dashboard not found\":\"Menu não localizado\",\"We're looking but can't seem to find this dashboard. Please check the URL and try again.\":\"Acesse no menu abaixo para voltar.\",\"Back to Home\":\"Voltar ao início\",\"Page not found\":\"Menu não localizado\",\"Not found\":\"Não localizado\",\"Sorry for the inconvenience\":\"Desculpe o transtorno\",\"Please try again or contact your administrator\":\"Tente novamente ou contate o administrador\"};function f(){var w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT),n;while((n=w.nextNode())){var t=n.nodeValue.trim();if(M[t]){n.nodeValue=n.nodeValue.replace(t,M[t]);}}document.querySelectorAll(\"a,button\").forEach(function(el){var t=el.textContent.trim();if(/^(community help|ajuda da comunidade)$/i.test(t)){el.style.setProperty(\"display\",\"none\",\"important\");}});}f();new MutationObserver(f).observe(document.body,{childList:true,subtree:true});})();</script></body>#" "$IDX"

  # --- sanitize html on (para paineis Business Text) ---
  GINI=/etc/grafana/grafana.ini
  grep -qE '^;?\s*disable_sanitize_html' "$GINI" && sed -i 's/^;\?\s*disable_sanitize_html.*/disable_sanitize_html = true/' "$GINI" || sed -i '/^\[panels\]/a disable_sanitize_html = true' "$GINI"

  # Branding gravado: reinicia e ESPERA o Grafana responder antes de chamar a API
  systemctl restart grafana-server
  for i in $(seq 1 30); do
    wget -qO- --timeout=2 "$GRAFANA_URL/api/health" 2>/dev/null | grep -q '"database"' && break; sleep 2
  done

  # --- DASHBOARDS: provisioning + remapeamento por tipo ---
  if [ -n "$GAUTH" ]; then
    PROV=/etc/grafana/provisioning/dashboards/flowspec.yaml
    mkdir -p "$DASH_DEST"
    [ -f "$PROV" ] || cat > "$PROV" << PEOF
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
      path: ${DASH_DEST}
PEOF
    wget -q -O "$T/repo.zip" "https://codeload.github.com/$REPO_SLUG/zip/refs/heads/$BRANCH"
    unzip -q -j -o "$T/repo.zip" "*.json" -d "$T/json"
    gget "$GRAFANA_URL/api/datasources" > "$T/ds.json"
    SRC="$T/json" DEST="$DASH_DEST" DS="$T/ds.json" python3 - << 'PYEOF'
import json,os,re,glob,unicodedata
src=os.environ["SRC"];dest=os.environ["DEST"];ds=json.load(open(os.environ["DS"]))
def by_type(t,db=None):
    c=[d for d in ds if d.get("type")==t]
    if db: c=[d for d in c if (d.get("jsonData",{}).get("database") or d.get("database") or "").lower()==db] or [d for d in c if db in d.get("name","").lower()] or c
    return c[0]["uid"] if c else None
LEG={"cfqk9ovp3fbpce":"zabbix","be7xq2m9kd4r0a":"wanguard"}
def tgt(t,u,sp):
    if t=="mysql": return by_type("mysql",(sp or {}).get("dataset") or LEG.get(u) or "zabbix")
    if t in ("datasource","grafana",None): return None
    return by_type(t)
def fix(r,t,sp):
    if not isinstance(r,dict):return
    u=tgt(t,r.get("name") or r.get("uid"),sp)
    if u:
        if "name" in r:r["name"]=u
        if "uid" in r:r["uid"]=u
def walk(d):
    if "spec" in d:
        for e in d["spec"].get("elements",{}).values():
            for pq in e["spec"].get("data",{}).get("spec",{}).get("queries",[]):
                q=pq["spec"]["query"];fix(q.get("datasource"),q.get("group"),q.get("spec"))
        for v in d["spec"].get("variables",[]):
            q=v["spec"].get("query")
            if isinstance(q,dict):fix(q.get("datasource"),q.get("group"),q.get("spec"))
            if v.get("kind")=="DatasourceVariable":
                u=tgt(v["spec"].get("pluginId"),(v["spec"].get("current") or {}).get("value"),None)
                if u and isinstance(v["spec"].get("current"),dict):v["spec"]["current"]["value"]=u
    else:
        for p in d.get("panels",[]):
            for pp in [p]+p.get("panels",[]):
                if isinstance(pp.get("datasource"),dict):fix(pp["datasource"],pp["datasource"].get("type"),None)
                for tg in pp.get("targets",[]):
                    if isinstance(tg.get("datasource"),dict):fix(tg["datasource"],tg["datasource"].get("type"),tg)
        for v in d.get("templating",{}).get("list",[]):
            if isinstance(v.get("datasource"),dict):fix(v["datasource"],v["datasource"].get("type"),None)
    return d
def slug(s):
    s=unicodedata.normalize("NFKD",s).encode("ascii","ignore").decode();return re.sub(r"[^A-Za-z0-9]+","-",s).strip("-").lower() or "dashboard"
def num(x):
    try:return int(x)
    except:return 0
cand={}
for f in sorted(glob.glob(os.path.join(src,"*.json"))):
    b=os.path.basename(f)
    try:d=walk(json.load(open(f,encoding="utf-8")))
    except:continue
    md=d.get("metadata",{});uid=md.get("name") or d.get("uid");title=d.get("spec",{}).get("title") or d.get("title") or uid
    if not uid:continue
    nm=slug(title);key=(b==nm+".json",md.get("annotations",{}).get("grafana.app/updatedTimestamp",""),num(md.get("resourceVersion")),num(md.get("generation")),-len(b))
    cand.setdefault(uid,[]).append((key,b,nm,d))
os.makedirs(dest,exist_ok=True)
for o in glob.glob(os.path.join(dest,"*.json")):os.remove(o)
for uid,l in cand.items():
    l.sort(key=lambda x:x[0],reverse=True);_,b,nm,d=l[0]
    d.get("metadata",{}).get("annotations",{}).pop("grafana.app/folder",None)
    for k in ("folderUid","folderId","folderUID"):d.pop(k,None)
    json.dump(d,open(os.path.join(dest,nm+".json"),"w",encoding="utf-8"),ensure_ascii=False,indent=2)
print(f"  {len(cand)} dashboards provisionados")
PYEOF
    chown -R grafana:grafana "$DASH_DEST" 2>/dev/null
    # HOME NOC como pagina inicial da organizacao (o Viewer entra direto no menu de modulos)
    HOME_UID="${HOME_UID:-aecn8csqbwdmob}"
    wget -qO- --header="$GAUTH" --header="Content-Type: application/json" --method=PUT \
      --body-data="{\"homeDashboardUID\":\"${HOME_UID}\"}" "$GRAFANA_URL/api/org/preferences" >/dev/null 2>&1 \
      && echo "  Home da organizacao definido: dashboard ${HOME_UID}" || echo "  AVISO: nao consegui definir o home (verifique permissao de admin)."

    ok "Dashboards provisionados em $DASH_DEST"
  else
    aviso "GRAFANA_PASS nao definida - branding aplicado, mas dashboards NAO provisionados."
  fi

  rm -rf "$T"
  systemctl restart grafana-server
  ok "Grafana: branding aplicado. Faca Ctrl+Shift+R no navegador."
}

###############################################################################
#  ETAPA 4 - BRANDING do ZABBIX (so se ja instalado; nunca instala Zabbix)
###############################################################################
instalar_zabbix_branding(){
  titulo "4. ZABBIX (branding white-label)"
  # Autodeteccao do frontend
  local ZBX=""
  if [ -d /usr/share/zabbix ] && [ -f /usr/share/zabbix/index.php ]; then ZBX=/usr/share/zabbix
  else ZBX=$(dpkg -L zabbix-frontend-php 2>/dev/null | grep -m1 '/index.php$' | xargs -r dirname); fi
  [ -n "$ZBX" ] && [ -d "$ZBX" ] || { info "Zabbix frontend nao encontrado - pulei."; return 0; }
  ZBXVER=$(zabbix_server -V 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  info "frontend: $ZBX (versao ${ZBXVER:-?})"

  local WEBUSER; WEBUSER=$(stat -c '%U' "$ZBX" 2>/dev/null); [ -z "$WEBUSER" ] || [ "$WEBUSER" = "root" ] && WEBUSER=www-data
  local IM; IM=$(command -v magick || command -v convert || true)
  [ -n "$IM" ] || { apt-get install -y imagemagick >/dev/null 2>&1; IM=$(command -v convert); }
  [ -n "$IM" ] || { erro "imagemagick indisponivel - pulei branding do Zabbix."; return 1; }

  local T; T=$(mktemp -d)
  wget -q -O "$T/white.png" "$REPO/white_logo_black_background.png"
  wget -q -O "$T/icon.png"  "$REPO/white_icon_transparent_background.png"
  wget -q -O "$T/fav.png"   "$REPO/fav32.png"
  wget -q -O "$T/bg.png"    "$REPO/fundo_grafana-novo.png"
  wget -q -O "$T/bg2.png"   "$REPO/fundo_grafana-pos-login.png"

  # Logos nos slots EXATOS (Zabbix nao redimensiona). Pasta 'rebranding' e servida.
  mkdir -p "$ZBX/rebranding"
  $IM "$T/white.png" -fuzz 15% -transparent black -trim +repage -resize 114x30 -background none -gravity center -extent 114x30 "$ZBX/rebranding/logo_login.png"
  $IM "$T/white.png" -fuzz 15% -transparent black -trim +repage -resize 91x24  -background none -gravity center -extent 91x24  "$ZBX/rebranding/logo_sidebar.png"
  $IM "$T/icon.png"  -trim +repage -resize 24x24 -background none -gravity center -extent 24x24 "$ZBX/rebranding/logo_compact.png"
  cp "$T/bg.png" "$ZBX/rebranding/login_bg.png"; cp "$T/bg2.png" "$ZBX/rebranding/app_bg.png"
  for t in $(find "$ZBX" -name favicon.ico 2>/dev/null); do $IM "$T/fav.png" -define icon:auto-resize=32,16 "$t"; done

  # brand.conf.php (nativo; imagens em rebranding/ que e servida, nao local/conf)
  mkdir -p "$ZBX/local/conf"
  local COMPACT="    'BRAND_LOGO_SIDEBAR_COMPACT' => './rebranding/logo_compact.png',"
  # bug ZBX-23676: logo compacta duplicada em 7.0.0-7.0.5
  if [ -n "$ZBXVER" ]; then
    MIN=$(echo "$ZBXVER"|awk -F. '{print $3}'); MAJ=$(echo "$ZBXVER"|awk -F. '{print $1"."$2}')
    [ "$MAJ" = "7.0" ] && [ "${MIN:-99}" -lt 6 ] && { COMPACT=""; aviso "Zabbix $ZBXVER: omitindo logo compacta (bug ZBX-23676)."; }
  fi
  cat > "$ZBX/local/conf/brand.conf.php" << BEOF
<?php
return [
    'BRAND_LOGO'                 => './rebranding/logo_login.png',
    'BRAND_LOGO_SIDEBAR'         => './rebranding/logo_sidebar.png',
${COMPACT}
    'BRAND_FOOTER'               => 'Flowspec Solutions',
    'BRAND_HELP_URL'             => 'https://flowspec.net.br'
];
BEOF

  # Nome do servidor no canto (edita para Flowguard, nao esvazia)
  CONF="$ZBX/conf/zabbix.conf.php"
  [ -f "$CONF" ] && grep -q 'ZBX_SERVER_NAME' "$CONF" && \
    sed -i "s/\$ZBX_SERVER_NAME\s*=.*/\$ZBX_SERVER_NAME = '${ZBX_NAME}';/" "$CONF"

  # CSS: fundo login + pos-login (idempotente)
  for TEMA in blue-theme dark-theme hc-light hc-dark; do
    CSS="$ZBX/assets/styles/$TEMA.css"; [ -f "$CSS" ] || continue
    sed -i '/FLOWSPEC-BG/d' "$CSS"
    printf '\n/*FLOWSPEC-BG*/ body:has(.signin-container){background:url("../../rebranding/login_bg.png") center/cover no-repeat fixed !important;} body:has(.signin-container) .signin-container{background:rgba(8,12,18,.72) !important;backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,.12);border-radius:8px;} body:has(.signin-container) .signin-container label, body:has(.signin-container) footer, body:has(.signin-container) .signin-links a, body:has(.signin-container) .server-name{color:#eef4f8 !important;} body:has(.signin-container) .signin-container input{background:rgba(255,255,255,.06) !important;color:#eef4f8 !important;border-color:rgba(255,255,255,.22) !important;}\n' >> "$CSS"
  done
  for TEMA in dark-theme hc-dark; do
    CSS="$ZBX/assets/styles/$TEMA.css"; [ -f "$CSS" ] || continue
    sed -i '/FLOWSPEC-APP/d' "$CSS"
    printf '\n/*FLOWSPEC-APP*/ body:not(:has(.signin-container)){background:url("../../rebranding/app_bg.png") center/cover no-repeat fixed !important;} body:not(:has(.signin-container)) .wrapper, body:not(:has(.signin-container)) main{background:transparent !important;}\n' >> "$CSS"
  done

  # Tema dark padrao (so config visual; nao toca em dados)
  DBCLI=$(command -v mariadb || command -v mysql || true)
  [ -n "$DBCLI" ] && "$DBCLI" -uroot -e "USE zabbix" 2>/dev/null && \
    "$DBCLI" -uroot zabbix -e "UPDATE config SET default_theme='dark-theme'; UPDATE users SET theme='default';" 2>/dev/null && \
    info "Tema dark definido como padrao."

  chown -R "$WEBUSER":"$WEBUSER" "$ZBX/rebranding" "$ZBX/local/conf" 2>/dev/null
  chmod 755 "$ZBX/rebranding"; chmod 644 "$ZBX/rebranding/"* 2>/dev/null
  rm -rf "$T"
  ok "Zabbix: branding aplicado (nome=${ZBX_NAME}). Ctrl+Shift+R + logout/login."
}

###############################################################################
#  FLUXO PRINCIPAL
###############################################################################
titulo "FLOWSPEC - INSTALACAO COMPLETA  ($(date '+%Y-%m-%d %H:%M:%S'))"

case "$MODO" in
  --auditar)      auditar; exit $?;;
  --so-branding)  auditar; instalar_grafana; instalar_zabbix_branding; exit 0;;
  --so-c2scan)    instalar_c2scan; exit 0;;
esac

# Modo padrao (tudo): audita, e so prossegue se nao houver BLOQUEIO.
if ! auditar; then
  echo ""
  fatal "Auditoria apontou BLOQUEIO(S). Resolva os itens [ERRO] acima antes de instalar."
fi

echo ""
info "Auditoria OK. Iniciando instalacao completa em 5s (Ctrl+C para abortar)..."
sleep 5

instalar_stack                 # Elastic + Kibana + Filebeat
instalar_c2scan                # deteccao C2 + cron
[ "${TEM_GRAFANA:-0}" = "1" ] || apt-get install -y grafana 2>/dev/null   # instala grafana se faltar
systemctl enable --now grafana-server 2>/dev/null
instalar_grafana               # branding + dashboards
instalar_zabbix_branding       # branding zabbix (se existir)

titulo "CONCLUIDO"
echo "  Elastic/Kibana : https://$(hostname -I|awk '{print $1}'):9200  /  :5601"
echo "  Grafana        : http://$(hostname -I|awk '{print $1}'):3000"
echo "  Senhas geradas : /root/.es_pass (elastic)  -  kibana_system no kibana.yml"
echo "  c2scan         : cron ativo (a cada hora). Log: /var/log/c2scan.log"
echo ""
echo "  Faca Ctrl+Shift+R no navegador (cache de assets do branding)."
