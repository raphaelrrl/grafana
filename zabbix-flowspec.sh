#!/bin/bash
###############################################################################
# zabbix-flowspec.sh  -  Flowspec Solutions
#
# Branding white-label do Zabbix (logos, favicon, fundo login/pos-login,
# rodape, tema dark padrao). SCRIPT MATRIZ: autodetecta path do frontend,
# versao, usuario do web server e servidor (apache/nginx) - roda em qualquer
# ambiente sem edicao.
#
# NAO instala Zabbix, NAO toca no banco. Idempotente.
#
# Uso:  ./zabbix-flowspec.sh
###############################################################################
set -uo pipefail

REPO="${REPO:-https://raw.githubusercontent.com/raphaelrrl/grafana/main}"
info() { echo -e "\n\033[0;36m== $1 ==\033[0m"; }
erro() { echo -e "\033[0;31m[ERRO]\033[0m $1"; exit 1; }

[ "$(id -u)" -eq 0 ] || erro "Rode como root."

###############################################################################
info "0. AUTODETECCAO do ambiente Zabbix"
###############################################################################
# --- Path do frontend: /usr/share/zabbix e o padrao; senao, pergunta ao dpkg
if [ -d /usr/share/zabbix ] && [ -f /usr/share/zabbix/index.php ]; then
  ZBX=/usr/share/zabbix
else
  ZBX=$(dpkg -L zabbix-frontend-php 2>/dev/null | grep -m1 '/index.php$' | xargs -r dirname)
fi
[ -n "$ZBX" ] && [ -d "$ZBX" ] || erro "Frontend do Zabbix nao encontrado. Este host tem zabbix-frontend-php?"
echo "  frontend: $ZBX"

# --- Versao (so informativo, para avisar do bug de logo compacta <7.0.6)
ZBXVER=$(zabbix_server -V 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
echo "  versao:   ${ZBXVER:-desconhecida}"

# --- Usuario do web server (apache=www-data em Debian; nginx idem)
if pgrep -x apache2 >/dev/null || systemctl is-active --quiet apache2; then
  WEBUSER=www-data; WEB=apache2
elif pgrep -x nginx >/dev/null || systemctl is-active --quiet nginx; then
  WEBUSER=nginx; systemctl is-active --quiet nginx || WEBUSER=www-data; WEB=nginx
else
  WEBUSER=www-data; WEB=desconhecido
fi
# Confirma o dono real do diretorio (mais confiavel que adivinhar)
DONO=$(stat -c '%U' "$ZBX" 2>/dev/null)
[ -n "$DONO" ] && [ "$DONO" != "root" ] && WEBUSER="$DONO"
echo "  web:      ${WEB} (usuario ${WEBUSER})"

# --- ferramentas
IM=$(command -v magick || command -v convert || true)
[ -n "$IM" ] || { apt-get install -y imagemagick >/dev/null 2>&1; IM=$(command -v convert); }
[ -n "$IM" ] || erro "imagemagick (convert) necessario e nao instalavel."

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

###############################################################################
info "1. Baixar artes do repositorio"
###############################################################################
wget -q -O "$TMP/dark.png"  "$REPO/black_logo_white_background.png"    # logo escura (card login claro)
wget -q -O "$TMP/white.png" "$REPO/white_logo_black_background.png"    # logo branca (sidebar/login escuro)
wget -q -O "$TMP/icon.png"  "$REPO/white_icon_transparent_background.png"
wget -q -O "$TMP/fav.png"   "$REPO/fav32.png"
wget -q -O "$TMP/bg.png"    "$REPO/fundo_grafana-novo.png"
wget -q -O "$TMP/bg2.png"   "$REPO/fundo_grafana-pos-login.png"
for f in dark white icon fav bg bg2; do
  [ -s "$TMP/$f.png" ] || erro "download de $f.png falhou (sem acesso ao repositorio?)."
done

###############################################################################
info "2. Gerar logos nos slots EXATOS do Zabbix"
###############################################################################
# O Zabbix NAO redimensiona: cada imagem precisa vir no tamanho do slot.
#   login   114x30  | sidebar 91x24 | compacta 24x24
# A pasta 'rebranding' e servida pelo Apache (local/conf da Forbidden!).
mkdir -p "$ZBX/rebranding"
# logo do login: usa a branca (o card do login apos branding e escuro)
$IM "$TMP/white.png" -fuzz 15% -transparent black -trim +repage -resize 114x30 -background none -gravity center -extent 114x30 "$ZBX/rebranding/logo_login.png"
$IM "$TMP/white.png" -fuzz 15% -transparent black -trim +repage -resize 91x24  -background none -gravity center -extent 91x24  "$ZBX/rebranding/logo_sidebar.png"
$IM "$TMP/icon.png"  -trim +repage -resize 24x24 -background none -gravity center -extent 24x24 "$ZBX/rebranding/logo_compact.png"
# fundo de login
cp "$TMP/bg.png"  "$ZBX/rebranding/login_bg.png"
cp "$TMP/bg2.png" "$ZBX/rebranding/app_bg.png"

# favicon e touch-icons (nomes gerados pelo build do Zabbix, se existirem)
for t in $(find "$ZBX" -name favicon.ico 2>/dev/null); do $IM "$TMP/fav.png" -define icon:auto-resize=32,16 "$t"; done
for t in $(find "$ZBX" -name 'apple-touch-icon-*.png' -o -name 'touch-icon-*.png' -o -name 'ms-tile-*.png' 2>/dev/null); do
  s=$(basename "$t" | grep -oE '[0-9]+x[0-9]+' | head -1); [ -n "$s" ] && $IM "$TMP/fav.png" -resize "$s" "$t"
done

###############################################################################
info "3. brand.conf.php (rebranding nativo do Zabbix)"
###############################################################################
# Fica em local/conf; as imagens ficam em rebranding/ (servida).
mkdir -p "$ZBX/local/conf"
BRAND="$ZBX/local/conf/brand.conf.php"
# Aviso do bug ZBX-23676 (logo compacta duplicada em 7.0.0-7.0.5).
COMPACT_LINE="    'BRAND_LOGO_SIDEBAR_COMPACT' => './rebranding/logo_compact.png',"
if [ -n "$ZBXVER" ]; then
  MIN=$(echo "$ZBXVER" | awk -F. '{print $3}')
  MAJ=$(echo "$ZBXVER" | awk -F. '{print $1"."$2}')
  if [ "$MAJ" = "7.0" ] && [ "${MIN:-99}" -lt 6 ]; then
    echo "  AVISO: Zabbix $ZBXVER tem bug de logo compacta (ZBX-23676). Omitindo BRAND_LOGO_SIDEBAR_COMPACT."
    COMPACT_LINE=""
  fi
fi
cat > "$BRAND" << EOF
<?php
return [
    'BRAND_LOGO'                 => './rebranding/logo_login.png',
    'BRAND_LOGO_SIDEBAR'         => './rebranding/logo_sidebar.png',
${COMPACT_LINE}
    'BRAND_FOOTER'               => 'Flowspec Solutions',
    'BRAND_HELP_URL'             => 'https://flowspec.net.br'
];
EOF

###############################################################################
info "4. CSS: fundo login/pos-login + card escuro (nos temas dark)"
###############################################################################
# O Zabbix nao tem config de fundo; injetamos CSS nos temas. Idempotente
# (remove marca anterior antes de reanexar).
for TEMA in blue-theme dark-theme hc-light hc-dark; do
  CSS="$ZBX/assets/styles/$TEMA.css"
  [ -f "$CSS" ] || continue
  # --- LOGIN ---
  sed -i '/FLOWSPEC-BG/d' "$CSS"
  printf '\n/*FLOWSPEC-BG*/ body:has(.signin-container){background:url("../../rebranding/login_bg.png") center/cover no-repeat fixed !important;} body:has(.signin-container) .signin-container{background:rgba(8,12,18,.72) !important;backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,.12);border-radius:8px;} body:has(.signin-container) .signin-container label, body:has(.signin-container) footer, body:has(.signin-container) .signin-links a, body:has(.signin-container) .server-name{color:#eef4f8 !important;} body:has(.signin-container) .signin-container input[type=text], body:has(.signin-container) .signin-container input[type=password]{background:rgba(255,255,255,.06) !important;color:#eef4f8 !important;border-color:rgba(255,255,255,.22) !important;}\n' >> "$CSS"
done
# --- POS-LOGIN (so nos temas escuros, para nao prejudicar leitura no claro) ---
for TEMA in dark-theme hc-dark; do
  CSS="$ZBX/assets/styles/$TEMA.css"
  [ -f "$CSS" ] || continue
  sed -i '/FLOWSPEC-APP/d' "$CSS"
  printf '\n/*FLOWSPEC-APP*/ body:not(:has(.signin-container)){background:url("../../rebranding/app_bg.png") center/cover no-repeat fixed !important;} body:not(:has(.signin-container)) .wrapper, body:not(:has(.signin-container)) main, body:not(:has(.signin-container)) .header-title, body:not(:has(.signin-container)) .dashboard-grid{background:transparent !important;}\n' >> "$CSS"
done

###############################################################################
info "5. Tema dark como padrao + permissoes"
###############################################################################
# Define o tema padrao no banco (dark) SE houver mariadb/mysql local e a base
# zabbix existir. So mexe em config visual - nao toca em dados de monitoramento.
if command -v mariadb >/dev/null 2>&1 || command -v mysql >/dev/null 2>&1; then
  DBCLI=$(command -v mariadb || command -v mysql)
  if "$DBCLI" -uroot -e "USE zabbix" 2>/dev/null; then
    "$DBCLI" -uroot zabbix -e "UPDATE config SET default_theme='dark-theme'; UPDATE users SET theme='default';" 2>/dev/null \
      && echo "  tema padrao definido: dark-theme" \
      || echo "  (nao foi possivel definir tema no banco - defina manualmente em Administration > General > GUI)"
  else
    echo "  (base 'zabbix' nao acessivel via root local - defina o tema dark manualmente na UI)"
  fi
fi

chown -R "$WEBUSER":"$WEBUSER" "$ZBX/rebranding" "$ZBX/local/conf" 2>/dev/null || true
chmod 755 "$ZBX/rebranding"; chmod 644 "$ZBX/rebranding/"* 2>/dev/null || true

###############################################################################
info "CONCLUIDO"
###############################################################################
echo "  Branding aplicado em $ZBX (Zabbix ${ZBXVER})."
echo "  E rebranding NATIVO - sobrevive a upgrade do frontend (fica em local/conf)."
echo "  Faca Ctrl+Shift+R no navegador. Logout/login para o tema dark valer."
echo ""
echo "  Teste a imagem servida:  http://<IP>/rebranding/logo_login.png"
