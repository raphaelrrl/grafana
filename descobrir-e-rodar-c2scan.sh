#!/bin/bash
###############################################################################
# descobrir-e-rodar-c2scan.sh  -  Flowspec Solutions
#
# Descobre AUTOMATICAMENTE os parametros do ambiente (IP do ES, CA, data
# stream do filebeat) e roda o c2scan, sem interacao manual - exceto a senha
# do 'elastic', que e lida uma vez de /root/.es_pass (ou pedida se ausente).
#
# Rode na VM 'netflow' (onde estao o Elastic e o CA), ou onde alcance o ES.
###############################################################################
set -euo pipefail

# --- 1. Descobrir a URL do Elasticsearch -------------------------------------
# Preferencia: variavel ES_URL; senao, le network.host do elasticsearch.yml;
# senao, usa o IP primario da maquina.
if [ -n "${ES_URL:-}" ]; then
  :
elif [ -r /etc/elasticsearch/elasticsearch.yml ]; then
  IP=$(grep -E '^\s*network.host:' /etc/elasticsearch/elasticsearch.yml | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  [ -n "$IP" ] || IP=$(hostname -I | awk '{print $1}')
  ES_URL="https://${IP}:9200"
else
  ES_URL="https://$(hostname -I | awk '{print $1}'):9200"
fi
export ES_URL

# --- 2. Localizar o CA -------------------------------------------------------
# c2scan usa ES_CA se o arquivo existir; caso contrario ele ignora verificacao.
if [ -r /etc/elasticsearch/certs/http_ca.crt ]; then
  export ES_CA=/etc/elasticsearch/certs/http_ca.crt
fi

# --- 3. Senha do elastic (lida do arquivo, nunca digitada em claro no shell) -
if [ -r /root/.es_pass ]; then
  ES_PASS=$(cat /root/.es_pass)
else
  read -rsp "Senha do usuario 'elastic': " ES_PASS; echo
  echo "$ES_PASS" > /root/.es_pass; chmod 600 /root/.es_pass
  echo "  (senha salva em /root/.es_pass com permissao 600 para as proximas execucoes)"
fi
export ES_PASS

# --- 4. Data stream: deixado VAZIO de proposito ------------------------------
# O c2scan autodescobre o data stream filebeat-* consultando o proprio ES.
# (Nao fixamos a versao aqui.)
unset ES_INDEX 2>/dev/null || true

echo "== Ambiente detectado =="
echo "  ES_URL   = $ES_URL"
echo "  ES_CA    = ${ES_CA:-<sem CA, verificacao TLS desativada>}"
echo "  ES_INDEX = <autodescoberto pelo c2scan>"
echo ""

# --- 5. Rodar o c2scan -------------------------------------------------------
# Passa todos os argumentos recebidos adiante (ex.: --hours 24 --scan --es-write)
python3 /root/c2scan.py "$@"
