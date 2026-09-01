#!/bin/bash
###############################################################################
# auditar-ambiente.sh  -  Flowspec Solutions
#
# OBJETIVO: verificar o que ja existe no servidor ANTES de instalar o stack
#           de coleta (Elasticsearch + Kibana + Filebeat/netflow).
#
# ESTE SCRIPT NAO INSTALA, NAO PARA E NAO ALTERA NADA.
# Ele apenas LE o estado do sistema e imprime um relatorio, para que voce
# decida com seguranca (o ambiente ja roda Zabbix e Grafana em producao).
#
# Uso:  chmod +x auditar-ambiente.sh ; ./auditar-ambiente.sh
###############################################################################

# Nao usamos 'set -e': queremos que o script continue mesmo quando um teste
# falha (um pacote ausente NAO deve abortar a auditoria).

# ---- cores para leitura (desativa se a saida nao for um terminal) -----------
if [ -t 1 ]; then
  VERDE="\033[0;32m"; AMAR="\033[0;33m"; VERM="\033[0;31m"; AZUL="\033[0;36m"; ZERO="\033[0m"
else
  VERDE=""; AMAR=""; VERM=""; AZUL=""; ZERO=""
fi

# Contadores para o resumo final
AVISOS=0      # coisas que exigem sua atencao antes de instalar
BLOQUEIOS=0   # coisas que impedem a instalacao com seguranca

ok()      { echo -e "  ${VERDE}[ OK ]${ZERO}   $1"; }
info()    { echo -e "  ${AZUL}[INFO]${ZERO}   $1"; }
aviso()   { echo -e "  ${AMAR}[AVISO]${ZERO} $1"; AVISOS=$((AVISOS+1)); }
bloqueio(){ echo -e "  ${VERM}[BLOQ]${ZERO}  $1"; BLOQUEIOS=$((BLOQUEIOS+1)); }
titulo()  { echo -e "\n${AZUL}== $1 ==${ZERO}"; }

# Precisa ser root para ler status de servicos e portas com dono de processo
if [ "$(id -u)" -ne 0 ]; then
  echo "Rode como root (algumas verificacoes precisam de privilegio)."; exit 1
fi

# Funcoes auxiliares -----------------------------------------------------------

# pacote instalado? (dpkg)
pkg_instalado() { dpkg -l "$1" 2>/dev/null | grep -q '^ii'; }

# servico existe no systemd?
servico_existe() { systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "$1.service"; }

# servico ativo agora?
servico_ativo() { systemctl is-active --quiet "$1"; }

# porta TCP em escuta? (retorna a linha do ss, se houver)
porta_escuta() { ss -tlnp 2>/dev/null | grep -E "[:.]$1 " ; }

###############################################################################
echo -e "${AZUL}"
echo "==============================================================="
echo " AUDITORIA PRE-INSTALACAO  -  stack de coleta NetFlow (Flowspec)"
echo " Data: $(date '+%Y-%m-%d %H:%M:%S')   Host: $(hostname)"
echo "==============================================================="
echo -e "${ZERO}"

###############################################################################
titulo "1. Sistema operacional"
###############################################################################
# O stack foi homologado em Debian 12/13 e Ubuntu 26.04. Confirmamos a base.
if [ -r /etc/os-release ]; then
  . /etc/os-release
  info "SO: $PRETTY_NAME"
  case "$ID:$VERSION_ID" in
    debian:12|debian:13|ubuntu:26.04|ubuntu:24.04)
      ok "Base homologada." ;;
    *)
      aviso "Base '$ID $VERSION_ID' fora das testadas (debian 12/13, ubuntu 24.04/26.04). O repositorio 8.x da Elastic ainda deve funcionar, mas valide." ;;
  esac
else
  aviso "Nao foi possivel ler /etc/os-release."
fi
info "Kernel: $(uname -r)"

###############################################################################
titulo "2. Recursos de hardware (Elasticsearch e faminto de RAM)"
###############################################################################
# Elasticsearch pede minimo pratico de 4 GB de RAM. Abaixo disso, o servico
# derruba o restante do host quando indexa - risco direto pro Zabbix/Grafana.
RAM_MB=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo)
info "RAM total: ${RAM_MB} MB"
if [ "$RAM_MB" -lt 4000 ]; then
  bloqueio "RAM abaixo de 4 GB. Elasticsearch + Zabbix + Grafana no mesmo host com <4GB tende a OOM. Revise antes de instalar."
elif [ "$RAM_MB" -lt 8000 ]; then
  aviso "RAM entre 4 e 8 GB. Funciona, mas defina jvm.options do ES com metade da RAM (ex.: -Xms2g -Xmx2g) para nao competir com Zabbix/Grafana."
else
  ok "RAM suficiente."
fi

# Disco livre em / (o indice de netflow cresce rapido)
DISCO_LIVRE_GB=$(df -BG --output=avail / 2>/dev/null | tail -1 | tr -dc '0-9')
info "Disco livre em / : ${DISCO_LIVRE_GB} GB"
if [ "${DISCO_LIVRE_GB:-0}" -lt 20 ]; then
  aviso "Menos de 20 GB livres. Indice netflow cresce rapido; planeje retencao (ILM) antes de ligar a coleta."
else
  ok "Espaco em disco adequado para inicio."
fi

# CPUs
info "CPUs: $(nproc)"

###############################################################################
titulo "3. Aplicacoes EXISTENTES em producao (nao tocar)"
###############################################################################
# Aqui apenas CONFIRMAMOS Zabbix e Grafana. O objetivo e garantir que a
# instalacao futura NAO vai colidir com eles (porta, memoria, repo apt).

# --- Zabbix ---
if pkg_instalado zabbix-server-mysql || pkg_instalado zabbix-server-pgsql || servico_existe zabbix-server; then
  VER_ZBX=$(zabbix_server -V 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  ok "Zabbix presente (versao ${VER_ZBX:-desconhecida}). Servico: $(systemctl is-active zabbix-server 2>/dev/null)"
else
  info "Zabbix nao detectado neste host."
fi

# --- Grafana ---
if pkg_instalado grafana || servico_existe grafana-server; then
  VER_GRF=$(dpkg -l grafana 2>/dev/null | awk '/^ii/ {print $3}')
  ok "Grafana presente (versao ${VER_GRF:-desconhecida}). Servico: $(systemctl is-active grafana-server 2>/dev/null)"
  # O stack usa o datasource do Elastic no Grafana; a porta do Grafana NAO muda.
  GRF_PORT=$(grep -E '^\s*http_port' /etc/grafana/grafana.ini 2>/dev/null | grep -oE '[0-9]+' | tail -1)
  info "Porta do Grafana configurada: ${GRF_PORT:-3000 (padrao)}"
else
  info "Grafana nao detectado neste host."
fi

# --- Banco do Zabbix (MySQL/MariaDB) - so reportar, nunca mexer ---
if servico_ativo mariadb || servico_ativo mysql; then
  ok "Servico de banco (MariaDB/MySQL) ativo - usado pelo Zabbix. NAO sera alterado."
fi

###############################################################################
titulo "4. Componentes do stack de coleta (a instalar)"
###############################################################################
# Para cada um: ja existe? Se sim, PRESERVAR (nao reinstalar, para nao perder
# dados/config). Se nao, esta livre para instalar.

for COMP in elasticsearch kibana filebeat; do
  if pkg_instalado "$COMP" || servico_existe "$COMP"; then
    VER=$(dpkg -l "$COMP" 2>/dev/null | awk '/^ii/ {print $3}')
    EST=$(systemctl is-active "$COMP" 2>/dev/null)
    aviso "$COMP JA INSTALADO (versao ${VER:-?}, estado ${EST}). NAO reinstalar - preservar dados e config existentes."
  else
    ok "$COMP ausente - livre para instalar."
  fi
done

# Diretorios de dados: se existirem com conteudo, ha instalacao anterior.
for DIR in /var/lib/elasticsearch /var/lib/kibana; do
  if [ -d "$DIR" ] && [ -n "$(ls -A "$DIR" 2>/dev/null)" ]; then
    aviso "Diretorio $DIR existe e NAO esta vazio - possui dados de instalacao anterior. Nao apague."
  fi
done

###############################################################################
titulo "5. Conflitos de PORTA (o que mais gera indisponibilidade)"
###############################################################################
# O stack usa: ES 9200, Kibana 5601, netflow UDP 2055.
# Se qualquer uma ja estiver em uso por OUTRO processo, precisa resolver antes.

verifica_porta_tcp() {
  local PORTA="$1" ESPERADO="$2"
  local LINHA; LINHA=$(porta_escuta "$PORTA")
  if [ -n "$LINHA" ]; then
    local DONO; DONO=$(echo "$LINHA" | grep -oE 'users:\(\("[^"]+' | grep -oE '"[^"]+' | tr -d '"' | head -1)
    if echo "$DONO" | grep -qi "$ESPERADO"; then
      ok "Porta TCP $PORTA ja em uso por '$DONO' (o proprio componente do stack - esperado)."
    else
      bloqueio "Porta TCP $PORTA OCUPADA por '$DONO' (esperado seria '$ESPERADO'). Resolva antes de instalar."
    fi
  else
    ok "Porta TCP $PORTA livre."
  fi
}
verifica_porta_tcp 9200 elasticsearch
verifica_porta_tcp 5601 kibana

# netflow e UDP 2055
if ss -ulnp 2>/dev/null | grep -qE '[:.]2055 '; then
  DONO_UDP=$(ss -ulnp 2>/dev/null | grep -E '[:.]2055 ' | grep -oE 'users:\(\("[^"]+' | grep -oE '"[^"]+' | tr -d '"' | head -1)
  if echo "$DONO_UDP" | grep -qi filebeat; then
    ok "UDP 2055 (netflow) ja em uso pelo filebeat - esperado."
  else
    bloqueio "UDP 2055 (netflow) ocupada por '$DONO_UDP'. Outro coletor de flow pode estar rodando; resolva antes."
  fi
else
  ok "UDP 2055 (netflow) livre."
fi

###############################################################################
titulo "6. Repositorio APT da Elastic (evitar entrada duplicada)"
###############################################################################
# A doc da Elastic alerta: duas entradas do mesmo repo quebram 'apt update'.
# So reportamos o estado; a criacao correta fica para o script de instalacao.
ENC=$(grep -rl 'artifacts.elastic.co' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null)
if [ -z "$ENC" ]; then
  info "Repositorio Elastic ainda nao configurado - normal se ES nunca foi instalado aqui."
else
  N=$(echo "$ENC" | grep -c .)
  if [ "$N" -gt 1 ]; then
    aviso "Repositorio Elastic aparece em MAIS DE UM arquivo (risco de 'Duplicate sources' no apt): $ENC"
  else
    ok "Repositorio Elastic ja presente em: $ENC"
  fi
fi

###############################################################################
titulo "7. Conectividade de saida (downloads e blocklists)"
###############################################################################
# So testa alcance (HEAD), nao baixa nada pesado.
testa_url() {
  local URL="$1" NOME="$2"
  if curl -s -m 8 -o /dev/null -I "$URL" 2>/dev/null; then
    ok "Alcanca $NOME"
  else
    aviso "Nao alcancou $NOME ($URL) - verifique firewall/proxy de saida antes de instalar."
  fi
}
testa_url "https://artifacts.elastic.co/packages/8.x/apt/" "repositorio Elastic 8.x"
testa_url "https://feodotracker.abuse.ch/" "abuse.ch (blocklists C2)"

###############################################################################
titulo "RESUMO"
###############################################################################
echo ""
if [ "$BLOQUEIOS" -gt 0 ]; then
  echo -e "${VERM}Resultado: $BLOQUEIOS bloqueio(s) e $AVISOS aviso(s).${ZERO}"
  echo -e "${VERM}NAO prossiga com a instalacao ate resolver os itens [BLOQ] acima.${ZERO}"
  exit 2
elif [ "$AVISOS" -gt 0 ]; then
  echo -e "${AMAR}Resultado: 0 bloqueios, $AVISOS aviso(s).${ZERO}"
  echo -e "${AMAR}Revise os itens [AVISO] (ex.: componente ja instalado = preservar) antes de instalar.${ZERO}"
  exit 1
else
  echo -e "${VERDE}Resultado: ambiente limpo, sem bloqueios nem avisos.${ZERO}"
  echo -e "${VERDE}Livre para a etapa de instalacao.${ZERO}"
  exit 0
fi
