#!/usr/bin/env bash
#
# netdiscover.sh — Reconnaissance reseau rapide et furtive
#
# Decouverte : ARP scan + ping sweep + comparatif
# Autres reseaux : routes, voisins ARP, traceroute
# Scan ports : nmap -sS (SYN furtif) sur ports sensibles/pivoting
#
# Necessite : bash 4+, ip, ping, timeout, nmap (obligatoire), root/sudo
#
# Usage : sudo ./netdiscover.sh [options]
#   -i IFACE     Interface (defaut : auto)
#   -n CIDR      Reseau cible (defaut : auto)
#   -h           Aide
#
set -o pipefail

# ----------------------------- couleurs -----------------------------
if [[ -t 1 ]]; then
  C_RST=$'\e[0m'; C_B=$'\e[1m'; C_RED=$'\e[31m'; C_GRN=$'\e[32m'
  C_YEL=$'\e[33m'; C_BLU=$'\e[34m'; C_CYN=$'\e[36m'; C_DIM=$'\e[2m'
else
  C_RST=""; C_B=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_CYN=""; C_DIM=""
fi
hdr()  { printf '\n%s=== %s ===%s\n' "$C_B$C_CYN" "$1" "$C_RST"; }
info() { printf '%s[*]%s %s\n' "$C_BLU" "$C_RST" "$1"; }
ok()   { printf '%s[+]%s %s\n' "$C_GRN" "$C_RST" "$1"; }
warn() { printf '%s[!]%s %s\n' "$C_YEL" "$C_RST" "$1"; }
err()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RST" "$1" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# ----------------------------- checks ---------------------------------
[[ $EUID -ne 0 ]] && { err "Doit etre lance en root/sudo."; exit 1; }
have nmap || { err "nmap obligatoire. sudo apt install nmap"; exit 1; }
have ip || { err "'ip' introuvable."; exit 1; }
have ping || { err "'ping' introuvable."; exit 1; }

# ----------------------------- defaults & args -------------------------
IFACE=""; CIDR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i) IFACE="$2"; shift 2;;
    -n) CIDR="$2"; shift 2;;
    -h|--help) sed -n '6,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) err "Option inconnue : $1"; exit 1;;
  esac
done

# ----------------------------- helpers ip ---------------------------
ip2int() { local IFS=.; read -r a b c d <<<"$1"; echo $(( (a<<24)+(b<<16)+(c<<8)+d )); }
int2ip() { local i=$1; echo "$(((i>>24)&255)).$(((i>>16)&255)).$(((i>>8)&255)).$((i&255))"; }

# ----------------------- autodetection iface/cidr -------------------
if [[ -z "$IFACE" ]]; then
  IFACE="$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')"
fi
if [[ -z "$IFACE" ]]; then
  IFACE="$(ip -o -f inet addr show 2>/dev/null | awk '$2!="lo"{print $2; exit}')"
fi
[[ -z "$IFACE" ]] && { err "Aucune interface detectee. Precise-la avec -i."; exit 1; }

MY_CIDR="$(ip -o -f inet addr show dev "$IFACE" 2>/dev/null | awk '{print $4; exit}')"
MY_IP="${MY_CIDR%%/*}"
[[ -z "$CIDR" ]] && CIDR="$MY_CIDR"
[[ -z "$CIDR" ]] && { err "Pas de reseau detecte sur $IFACE. Precise-le avec -n."; exit 1; }

NET="${CIDR%%/*}"; PREFIX="${CIDR##*/}"
[[ "$CIDR" == */* ]] || PREFIX=24

# calcul plage
ip_int=$(ip2int "$NET")
mask=$(( 0xFFFFFFFF << (32-PREFIX) & 0xFFFFFFFF ))
netaddr=$(( ip_int & mask ))
if (( PREFIX >= 31 )); then
  first=$netaddr; last=$(( netaddr + (2**(32-PREFIX)) - 1 ))
else
  bcast=$(( netaddr | (~mask & 0xFFFFFFFF) ))
  first=$(( netaddr + 1 )); last=$(( bcast - 1 ))
fi
NHOSTS=$(( last - first + 1 ))

hdr "Configuration"
info "Interface      : ${C_B}$IFACE${C_RST}"
info "IP locale      : ${C_B}${MY_IP:-?}${C_RST}"
info "Reseau cible   : ${C_B}$(int2ip $netaddr)/$PREFIX${C_RST}  (${NHOSTS} hotes)"
info "Outils         : nmap=$(have nmap && echo oui || echo NON) arp-scan=$(have arp-scan && echo oui || echo non)"

# liste des IP cibles
TARGETS=(); for ((i=first; i<=last; i++)); do TARGETS+=("$(int2ip $i)"); done

# ====================================================================
# 1. DECOUVERTE : ARP/L2 + PING SWEEP
# ====================================================================
declare -A PING_UP ARP_UP ARP_MAC

run_with_jobs() {  # run_with_jobs <fn> : lit les IP sur stdin, limite a 64 jobs
  local fn="$1" ip
  while read -r ip; do
    "$fn" "$ip" &
    while (( $(jobs -rp | wc -l) >= 64 )); do wait -n 2>/dev/null || break; done
  done
  wait
}

ping_one() {
  local ip="$1"
  if ping -c1 -W1 -n "$ip" >/dev/null 2>&1; then echo "PING $ip"; fi
}

# -- provoque ARP via TCP connect (marche meme si ICMP filtre) --
arp_provoke() {
  local ip="$1" port
  for port in 80 443 22 445; do
    timeout 1 bash -c "exec 3<>/dev/tcp/$ip/$port" 2>/dev/null && { exec 3>&- 2>/dev/null; break; }
  done
  return 0
}

hdr "Decouverte L2 (ARP)"
if have arp-scan; then
  info "arp-scan detecte -> scan ARP natif..."
  while read -r ip mac _; do
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    ARP_UP["$ip"]=1; ARP_MAC["$ip"]="$mac"
  done < <(arp-scan --interface="$IFACE" --localnet 2>/dev/null | awk '/^[0-9]+\./{print $1,$2}')
else
  info "Provocation ARP via TCP connect..."
  printf '%s\n' "${TARGETS[@]}" | run_with_jobs arp_provoke
  while read -r ip _ mac state; do
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    ipi=$(ip2int "$ip"); (( ipi < first || ipi > last )) && continue
    case "$state" in REACHABLE|STALE|DELAY|PROBE)
      ARP_UP["$ip"]=1; ARP_MAC["$ip"]="$mac";;
    esac
  done < <(ip neigh show dev "$IFACE" 2>/dev/null | grep lladdr)
fi
ok "Hotes presents en L2 (ARP) : ${#ARP_UP[@]}"

hdr "Ping sweep (ICMP)"
info "Ping de $NHOSTS hotes..."
while read -r tag ip; do [[ "$tag" == PING ]] && PING_UP["$ip"]=1; done \
  < <(printf '%s\n' "${TARGETS[@]}" | run_with_jobs ping_one)
ok "Hotes qui repondent au ping : ${#PING_UP[@]}"

# -- ensemble unifie des hotes "up" --
declare -A ALIVE
for ip in "${!ARP_UP[@]}";  do ALIVE["$ip"]=1; done
for ip in "${!PING_UP[@]}"; do ALIVE["$ip"]=1; done

# -- tableau comparatif --
hdr "Comparatif : visibles (ARP) vs joignables (ping)"
printf '%s%-16s %-19s %-8s %-8s%s\n' "$C_B" "IP" "MAC" "ARP" "PING" "$C_RST"
printf '%s%s%s\n' "$C_DIM" "------------------------------------------------------------" "$C_RST"
mapfile -t SORTED < <(printf '%s\n' "${!ALIVE[@]}" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n)
for ip in "${SORTED[@]}"; do
  a="${ARP_UP[$ip]:-}"; p="${PING_UP[$ip]:-}"; mac="${ARP_MAC[$ip]:-—}"
  as=$([[ -n "$a" ]] && echo "${C_GRN}oui${C_RST}" || echo "${C_DIM}non${C_RST}")
  ps=$([[ -n "$p" ]] && echo "${C_GRN}oui${C_RST}" || echo "${C_RED}non${C_RST}")
  note=""
  [[ -n "$a" && -z "$p" ]] && note="  ${C_YEL}<- visible L2 mais ne ping pas (ICMP filtre ?)${C_RST}"
  printf '%-16s %-19s %b      %b%b\n' "$ip" "$mac" "$as" "$ps" "$note"
done
echo
ok "Total joignables : ${C_B}${#ALIVE[@]}${C_RST}  | ARP : ${#ARP_UP[@]}  | Ping : ${#PING_UP[@]}"

# ====================================================================
# 2. AUTRES SOUS-RESEAUX ACCESSIBLES
# ====================================================================
hdr "Autres sous-reseaux accessibles"
LOCAL_SUBNET="$(int2ip $netaddr)/$PREFIX"

info "Routes connues (table de routage) :"
ip -o -f inet route show 2>/dev/null | awk '{print "    "$0}'

echo
info "Sous-reseaux directement routes (hors reseau courant) :"
OTHER=0
while read -r dst _; do
  [[ "$dst" == "default" || -z "$dst" ]] && continue
  [[ "$dst" == */* ]] || continue
  [[ "$dst" == "$LOCAL_SUBNET" ]] && continue
  printf '    %s%s%s\n' "$C_GRN" "$dst" "$C_RST"; OTHER=1
done < <(ip -o -f inet route show 2>/dev/null | awk '$1!="default"{print $1}' | sort -u)
(( OTHER == 0 )) && info "    (aucun autre sous-reseau directement route)"

# ====================================================================
# 3. SCAN DE PORTS SENSIBLES
# ====================================================================
# Ports importants pour le pivoting : SSH, FTP, Telnet, DNS, HTTP/S,
# SMB, LDAP, RDP, VNC, MySQL/MariaDB, PostgreSQL, MSSQL, MongoDB,
# Redis, Memcached, RabbitMQ, Kafka, Elasticsearch, Cassandra
PORTS_PIVOT="21,22,23,53,80,139,389,443,445,1433,3306,3389,5432,5672,5900,6379,8080,8443,9042,9092,9200,11211,27017"

if (( ${#ALIVE[@]} == 0 )); then
  warn "Aucun hote decouvert. Pas de scan de ports."
  exit 0
fi

# ----------------------------------------------------------------
# 3a. Scan nmap de masse (SYN furtif)
#     -> sauvegarde output greppable pour comparaison avec scan custom
# ----------------------------------------------------------------
hdr "Scan nmap de masse (SYN furtif)"
info "Hotes : ${#SORTED[@]}  |  Ports : $PORTS_PIVOT"
echo

NMAP_NORM=$(mktemp); NMAP_GREP=$(mktemp)
nmap -sS -T2 --min-rate 50 --randomize-hosts \
     -p "$PORTS_PIVOT" "${SORTED[@]}" \
     -oN "$NMAP_NORM" -oG "$NMAP_GREP" >/dev/null
cat "$NMAP_NORM"
rm -f "$NMAP_NORM"

# Parser les ports ouverts du scan de masse pour comparaison
declare -A NMAP_OPEN
while IFS= read -r key; do
  NMAP_OPEN["$key"]=1
done < <(grep "^Host:" "$NMAP_GREP" | awk '{
  ip = $2
  for (i = 1; i <= NF; i++) {
    if ($i ~ /\/open\/tcp/) {
      split($i, parts, "/")
      gsub(/,/, "", parts[1])
      print ip ":" parts[1]
    }
  }
}')
rm -f "$NMAP_GREP"

# ----------------------------------------------------------------
# 3b. Scan custom IP-by-IP
#     Scanne chaque hote individuellement : peut contourner certains
#     IDS/firewalls qui detectent uniquement les scans de masse,
#     et trouver des ports que le scan de masse aurait rates.
# ----------------------------------------------------------------
hdr "Scan custom IP-by-IP (detection complementaire)"
info "Scan individuel de ${#SORTED[@]} hotes sur les memes ports..."
echo

declare -A CUSTOM_OPEN
CIDR_RANGE="$(int2ip $netaddr)/$PREFIX"

for ip in "${SORTED[@]}"; do
  while IFS= read -r portline; do
    port=$(echo "$portline" | awk -F'/' '{gsub(/ /,"",$1); print $1}')
    [[ -n "$port" && "$port" =~ ^[0-9]+$ ]] && CUSTOM_OPEN["${ip}:${port}"]=1
  done < <(nmap -sS -p "$PORTS_PIVOT" "$ip" 2>/dev/null | grep "^[0-9].*open")
done

# Comparer : afficher seulement ce que custom a trouve en plus
EXTRAS=0
for key in $(printf '%s\n' "${!CUSTOM_OPEN[@]}" | sort -t: -k1,1 -k2,2n); do
  if [[ -z "${NMAP_OPEN[$key]:-}" ]]; then
    cip="${key%%:*}"; cport="${key##*:}"
    if (( EXTRAS == 0 )); then
      printf '%s[+] Nouveaux resultats trouves par le scan custom :%s\n' "$C_YEL" "$C_RST"
    fi
    printf '  %s%-16s%s port %s%-6s%s ouvert %s(non detecte par le scan de masse)%s\n' \
      "$C_B" "$cip" "$C_RST" "$C_GRN" "$cport" "$C_RST" "$C_DIM" "$C_RST"
    EXTRAS=1
  fi
done
(( EXTRAS == 0 )) && info "Aucun port supplementaire trouve par le scan custom."

# ====================================================================
# 4. RÉCAPITULATIF DES PORTS OUVERTS PAR IP
# ====================================================================
hdr "Recapitulatif des ports ouverts"

# Noms lisibles des services
declare -A SVC=(
  [21]="FTP"         [22]="SSH"          [23]="Telnet"
  [53]="DNS"         [80]="HTTP"         [139]="NetBIOS"
  [389]="LDAP"       [443]="HTTPS"       [445]="SMB"
  [1433]="MSSQL"     [2049]="NFS"        [3306]="MySQL/MariaDB"
  [3389]="RDP"       [5432]="PostgreSQL" [5672]="RabbitMQ"
  [5900]="VNC"       [6379]="Redis"      [8080]="HTTP-Alt"
  [8443]="HTTPS-Alt" [9000]="S3/MinIO"   [9042]="Cassandra"
  [9092]="Kafka"     [9200]="Elasticsearch" [9418]="Git"
  [11211]="Memcached" [15672]="RabbitMQ-Mgmt" [27017]="MongoDB"
)

# Combiner NMAP_OPEN + CUSTOM_OPEN → ALL_OPEN, grouper par IP
declare -A ALL_OPEN PORTS_BY_IP
for key in "${!NMAP_OPEN[@]}" "${!CUSTOM_OPEN[@]}"; do
  ALL_OPEN["$key"]=1
  cip="${key%%:*}"; cport="${key##*:}"
  PORTS_BY_IP["$cip"]+=" $cport"
done

if (( ${#PORTS_BY_IP[@]} == 0 )); then
  warn "Aucun port ouvert detecte."
else
  mapfile -t RECAP_IPS < <(printf '%s\n' "${!PORTS_BY_IP[@]}" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n)
  for ip in "${RECAP_IPS[@]}"; do
    mapfile -t ip_ports < <(printf '%s\n' ${PORTS_BY_IP[$ip]} | sort -u -n)
    line=""
    for p in "${ip_ports[@]}"; do
      name="${SVC[$p]:-svc}"
      line+="${C_GRN}${p}${C_RST}${C_DIM}/${name}${C_RST}  "
    done
    printf '  %s%-16s%s : %b\n' "$C_B" "$ip" "$C_RST" "$line"
  done
fi

# ====================================================================
# 5. VERIFICATION DES SERVICES
# ====================================================================
hdr "Verification des services"

if (( ${#PORTS_BY_IP[@]} == 0 )); then
  warn "Aucun service a verifier."
  hdr "Termine"; exit 0
fi

# --- Helper : requete bidirectionnelle bash /dev/tcp ---
# Usage : tcp_dialog IP PORT PAYLOAD [timeout]
tcp_dialog() {
  local ip="$1" port="$2" payload="$3" to="${4:-2}"
  timeout "$to" bash -c "
    exec 3<>/dev/tcp/$ip/$port 2>/dev/null
    printf '%s' '$payload' >&3
    sleep 0.5
    timeout 1 cat <&3
    exec 3>&-
  " 2>/dev/null
}

# --- Scripts NSE par port ---
declare -A NSE=(
  [21]="ftp-anon,ftp-syst"
  [22]="ssh-hostkey"
  [53]="dns-recursion"
  [80]="http-title,http-server-header,http-git,http-auth-finder"
  [139]="smb-security-mode,smb-enum-shares,smb-os-discovery"
  [389]="ldap-rootdse"
  [443]="http-title,http-server-header,http-git,http-auth-finder"
  [445]="smb-security-mode,smb-enum-shares,smb-os-discovery,smb-vuln-ms17-010"
  [1433]="ms-sql-info,ms-sql-empty-password"
  [2049]="nfs-showmount,nfs-ls"
  [3306]="mysql-info,mysql-empty-password"
  [3389]="rdp-enum-encryption"
  [5432]="pgsql-brute"
  [5900]="vnc-info"
  [6379]="redis-info"
  [8080]="http-title,http-server-header,http-git,http-auth-finder"
  [8443]="http-title,http-server-header,http-git,http-auth-finder"
  [9042]="cassandra-info"
  [9200]="http-title"
  [11211]="memcached-info"
  [27017]="mongodb-info,mongodb-databases"
)

for ip in "${RECAP_IPS[@]}"; do
  mapfile -t ip_ports < <(printf '%s\n' ${PORTS_BY_IP[$ip]} | sort -u -n)
  [[ ${#ip_ports[@]} -eq 0 ]] && continue

  printf '\n%s┌─[ %s ]%s\n' "$C_B$C_CYN" "$ip" "$C_RST"

  ports_csv=$(printf '%s,' "${ip_ports[@]}" | sed 's/,$//')

  # Construire la liste des scripts NSE (sans doublons)
  declare -A _seen=()
  scripts_list=""
  for p in "${ip_ports[@]}"; do
    s="${NSE[$p]:-}"
    [[ -z "$s" ]] && continue
    IFS=',' read -ra slist <<< "$s"
    for sc in "${slist[@]}"; do
      if [[ -z "${_seen[$sc]:-}" ]]; then
        _seen["$sc"]=1
        scripts_list+=",$sc"
      fi
    done
  done
  scripts_list="${scripts_list#,}"
  unset _seen

  # nmap -sV -O + scripts NSE sur les seuls ports ouverts de cet hote
  nmap_args="-sS -sV -O --osscan-guess -p $ports_csv"
  [[ -n "$scripts_list" ]] && nmap_args+=" --script $scripts_list"
  # pgsql-brute : limiter aux creds par defaut postgres/postgres uniquement
  [[ "$scripts_list" == *"pgsql-brute"* ]] && \
    nmap_args+=" --script-args brute.firstonly=true,pgsql-brute.userdb=/dev/null,brute.mode=user"

  nmap $nmap_args "$ip" 2>/dev/null | grep -v "^$" | sed 's/^/  /'

  # -----------------------------------------------------------------
  # Checks additionnels par service (ce que nmap NSE ne couvre pas)
  # -----------------------------------------------------------------
  for p in "${ip_ports[@]}"; do
    case "$p" in

      # --- Elasticsearch : acces sans auth, info cluster ---
      9200)
        info "  [Elasticsearch] Check acces sans auth..."
        if have curl; then
          res=$(curl -sk --max-time 4 "http://$ip:9200/" 2>/dev/null)
        else
          res=$(tcp_dialog "$ip" 9200 "GET / HTTP/1.0\r\nHost: $ip\r\n\r\n" 4)
        fi
        if echo "$res" | grep -q '"cluster_name"'; then
          cluster=$(echo "$res" | grep -o '"cluster_name":"[^"]*"' | cut -d'"' -f4)
          version=$(echo "$res" | grep -o '"number":"[^"]*"'       | cut -d'"' -f4)
          warn "  [!] ELASTICSEARCH sans auth ! cluster=$cluster version=$version"
          # lister les index
          if have curl; then
            indices=$(curl -sk --max-time 4 "http://$ip:9200/_cat/indices?v" 2>/dev/null | head -10)
            [[ -n "$indices" ]] && printf '  Index detectes :\n%s\n' "$indices" | sed 's/^/    /'
          fi
        else
          ok "  [Elasticsearch] Auth requise ou service non accessible sans creds."
        fi
        ;;

      # --- Redis : PING sans auth ---
      6379)
        info "  [Redis] Check acces sans auth..."
        if have nc; then
          res=$(printf "PING\r\n" | nc -w2 "$ip" 6379 2>/dev/null)
        else
          res=$(tcp_dialog "$ip" 6379 "PING\r\n")
        fi
        if echo "$res" | grep -q "+PONG"; then
          warn "  [!] REDIS sans auth !"
          # version + OS via INFO
          if have nc; then
            info_res=$(printf "INFO server\r\n" | nc -w2 "$ip" 6379 2>/dev/null | \
                       grep -E "^redis_version|^os:|^arch_bits|^tcp_port")
          else
            info_res=$(tcp_dialog "$ip" 6379 "INFO server\r\n" 3 | \
                       grep -E "^redis_version|^os:|^arch_bits|^tcp_port")
          fi
          [[ -n "$info_res" ]] && echo "$info_res" | sed 's/^/    /'
        else
          ok "  [Redis] Auth requise."
        fi
        ;;

      # --- MongoDB : couvert par NSE mongodb-databases ---
      # NSE mongodb-databases liste les DBs si pas d'auth -> deja fait ci-dessus

      # --- S3 / MinIO : check endpoint ---
      9000|9001)
        info "  [S3/MinIO] Check endpoint sur port $p..."
        if have curl; then
          res=$(curl -sI --max-time 4 "http://$ip:$p/" 2>/dev/null)
          body=$(curl -sk --max-time 4 "http://$ip:$p/" 2>/dev/null)
          if echo "$res$body" | grep -qi "x-amz\|minio\|ListBucketResult"; then
            warn "  [!] Endpoint S3/MinIO detecte sur $ip:$p"
            # tenter de lister les buckets
            buckets=$(curl -sk --max-time 4 "http://$ip:$p/" 2>/dev/null | \
                      grep -oP '(?<=<Name>)[^<]+' | head -10)
            [[ -n "$buckets" ]] && { info "  Buckets accessibles :"; echo "$buckets" | sed 's/^/    /'; }
          else
            ok "  [S3/MinIO] Pas de reponse S3-compatible (ou auth requise)."
          fi
        else
          warn "  [S3/MinIO] curl absent, check HTTP impossible."
        fi
        ;;

      # --- Git (protocole natif port 9418) ---
      9418)
        info "  [Git] Check protocole git natif (port 9418)..."
        payload="$(printf '0015git-upload-pack /\000host=%s\000' "$ip")"
        res=$(tcp_dialog "$ip" 9418 "$payload" 3 | strings | head -5)
        if [[ -n "$res" ]]; then
          ok "  [Git] Service git natif repond :"
          echo "$res" | sed 's/^/    /'
        else
          info "  [Git] Pas de reponse git natif sur port 9418."
        fi
        ;;

      # --- Git + S3 sur HTTP/HTTPS ---
      80|443|8080|8443)
        scheme="http"; [[ "$p" == "443" || "$p" == "8443" ]] && scheme="https"
        base="$scheme://$ip:$p"

        if have curl; then
          # .git expose
          code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "$base/.git/HEAD" 2>/dev/null)
          [[ "$code" == "200" ]] && \
            warn "  [!] GIT: /.git/HEAD accessible sur $base -> repo potentiellement lisible !"

          # GitLab
          gl=$(curl -sk --max-time 3 "$base/api/v4/version" 2>/dev/null)
          echo "$gl" | grep -q '"version"' && ok "  [Git] GitLab detecte sur $base : $(echo "$gl" | grep -o '"version":"[^"]*"')"

          # Gitea
          gt=$(curl -sk --max-time 3 "$base/api/swagger" 2>/dev/null)
          echo "$gt" | grep -qi "gitea" && ok "  [Git] Gitea detecte sur $base"

          # Gogs
          gg=$(curl -sk --max-time 3 "$base/api/v1/settings/api" 2>/dev/null)
          echo "$gg" | grep -qi "gogs\|gitea" && ok "  [Git] Gogs/Gitea API detecte sur $base"

          # GitHub Enterprise
          ghe=$(curl -sk --max-time 3 "$base/api/v3/meta" 2>/dev/null)
          echo "$ghe" | grep -qi '"github_services_sha"\|"verifiable_password_authentication"' && \
            ok "  [Git] GitHub Enterprise detecte sur $base"

          # S3 sur HTTP standard
          s3h=$(curl -sI --max-time 3 "$base/" 2>/dev/null)
          echo "$s3h" | grep -qi "x-amz\|minio" && \
            warn "  [!] S3: Headers AWS/MinIO detectes sur $base"

          # Elasticsearch sur port 80/8080 (rare mais possible)
          es=$(curl -sk --max-time 3 "$base/" 2>/dev/null)
          echo "$es" | grep -q '"cluster_name"' && \
            warn "  [!] Elasticsearch sans auth detecte sur $base !"
        fi
        ;;

      # --- Memcached : stats sans auth ---
      11211)
        info "  [Memcached] Check acces sans auth..."
        if have nc; then
          res=$(printf "stats\r\n" | nc -w2 "$ip" 11211 2>/dev/null | head -5)
        else
          res=$(tcp_dialog "$ip" 11211 "stats\r\n")
        fi
        if echo "$res" | grep -q "^STAT "; then
          warn "  [!] MEMCACHED sans auth ! Stats accessibles :"
          echo "$res" | grep "^STAT " | head -6 | sed 's/^/    /'
        else
          ok "  [Memcached] Pas de reponse aux stats (ou auth requise)."
        fi
        ;;

      # --- RabbitMQ management UI ---
      15672)
        info "  [RabbitMQ] Check interface management..."
        if have curl; then
          res=$(curl -sk --max-time 3 -u guest:guest "http://$ip:15672/api/overview" 2>/dev/null)
          echo "$res" | grep -q '"rabbitmq_version"' && \
            warn "  [!] RabbitMQ management accessible avec guest:guest !"
        fi
        ;;

    esac
  done
done

hdr "Termine"
