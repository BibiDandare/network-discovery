#!/usr/bin/env bash
#
# netdiscover.sh - Reconnaissance reseau autonome (bash pur)
#
#   1) Decouverte L2 (ARP) + ping sweep, avec comparaison des deux vues
#      -> met en evidence les hotes visibles en L2 mais qui ne repondent pas au ping
#         (typiquement des machines qui filtrent l'ICMP).
#   2) Recherche d'autres sous-reseaux accessibles (routes, voisins, traceroute).
#   3) Scan de ports des hotes decouverts (connect-scan bash /dev/tcp, ou nmap si dispo).
#
# Aucune dependance obligatoire a arp-scan / nmap : ils sont utilises s'ils existent.
# Necessite bash >= 4 (pour /dev/tcp). Outils utilises s'ils sont presents :
#   ip, ping, timeout, nc, nmap, arp-scan, traceroute.
#
# Lance SANS argument, il fait tout, sans interaction (concu pour etre appele
# depuis un autre script) : decouverte ARP + ping sweep, recherche d'autres
# sous-reseaux, puis scan de TOUS les ports des hotes decouverts (furtif si possible).
#
# Usage : ./netdiscover.sh [options]
#   -i IFACE     Interface (defaut : route par defaut)
#   -n CIDR      Reseau cible, ex 192.168.1.0/24 (defaut : auto)
#   -P LISTE     Ports a scanner : "all" (defaut), "top", liste "22,80,443" ou plage "1-1024"
#   --pn         Scanner les ports meme sur les hotes qui ne repondent pas (equivalent nmap -Pn)
#   --no-ports   Ne PAS scanner les ports (decouverte seule)
#   -d MS        Delai de base entre probes de port en ms (defaut 0). Du jitter aleatoire est ajoute.
#   -t SEC       Timeout de connexion en secondes (defaut 1)
#   -j N         Parallelisme hotes ET ports (defaut 64)
#   --no-ping    Ne pas faire le ping sweep
#   --no-arp     Ne pas faire la decouverte ARP/L2
#   --force      (defaut actif) ne jamais demander de confirmation
#   -h           Aide
#
# Pas de 'set -u' : on manipule des tableaux associatifs potentiellement vides,
# que bash considere comme "unbound". Les acces sensibles utilisent ${x:-} de toute facon.

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

# ----------------------------- defaults -----------------------------
# Defauts penses pour un lancement SANS option (couplage dans un autre script) :
# decouverte complete + scan de TOUS les ports, non-interactif.
IFACE=""; CIDR=""; DO_PORTS=1; PORTS_SPEC="all"; PN=0
DELAY_MS=0; TIMEOUT=1; JOBS=64; DO_PING=1; DO_ARP=1; FORCE=1
MAX_HOSTS_NOCONFIRM=1024

TOP_PORTS="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

# ----------------------------- args ---------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -i) IFACE="$2"; shift 2;;
    -n) CIDR="$2"; shift 2;;
    -p) DO_PORTS=1; shift;;
    -P) PORTS_SPEC="$2"; DO_PORTS=1; shift 2;;
    --pn) PN=1; shift;;
    -d) DELAY_MS="$2"; shift 2;;
    -t) TIMEOUT="$2"; shift 2;;
    -j) JOBS="$2"; shift 2;;
    --no-ports) DO_PORTS=0; shift;;
    --no-ping) DO_PING=0; shift;;
    --no-arp) DO_ARP=0; shift;;
    --force) FORCE=1; shift;;
    -h|--help) usage;;
    *) err "Option inconnue : $1"; usage;;
  esac
done

# ----------------------------- helpers ip ---------------------------
ip2int() { local IFS=.; read -r a b c d <<<"$1"; echo $(( (a<<24)+(b<<16)+(c<<8)+d )); }
int2ip() { local i=$1; echo "$(((i>>24)&255)).$(((i>>16)&255)).$(((i>>8)&255)).$((i&255))"; }

# pause d'un certain delai (base + jitter) pour la furtivite
stealth_sleep() {
  (( DELAY_MS <= 0 )) && return
  local jitter=$(( RANDOM % (DELAY_MS + 1) ))
  local total=$(( DELAY_MS + jitter ))
  sleep "$(awk -v m="$total" 'BEGIN{printf "%.3f", m/1000}')"
}

# ----------------------- autodetection iface/cidr -------------------
if ! have ip; then err "'ip' introuvable, impossible de continuer."; exit 1; fi

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
if (( PREFIX >= 31 )); then
  mask=$(( 0xFFFFFFFF << (32-PREFIX) & 0xFFFFFFFF ))
  netaddr=$(( ip_int & mask ))
  first=$netaddr; last=$(( netaddr + (2**(32-PREFIX)) - 1 ))
else
  mask=$(( 0xFFFFFFFF << (32-PREFIX) & 0xFFFFFFFF ))
  netaddr=$(( ip_int & mask ))
  bcast=$(( netaddr | (~mask & 0xFFFFFFFF) ))
  first=$(( netaddr + 1 )); last=$(( bcast - 1 ))
fi
NHOSTS=$(( last - first + 1 ))

hdr "Configuration"
info "Interface      : ${C_B}$IFACE${C_RST}"
info "IP locale      : ${C_B}${MY_IP:-?}${C_RST}"
info "Reseau cible   : ${C_B}$(int2ip $netaddr)/$PREFIX${C_RST}  (${NHOSTS} hotes)"
info "Ping sweep     : $([[ $DO_PING == 1 ]] && echo oui || echo non)   ARP/L2 : $([[ $DO_ARP == 1 ]] && echo oui || echo non)"
info "Scan de ports  : $([[ $DO_PORTS == 1 ]] && echo "oui ($PORTS_SPEC)$([[ $PN == 1 ]] && echo ' [-Pn]')" || echo non)"
info "Outils         : arp-scan=$(have arp-scan&&echo oui||echo non) nmap=$(have nmap&&echo oui||echo non) nc=$(have nc&&echo oui||echo non)"

# Confirmation seulement en interactif ET sans --force : jamais de blocage si couple a un script.
if (( NHOSTS > MAX_HOSTS_NOCONFIRM && FORCE == 0 )) && [[ -t 0 ]]; then
  warn "La plage contient $NHOSTS hotes (> $MAX_HOSTS_NOCONFIRM)."
  read -rp "Continuer ? [y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]] || { info "Abandon."; exit 0; }
elif (( NHOSTS > MAX_HOSTS_NOCONFIRM )); then
  warn "Grande plage : $NHOSTS hotes. (lancement automatique)"
fi

# liste des IP cibles
TARGETS=(); for ((i=first; i<=last; i++)); do TARGETS+=("$(int2ip $i)"); done

# ====================================================================
# 1. DECOUVERTE : ARP/L2 + PING SWEEP
# ====================================================================
declare -A PING_UP ARP_UP ARP_MAC

run_with_jobs() {  # run_with_jobs <fn> : lit les IP sur stdin, limite a $JOBS
  local fn="$1" ip
  while read -r ip; do
    "$fn" "$ip" &
    while (( $(jobs -rp | wc -l) >= JOBS )); do wait -n 2>/dev/null || break; done
  done
  wait
}

# -- ping sweep --
ping_one() {
  local ip="$1"
  if ping -c1 -W1 -n "$ip" >/dev/null 2>&1; then echo "PING $ip"; fi
}

# -- provoque ARP via TCP connect (marche meme si ICMP filtre) --
arp_provoke() {
  local ip="$1" port
  for port in 80 443 22 445; do
    timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/$ip/$port" 2>/dev/null && { exec 3>&- 2>/dev/null; break; }
  done
  return 0
}

if (( DO_ARP )); then
  hdr "Decouverte L2 (ARP)"
  if have arp-scan; then
    info "arp-scan detecte -> scan ARP natif (necessite root)..."
    while read -r ip mac _; do
      [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
      ARP_UP["$ip"]=1; ARP_MAC["$ip"]="$mac"
    done < <(arp-scan --interface="$IFACE" --localnet 2>/dev/null | awk '/^[0-9]+\./{print $1,$2}')
  else
    info "Pas de arp-scan : on provoque la resolution ARP via TCP connect..."
    printf '%s\n' "${TARGETS[@]}" | run_with_jobs arp_provoke
    # lecture de la table de voisinage
    # format : "IP lladdr MAC STATE"
    while read -r ip _ mac state; do
      [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
      # on ne garde que les IP dans la plage ciblee (le cache neigh est global)
      ipi=$(ip2int "$ip"); (( ipi < first || ipi > last )) && continue
      case "$state" in REACHABLE|STALE|DELAY|PROBE)
        ARP_UP["$ip"]=1; ARP_MAC["$ip"]="$mac";;
      esac
    done < <(ip neigh show dev "$IFACE" 2>/dev/null | grep lladdr)
  fi
  ok "Hotes presents en L2 (ARP) : ${C_B}${#ARP_UP[@]}${C_RST}"
fi

if (( DO_PING )); then
  hdr "Ping sweep (ICMP)"
  info "Ping de $NHOSTS hotes (parallelisme $JOBS)..."
  while read -r tag ip; do [[ "$tag" == PING ]] && PING_UP["$ip"]=1; done \
    < <(printf '%s\n' "${TARGETS[@]}" | run_with_jobs ping_one)
  ok "Hotes qui repondent au ping : ${C_B}${#PING_UP[@]}${C_RST}"
fi

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
# hotes interessants = L2 sans ping
GHOSTS=(); for ip in "${SORTED[@]}"; do [[ -n "${ARP_UP[$ip]:-}" && -z "${PING_UP[$ip]:-}" ]] && GHOSTS+=("$ip"); done
(( ${#GHOSTS[@]} )) && warn "Hotes visibles en L2 qui ne repondent pas au ping : ${C_B}${GHOSTS[*]}${C_RST}"

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

echo
info "Voisins connus sur d'autres reseaux (cache ARP global) :"
ip -o -f inet neigh show 2>/dev/null | awk '{print $1}' | sort -u | while read -r nip; do
  [[ -z "$nip" ]] && continue
  if [[ "$nip" != "$(int2ip $netaddr)"* ]]; then
    nint=$(ip2int "$nip"); (( (nint & mask) != netaddr )) && printf '    %s\n' "$nip"
  fi
done

GW="$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')"
if [[ -n "$GW" ]] && have traceroute; then
  echo
  info "Traceroute vers la passerelle ($GW) puis au-dela (8.8.8.8) pour reveler les routeurs intermediaires :"
  traceroute -n -m 5 -w 1 "$GW" 2>/dev/null | awk 'NR>0{print "    "$0}'
  warn "Astuce : chaque saut intermediaire est un routeur -> souvent une porte vers un autre sous-reseau."
fi

# ====================================================================
# 3. SCAN DE PORTS
# ====================================================================
if (( DO_PORTS )); then
  hdr "Scan de ports"

  # cible : hotes up, ou tous (--pn)
  if (( PN )); then
    SCAN_TARGETS=("${TARGETS[@]}")
    info "Mode -Pn : scan de tous les ${#SCAN_TARGETS[@]} hotes de la plage."
  else
    SCAN_TARGETS=("${SORTED[@]}")
    info "Scan des ${#SCAN_TARGETS[@]} hotes decouverts."
  fi
  (( ${#SCAN_TARGETS[@]} == 0 )) && { warn "Aucun hote a scanner."; exit 0; }

  # resolution de la liste de ports
  if [[ "$PORTS_SPEC" == "top" ]]; then
    PORTLIST="$TOP_PORTS"
  elif [[ "$PORTS_SPEC" == "all" ]]; then
    PORTLIST="1-65535"
  else
    PORTLIST="$PORTS_SPEC"
  fi

  # ---- chemin nmap (plus furtif : SYN scan en root) ----
  if have nmap; then
    # nmap dispo -> lancement automatique du scan le plus furtif possible
    if [[ $EUID -eq 0 ]]; then
      NMAP_FLAGS="-sS -T2 -f --randomize-hosts"      # SYN scan furtif + fragmentation
      info "nmap + root -> SYN scan furtif (-sS -f)."
    else
      NMAP_FLAGS="-sT -T2 --randomize-hosts"
      warn "nmap sans root -> SYN scan indispo, connect-scan nmap (-sT)."
    fi
    PFLAG=$([[ "$PORTLIST" == "1-65535" ]] && echo "-p-" || echo "-p $PORTLIST")
    [[ $PN == 1 ]] && NMAP_FLAGS="$NMAP_FLAGS -Pn"
    info "Commande : nmap $NMAP_FLAGS $PFLAG <${#SCAN_TARGETS[@]} hotes>"
    nmap $NMAP_FLAGS $PFLAG "${SCAN_TARGETS[@]}"
    exit 0
  else
    info "nmap absent -> connect-scan bash (/dev/tcp)."
    warn "Note furtivite : un connect-scan ouvre la connexion complete (loggee cote service)."
    warn "Mitigations actives : ordre aleatoire des hotes/ports, delai+jitter (-d), timeout court."
  fi

  # ---- connect-scan bash ----
  # expansion de la liste de ports en tableau
  expand_ports() {
    local spec="$1" part lo hi
    IFS=',' read -ra parts <<<"$spec"
    for part in "${parts[@]}"; do
      if [[ "$part" == *-* ]]; then
        lo="${part%-*}"; hi="${part#*-}"
        for ((p=lo; p<=hi; p++)); do echo "$p"; done
      else echo "$part"; fi
    done
  }
  mapfile -t PORTS_ARR < <(expand_ports "$PORTLIST")
  # ordre aleatoire des ports
  mapfile -t PORTS_ARR < <(printf '%s\n' "${PORTS_ARR[@]}" | shuf 2>/dev/null || printf '%s\n' "${PORTS_ARR[@]}")
  # ordre aleatoire des hotes
  mapfile -t SCAN_TARGETS < <(printf '%s\n' "${SCAN_TARGETS[@]}" | shuf 2>/dev/null || printf '%s\n' "${SCAN_TARGETS[@]}")

  info "Ports a tester par hote : ${#PORTS_ARR[@]}  | timeout ${TIMEOUT}s | parallelisme $JOBS | delai ${DELAY_MS}ms+jitter"
  for ip in "${SCAN_TARGETS[@]}"; do
    printf '%s[scan]%s %s\n' "$C_CYN" "$C_RST" "$ip"
    tmp="$(mktemp)"
    # scan parallele des ports ; chaque port ouvert ecrit son numero dans $tmp
    {
      for port in "${PORTS_ARR[@]}"; do
        ( timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/$ip/$port" 2>/dev/null && echo "$port"; stealth_sleep ) &
        while (( $(jobs -rp | wc -l) >= JOBS )); do wait -n 2>/dev/null || break; done
      done
      wait
    } > "$tmp"
    if [[ -s "$tmp" ]]; then
      sort -n "$tmp" | while read -r port; do
        printf '  %s%-16s%s port %s%-6s%s %souvert%s\n' "$C_B" "$ip" "$C_RST" "$C_GRN" "$port" "$C_RST" "$C_GRN" "$C_RST"
      done
    else
      printf '  %s(aucun port ouvert)%s\n' "$C_DIM" "$C_RST"
    fi
    rm -f "$tmp"
  done
fi

hdr "Termine"
