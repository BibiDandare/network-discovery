# netdiscover.sh — Reconnaissance réseau autonome en bash

Script bash de **découverte réseau complète** et **scan de ports**, conçu pour fonctionner sans dépendances obligatoires et s'intégrer dans d'autres scripts (mode non-interactif par défaut).

## Fonctionnalités

### 1️⃣ Découverte L2 (ARP) + Ping sweep
- **Scan ARP** pour détecter les hôtes présents à la couche 2 (MAC address)
  - Utilise `arp-scan` s'il est disponible (vrai scan ARP raw)
  - Sinon : provoque la résolution ARP via tentatives TCP (hôtes firewallés détectés aussi)
- **Ping sweep ICMP** pour voir qui répond à l'ICMP
- **Tableau comparatif** : met en évidence les hôtes visibles en L2 mais ne répondant pas au ping (ICMP filtré/firewall)

### 2️⃣ Découverte d'autres sous-réseaux
- Lecture de la table de routage (`ip route`)
- Voisins ARP détectés hors du réseau cible
- Traceroute vers la passerelle → révèle les routeurs intermédiaires

### 3️⃣ Scan de ports
- **Tous les ports** (`1-65535`) par défaut
- **Furtif si possible** :
  - Si `nmap` + root → **SYN scan `-sS -f`** (fragmentation) ← vraie furtivité
  - Si `nmap` seul → connect-scan via nmap `-sT`
  - Sinon → connect-scan bash `/dev/tcp` parallélisé (randomisé, timeouts courts)
- Ports triés en résultat, sortie colorée (ou plain text si piped)

---

## Technologies utilisées

| Composant | Outil | Obligatoire | Rôle |
|-----------|-------|-------------|------|
| **Réseau** | `ip` | ✅ OUI | Détection interface, routes, ARP cache |
| **ICMP** | `ping` | ✅ OUI | Ping sweep |
| **Timing** | `timeout` | ✅ OUI | Limiter les connexions stagnantes |
| **Shell** | `bash` ≥ 4 | ✅ OUI | `/dev/tcp` pour TCP connect-scan |
| **Utilitaires** | `awk`, `shuf`, `mktemp`, `sort` | ✅ OUI | Traitement de texte, randomisation |
| **Traçage** | `traceroute` | ❌ OPT | Découverte de routeurs intermédiaires |
| **Scan ARP avancé** | `arp-scan` | ❌ OPT | Vrai scan L2 raw (meilleur que TCP provoke) |
| **Scan ports furtif** | `nmap` | ❌ OPT | SYN scan (`-sS`), fragmentation, stealth |

### Pourquoi pas de dépendances obligatoires ?

- **`ip`** + **`ping`** : socles de tout discovery réseau Unix
- **`bash` 5+ `/dev/tcp`** : permet TCP connect-scan **sans nmap** (sinon fallback complet)
- **`arp-scan` / `nmap` optionnels** : utilisés automatiquement s'ils existent, sinon implémentation bash pure

---

## Installation & prérequis

### Prérequis minimaux (tout OS Linux moderne)

```bash
# Vérifier que tu as bash ≥ 4 et ip/ping
bash --version      # → bash 4.X ou 5.X
command -v ip       # → /usr/bin/ip (présent par défaut)
command -v ping     # → /bin/ping (présent par défaut)
```

### (Optionnel) Pour meilleure furtivité : installer nmap + arp-scan

```bash
# Debian / Ubuntu
sudo apt install nmap arp-scan

# RedHat / CentOS
sudo yum install nmap arp-scan

# Alpine
apk add nmap arp-scan
```

### Télécharger le script

```bash
# Si déjà présent à ~/netdiscover.sh
chmod +x ~/netdiscover.sh

# Ou cloner/copier depuis source
cp netdiscover.sh /usr/local/bin/  # (optionnel)
chmod +x /usr/local/bin/netdiscover.sh
```

---

## Usage

### Mode par défaut (aucune option)

Lancement complet : découverte + tous les ports, non-interactif (idéal pour scripts).

```bash
./netdiscover.sh
```

**Résultat attendu** :
```
=== Configuration ===
[*] Interface      : eth0
[*] IP locale      : 192.168.1.10
[*] Reseau cible   : 192.168.1.0/24  (254 hotes)
...
=== Decouverte L2 (ARP) ===
[+] Hotes presents en L2 (ARP) : 12
=== Ping sweep (ICMP) ===
[+] Hotes qui repondent au ping : 10
=== Comparatif : visibles (ARP) vs joignables (ping) ===
192.168.1.1      aa:bb:cc:dd:ee:ff  oui      oui
192.168.1.50     —                 oui      non    <- visible L2 mais ne ping pas (ICMP filtre ?)
...
=== Scan de ports ===
[scan] 192.168.1.1
  192.168.1.1      port 22     ouvert
  192.168.1.1      port 80     ouvert
...
```

### Exemples spécifiques

#### Découverte seule (pas de scan de ports)
```bash
./netdiscover.sh --no-ports
```

#### Scanner un réseau spécifique
```bash
./netdiscover.sh -n 10.0.0.0/24 -i eth1
```

#### Scan ports seulement sur certains ports
```bash
./netdiscover.sh -P 22,80,443,8080,3306
```

#### Scanner aussi les hôtes qui ne répondent pas (comme nmap `-Pn`)
```bash
./netdiscover.sh --pn
```

#### Scanner avec délai/jitter pour plus de furtivité
```bash
./netdiscover.sh -d 500 -j 32 -t 2
# -d 500 : 500ms+jitter entre chaque probe
# -j 32  : moins de parallélisme (stealth)
# -t 2   : timeout 2s (plus tolérant)
```

#### Coupler dans un autre script (capture output)
```bash
#!/bin/bash
output=$(/path/to/netdiscover.sh 2>&1)
echo "$output" | grep -E "port.*ouvert" | awk '{print $1}'  # liste IP avec ports ouverts
```

---

## Options complètes

```
./netdiscover.sh [options]

  -i IFACE      Interface réseau (défaut : détection auto via route)
  -n CIDR       Réseau cible, ex 192.168.1.0/24 (défaut : auto depuis interface)
  
  -P LISTE      Ports à scanner :
                  "all"           → 1-65535 (défaut)
                  "top"           → ports courants (21,22,80,443,...)
                  "22,80,443"     → liste explicite
                  "1-1024"        → plage
  
  -p            Activer scan de ports (défaut : oui)
  --no-ports    Désactiver scan de ports (découverte seule)
  
  --pn          Scanner aussi les hôtes "muets" (no ping, équiv nmap -Pn)
  
  -d MS         Délai de base entre probes de port en ms (défaut 0)
                Du jitter aléatoire est ajouté pour plus de furtivité
  
  -t SEC        Timeout de connexion en secondes (défaut 1)
  
  -j N          Parallélisme hôtes ET ports (défaut 64)
                Moins = plus furtif mais plus lent
                Plus = plus rapide mais plus bruyant
  
  --no-ping     Ne pas faire le ping sweep
  --no-arp      Ne pas faire la découverte ARP/L2
  --force       (défaut) : ignore les prompts de confirmation
  
  -h            Affiche cette aide
```

---

## Détails techniques

### ARP Discovery (L2)

#### Avec `arp-scan` (idéal)
- Envoie des requêtes ARP raw à la couche 2 (pas dépendant d'ICMP)
- Détecte **tous les hôtes qui répondent au protocole ARP**, même ceux qui filtrent l'ICMP
- Rapide et vrai

#### Sans `arp-scan` (fallback bash)
- Provoque la résolution ARP via tentatives TCP connect à ports courants (80, 443, 22, 445)
- Le noyau **doit** résoudre le MAC avant d'envoyer le SYN (indépendant de la réponse IP)
- Lit ensuite `ip neigh show` pour récupérer les MACs découverts
- **Avantage** : fonctionne même sur hôtes firewallés (ICMP bloqué)
- **Désavantage** : plus lent que vrai ARP scan

### Ping Sweep (ICMP)

```bash
ping -c1 -W1 -n <IP>
```
- `-c1` : un seul echo
- `-W1` : timeout 1s
- Parallélisé jusqu'à `$JOBS` (défaut 64) hôtes en même temps

### Scan de ports

#### Avec `nmap` (furtivité optimale)

**Si root** :
```bash
nmap -sS -T2 -f -p- --randomize-hosts <hotes>
```
- `-sS` : **SYN scan** (ne complète jamais la connexion TCP) → plus furtif
- `-f` : fragmente les paquets (anti-IDS)
- `-T2` : timing "polite" (lent)
- `-p-` : tous les ports

**Si user normal** :
```bash
nmap -sT -T2 --randomize-hosts -p- <hotes>
```
- `-sT` : connect-scan (fallback, pas de SYN privé)

#### Sans `nmap` (bash `/dev/tcp`)

```bash
exec 3<>/dev/tcp/<IP>/<PORT> 2>/dev/null && echo "$PORT"
```
- Bête et méchant : ouvre connexion TCP complète
- **Non furtif** : loggé côté service
- **Avantage** : aucune dépendance externe

**Optimisations pour la furtivité (bash)** :
- Ordre aléatoire hôtes (`shuf`)
- Ordre aléatoire ports (`shuf`)
- Délai configurable (`-d`) + jitter aléatoire
- Timeout court (1s défaut)
- Parallélisation modérée (réduire `-j` = plus lent mais plus discret)

---

## Furtivité : comparatif des approches

| Méthode | Discrétion | Rapidité | Dépendance |
|---------|-----------|----------|-----------|
| **nmap SYN (-sS)** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | nmap + root |
| **nmap connect (-sT)** | ⭐⭐⭐ | ⭐⭐⭐ | nmap |
| **bash /dev/tcp** | ⭐⭐ | ⭐⭐⭐ | bash 4+ (aucun autre) |
| **arp-scan** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | arp-scan (optionnel) |

### Recommandations

- **Pentest interne / lab** : `nmap -sS` en root → furtivité + rapidité
- **Environnement restreint** : bash `/dev/tcp` + `-d 1000 -j 16` → lent mais sans dépendance
- **Découverte rapide** : bash `/dev/tcp` + `-j 100` → bruyant mais rapide
- **Éviter la détection IDS** : `nmap -sS -f -T1 --spoof-mac` (plus les options du script)

---

## Couplage dans un autre script

```bash
#!/bin/bash
# Exemple : lancer netdiscover et récupérer les résultats

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_NET="${1:-192.168.1.0/24}"

# Lancer le scan (non-interactif, pas de couleurs si piped)
output=$("$SCRIPT_DIR/netdiscover.sh" -n "$TARGET_NET" 2>&1)

# Extraire les ports ouverts
echo "=== Ports ouverts détectés ==="
echo "$output" | grep "ouvert" | awk '{print $1, $3}' | sort -u

# Ou : extraire les adresses IP des hôtes découverts
echo "=== Hôtes découverts ==="
echo "$output" | grep -E "^\d+\.\d+\.\d+\.\d+" | awk '{print $1}' | sort -u

# Ou : check si un port spécifique est ouvert
if echo "$output" | grep -q "22.*ouvert"; then
  echo "SSH (port 22) ouvert !"
fi
```

### Sortie non-colorée quand piped

Le script détecte automatiquement si stdout est un terminal :
```bash
[[ -t 1 ]] && export COLORS=1 || export COLORS=0
```

Donc `./netdiscover.sh | grep ...` donne du texte brut, facile à parser.

---

## Limitations connues

1. **Pas de protocoles autres que TCP** : HTTP, DNS, SNMP scans nécessitent nmap ou outils spécialisés
2. **Hôtes filtrés → lents** : si un hôte drop tous les paquets (no RST), chaque port attend le timeout complet
3. **Pas de UDP** : seul TCP connect-scan / nmap SYN
4. **Pas de chemin réseau inversé** : pas de scan de sous-réseaux non-contigus
5. **Pas d'OS fingerprinting** : seul port knocking

---

## Exemples d'output

### Avec hôtes détectés

```
=== Comparatif : visibles (ARP) vs joignables (ping) ===
IP               MAC                 ARP      PING    
------------------------------------------------------------
192.168.1.1      bc:24:11:6b:1b:e3   oui      oui
192.168.1.50     aa:bb:cc:dd:ee:ff   oui      non    <- visible L2 mais ne ping pas (ICMP filtre ?)
192.168.1.100    bb:cc:dd:ee:ff:aa   non      oui    <- ping only, ARP pas resolu (timeout provoke)

[+] Total joignables : 3  | ARP : 2  | Ping : 3
```

### Scan de ports

```
=== Scan de ports ===
[*] Scan des 3 hotes decouverts.
[*] nmap absent -> connect-scan bash (/dev/tcp).
[*] Ports a tester par hote : 65535  | timeout 1s | parallelisme 64 | delai 0ms+jitter
[scan] 192.168.1.1
  192.168.1.1      port 22     ouvert
  192.168.1.1      port 80     ouvert
  192.168.1.1      port 443    ouvert
[scan] 192.168.1.50
  192.168.1.50     port 3306   ouvert
[scan] 192.168.1.100
  192.168.1.100    (aucun port ouvert)
```

---

## Troubleshooting

### Le script dit "Aucune interface detectee"
```bash
# Vérifier les interfaces disponibles
ip addr show

# Spécifier l'interface manuellement
./netdiscover.sh -i eth0 -n 192.168.1.0/24
```

### Pas d'hôtes trouvés
- Vérifier que le réseau est correct : `ip route show`
- Tester ping manuel : `ping -c1 192.168.1.1`
- Le réseau peut être vide ou isolé

### Scan de ports très lent
- Réduire la plage : `-P 1-1024` au lieu de `all`
- Augmenter parallelisme : `-j 200`
- Réduire timeout : `-t 0.5` (risque de faux négatifs)

### "Grande plage : N hotes" sans demande de confirmation
- C'est normal en mode non-interactif (stdin non-tty)
- Le script procède d'office (`--force` défaut)

---

## License & notes de sécurité

Ce script est fourni à titre éducatif et de test réseau interne.

⚠️ **Utilisation responsable** : ne scanner que des réseaux sur lesquels tu as autorisation. Les scans de ports non-autorisés peuvent être illégaux dans certaines juridictions.

---

## Contacts & contributions

Questions / bugs → voir code source ou ouvrir une issue.
