# 🛡️ PentestKit v1.0 — Web-Based Penetration Testing Tool

> ⚠️ **For authorized security testing only. Do not use on systems you don't own or have explicit permission to test.**

## 🚀 Quick Start

### Option 1 — Script automatique
```bash
chmod +x start.sh
./start.sh
```

### Option 2 — Manuel
```bash
# Installer les dépendances
pip install -r requirements.txt

# Lancer le serveur
python3 app.py

# Ouvrir dans le navigateur
# http://localhost:5000
```

### Option 3 — Docker
```bash
docker build -t pentestkit .
docker run -p 5000:5000 pentestkit
```

---

## 📦 Modules disponibles

### 🔍 Network
| Module | Description |
|--------|-------------|
| **Port Scanner** | TCP scan avec détection de services et banner grabbing |
| **Ping / Traceroute** | Test de connectivité réseau |
| **Banner Grabbing** | Capture des bannières de services |
| **Firewall Detect** | Détection de pare-feu par analyse du filtrage |

### 🕵️ Reconnaissance
| Module | Description |
|--------|-------------|
| **DNS Enumeration** | Records A/AAAA/MX/NS/TXT/SOA + zone transfer + DNSSEC |
| **Subdomain Enum** | Brute-force de sous-domaines (~150 wordlist intégrée) |
| **WHOIS / GeoIP** | Informations d'enregistrement + géolocalisation IP |
| **Google Dorks** | Générateur de requêtes Google Dork (6 catégories) |

### 🌍 Web Security
| Module | Description |
|--------|-------------|
| **HTTP Analyzer** | Headers sécurité, cookies, CORS, technologies |
| **SSL/TLS Scanner** | Certificat, protocoles, chiffrement, vulnérabilités |
| **Directory Scanner** | Découverte de répertoires et fichiers cachés |
| **robots.txt** | Analyse du fichier robots.txt |

### 💥 Vulnerabilities
| Module | Description |
|--------|-------------|
| **SQLi Tester** | Error-based, Time-based blind, Boolean |
| **XSS Tester** | Reflected XSS avec 10+ payloads |
| **LFI Tester** | Local File Inclusion (/etc/passwd, etc.) |
| **Misconfigs** | TRACE, PUT, directory listing, .git/.env exposés |

### 🗄️ Database Extraction
| Mode | Description |
|------|-------------|
| **Basic** | Version DB, user, hostname |
| **Enum** | Liste des bases et tables |
| **Dump** | Extraction de données (UNION-based) |

### 🔑 Tools
| Module | Description |
|--------|-------------|
| **Hash Identify** | Identification de type de hash |
| **Hash Generate** | MD5/SHA1/SHA256/SHA512/Blake2b |
| **Hash Crack** | Dictionnaire intégré (1000+ passwords) |
| **Password Analyzer** | Score de robustesse + entropie |
| **Password Generator** | Génération sécurisée |
| **Report Generator** | Rapport HTML professionnel |

---

## ⌨️ Raccourcis clavier

| Touche | Action |
|--------|--------|
| `F5` ou `Ctrl+Enter` | Lancer le scan actif |
| `Escape` | Arrêter le scan |
| `Ctrl+L` | Effacer le terminal |

---

## 🏗️ Architecture

```
PentestKit/
├── app.py                  # Serveur Flask principal
├── requirements.txt        # Dépendances Python
├── start.sh               # Script de démarrage
├── templates/
│   └── index.html         # Interface web (SPA)
├── modules/
│   ├── port_scanner.py    # Scanner de ports
│   ├── dns_enum.py        # Énumération DNS
│   ├── http_analyzer.py   # Analyse HTTP/headers
│   ├── ssl_analyzer.py    # Analyse SSL/TLS
│   ├── dir_scanner.py     # Scanner de répertoires
│   ├── whois_lookup.py    # WHOIS et GeoIP
│   ├── network_tools.py   # Ping, traceroute, banner
│   ├── vuln_scanner.py    # SQLi, XSS, LFI, redirects
│   ├── db_extractor.py    # Extraction base de données
│   ├── hash_tools.py      # Outils de hachage
│   └── report_generator.py # Génération de rapports
└── reports/               # Rapports générés
```

---

## ⚖️ Avertissement légal

Cet outil est fourni à des fins éducatives et de test de sécurité autorisé uniquement. L'utilisation sur des systèmes sans autorisation explicite est illégale. Les auteurs ne sont pas responsables de tout usage abusif.
