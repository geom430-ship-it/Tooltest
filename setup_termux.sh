#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#  PentestKit - Script d'installation automatique pour Termux
#  Copie-colle tout ça dans Termux !
# ============================================================

echo "╔══════════════════════════════════════════╗"
echo "║  PentestKit — Installation Termux         ║"
echo "╚══════════════════════════════════════════╝"

# Mise à jour des paquets
echo "[1/5] Mise à jour..."
pkg update -y && pkg upgrade -y

# Installer les dépendances système
echo "[2/5] Installation Python, git, nmap..."
pkg install -y python git nmap traceroute dnsutils curl wget

# Installer pip si nécessaire
python -m ensurepip --upgrade 2>/dev/null || pip install --upgrade pip

# Cloner le repo
echo "[3/5] Clonage du projet..."
cd ~
git clone https://github.com/geom430-ship-it/tooltest PentestKit 2>/dev/null || {
    echo "Repo privé — copie des fichiers manuelle nécessaire"
    mkdir -p ~/PentestKit
}
cd ~/PentestKit

# Installer les dépendances Python
echo "[4/5] Installation des librairies Python..."
pip install flask flask-cors requests dnspython python-whois

# Lancer le tool
echo "[5/5] Lancement de PentestKit..."
echo ""
echo "✅ Installation terminée !"
echo "🌐 Ouvre ton navigateur sur : http://localhost:8080"
echo ""
python app.py --port 8080
