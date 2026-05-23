# 🚀 Comment lancer PentestKit — Guide complet

---

## 📱 OPTION 1 — TERMUX (Android) ✅ MEILLEUR POUR TÉLÉPHONE

Termux = terminal Linux sur Android, **GRATUIT**, fonctionne hors ligne.

### Installation rapide (copie-colle dans Termux)

```bash
# 1. Mise à jour
pkg update -y && pkg upgrade -y

# 2. Installer Python et les outils réseau
pkg install -y python git nmap traceroute dnsutils

# 3. Cloner le projet (remplace par ton vrai repo)
git clone https://github.com/TON-USER/pentestkit ~/PentestKit
cd ~/PentestKit

# 4. Installer les dépendances Python
pip install flask flask-cors requests dnspython python-whois

# 5. Lancer !
python app.py
```

### 🌐 Accéder à l'interface
Ouvre le navigateur de ton Android sur :
```
http://localhost:5000
```

### 📲 Installer Termux
- **Google Play** : ❌ version obsolète
- **F-Droid** : ✅ https://f-droid.org → chercher "Termux"
- **GitHub** : ✅ https://github.com/termux/termux-app/releases

---

## 💻 OPTION 2 — REPLIT (En ligne, URL publique gratuite)

Replit te donne une URL publique accessible depuis n'importe où.

### Étapes
1. Aller sur **https://replit.com** → Créer un compte
2. Cliquer **"Create Repl"** → Choisir **Python**
3. Uploader les fichiers du projet OU connecter GitHub
4. Dans le fichier `.replit` mettre :
   ```
   run = "python app.py"
   ```
5. Cliquer **RUN** ▶️
6. Tu obtiens une URL : `https://pentestkit.ton-user.repl.co`

---

## 🚂 OPTION 3 — RAILWAY.APP (Hébergement cloud GRATUIT)

Railway = hosting gratuit, déploiement en 1 clic depuis GitHub.

### Étapes
1. Aller sur **https://railway.app** → Compte gratuit
2. **"New Project"** → **"Deploy from GitHub repo"**
3. Sélectionner ton repo
4. Railway détecte automatiquement Python et lance
5. Tu obtiens une URL : `https://pentestkit-production.up.railway.app`

✅ **500h/mois gratuites**, domaine custom possible

---

## 🎨 OPTION 4 — RENDER.COM (Gratuit, toujours dispo)

```bash
# render.yaml déjà configuré dans le projet
# Il suffit de :
# 1. Créer compte sur render.com
# 2. "New Web Service" → connecter GitHub
# 3. Render déploie automatiquement
```

---

## 🐳 OPTION 5 — DOCKER (Partout)

```bash
# Builder l'image
docker build -t pentestkit .

# Lancer
docker run -p 5000:5000 pentestkit

# Accéder
# http://localhost:5000
```

---

## 🖥️ OPTION 6 — KALI LINUX (Best pour pentest sérieux)

Kali Linux = distro dédiée au pentest, avec tous les outils.

```bash
# Sur Kali ou tout Linux/Mac
git clone https://github.com/TON-USER/pentestkit
cd pentestkit
pip3 install flask flask-cors requests dnspython python-whois
python3 app.py

# Accéder depuis le réseau local :
# http://[TON-IP]:5000
```

**Kali sur Android** : NetHunter (https://www.kali.org/get-kali/#kali-nethunter)

---

## ☁️ OPTION 7 — VPS ORACLE FREE TIER (Gratuit à vie!)

Oracle offre un VPS **GRATUIT À VIE** avec 4 CPU + 24GB RAM.

```bash
# Sur ton VPS Oracle
git clone https://github.com/TON-USER/pentestkit
cd pentestkit
pip3 install flask flask-cors requests dnspython python-whois

# Lancer en arrière-plan
nohup python3 app.py &

# Accéder depuis ton téléphone :
# http://IP-PUBLIQUE-VPS:5000
```

1. Créer compte : **https://oracle.com/cloud/free**
2. Créer une instance ARM Ubuntu
3. Ouvrir le port 5000 dans le firewall
4. C'est parti !

---

## 📊 Comparatif

| Option | Coût | Accès depuis téléphone | Vitesse | Recommandé |
|--------|------|------------------------|---------|------------|
| **Termux** | 🆓 Gratuit | ✅ localhost | ⚡ Ultra rapide | 🥇 **MEILLEUR** |
| **Replit** | 🆓 Gratuit | ✅ URL publique | ⚡ Rapide | 🥈 Très bien |
| **Railway** | 🆓 Gratuit | ✅ URL publique | ⚡ Rapide | 🥈 Très bien |
| **Render** | 🆓 Gratuit | ✅ URL publique | 🐌 Froid = lent | 🥉 OK |
| **Docker** | 🆓 Gratuit | ✅ Réseau local | ⚡ Ultra rapide | 💡 Dev |
| **Oracle VPS** | 🆓 Gratuit | ✅ URL publique | ⚡ Rapide | 🥇 **PRO** |
| **GitHub** | ❌ Impossible | - | - | ❌ Non |

---

## ⚠️ Rappel légal

Utilise cet outil **uniquement** sur des systèmes que tu es autorisé à tester.
L'accès non autorisé est illégal dans tous les pays.
