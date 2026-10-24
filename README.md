# dev_mode_unlock - Déblocage du mode développeur SFR Connect TV (V2 / V3)

**Retrouvez le code du mode développeur (Developer Mode / Developer Options) de votre décodeur SFR Connect TV V2 et V3, bloqué par mot de passe depuis la mise à jour firmware.**

Depuis une MAJ firmware, l'accès au **mode développeur** des décodeurs **SFR Connect TV** (plateforme **SDMC**, Android TV) est protégé par un **mot de passe / code PIN**. Ce projet montre que **ce n'est pas un code fixe** : le code est **calculé à partir du numéro de série de votre propre décodeur**, il est donc **reproductible** et **propre à votre matériel**.

Ce dépôt fournit un petit **script Python** qui analyse l'APK de l'app *Paramètres* de votre box et vous **affiche le code à saisir**.

> Projet d'interopérabilité, à usage strictement personnel sur son propre matériel.

---

## ✨ Fonctionnalités

- Récupère automatiquement le secret depuis l'**APK des Paramètres** (`com.android.tv.settings`).
- Gère **3 cas**, exactement comme le firmware :
  1. **Mot de passe calculé** — le code est dérivé du **numéro de série** (schéma **PBKDF2 + AES**).
  2. **Code fixe** — un PIN en dur est extrait directement de l'app.
  3. **Aucune protection** — activation par 7 clics, sans code.
- **Aucune dépendance externe** : AES implémenté en **Python pur** (bibliothèque standard uniquement).
- Fonctionne par **double-clic** (Windows) ou en ligne de commande.

---

## 🚀 Utilisation rapide

1. Récupérez l'**APK des Paramètres** de votre décodeur (voir ci-dessous).
2. Lancez le script :

```bash
python dev_mode_unlock.py
```

ou directement avec le chemin de l'APK :

```bash
python dev_mode_unlock.py chemin/vers/TvSettings.apk
```

3. Entrez le **numéro de série** si demandé → le script affiche le **code du mode développeur**.

---

## 📦 Récupérer l'APK des Paramètres 

Utilisez un explorateur de fichiers

**Numéro de série** : `Paramètres → À propos → État → Numéro de série`
(ou `adb shell getprop ro.serialno`).

---

## 📺 Modèles concernés

- **SFR Connect TV V2**
- **SFR Connect TV V3**
- Décodeurs **Android TV / SDMC** utilisant le même mécanisme.

Votre modèle n'est pas reconnu ? **Ouvrez une issue** (voir ci-dessous), c'est le meilleur moyen de le faire prendre en charge.

---

## 🐛 Signaler un modèle non géré

1. Connectez-vous à GitHub (ou créez un compte gratuit).
2. Ouvrez une issue avec le modèle pré-rempli :
   👉 https://github.com/dotkl3m/dev_mode_unlock/issues/new?template=retour-modele.md
3. Indiquez le **modèle**, le **firmware**, la **sortie du script** et joignez votre **APK zippée** (GitHub refuse le `.apk` brut).

---

## 🤝 Contribuer

Les **pull requests** sont ouvertes. Pour améliorer la **robustesse** ou la **compatibilité** (nouveaux modèles, cas particuliers, corrections) : forkez le dépôt et proposez vos changements.

---

## 🔧 Aspect technique

Projet de **reverse engineering Android** :

- Analyse du **bytecode DEX** (lecture de la table des chaînes, repérage des instructions `const-string`).
- Extraction du secret et du schéma de dérivation depuis l'APK système.
- **Cryptanalyse** du calcul du code : **PBKDF2-HMAC-SHA1** (salt `sdmc`, 10 000 itérations) → clé → **AES-256-ECB** → encodage Base64.
- **Réimplémentation complète en Python pur**, sans dépendance.

---

## ⚠️ Avertissement légal

Outil fourni **à des fins d'interopérabilité et d'usage personnel**, à utiliser **uniquement sur votre propre décodeur**. Vous êtes seul responsable de l'usage que vous en faites. Ce projet n'est **affilié à aucun opérateur ni fabricant**.

---

## 🔎 Mots-clés

`SFR Connect TV` · `Connect TV V2` · `Connect TV V3` · `mode développeur` · `developer mode` · `developer options` · `déblocage décodeur` · `unlock developer mode` · `Android TV` · `SDMC` · `décodeur SFR` · `box SFR` · `code PIN mode développeur` · `adb` · `reverse engineering` · `DEX` · `PBKDF2` · `AES` · `Python`
