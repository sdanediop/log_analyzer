# log_audit.py

Outil d'audit de sécurité pour fichiers logs — génère un rapport HTML unique couvrant la sécurité des logs, la détection de données personnelles et la conformité aux exigences de journalisation.

---

## Fonctionnalités

- **Détection automatique du format** : texte brut (Spring Boot, syslog, custom), JSON, CSV
- **Nettoyage des codes ANSI** et **fusion des stack traces multilignes** avant analyse
- **Rapport HTML unique** avec deux sections navigables : Sécurité / Données personnelles + Conformité / Complétude
- **Zéro dépendance externe** — stdlib Python uniquement

---

## Prérequis

- Python 3.8+
- Aucune bibliothèque externe requise

---

## Installation

```bash
git clone https://github.com/sdanediop/log_analyzer.git
cd log_audit
```

Aucune installation supplémentaire nécessaire.

---

## Usage

```bash
# Analyser un fichier unique
python3 log_audit.py fichier.log

# Analyser plusieurs fichiers
python3 log_audit.py audit.log cli.log webui.log

# Analyser tous les logs d'un répertoire
python3 log_audit.py --dir /var/log/appli/

# Nommer le rapport de sortie
python3 log_audit.py --dir /var/log/appli/ --output rapport_audit.html

# Formats supportés
python3 log_audit.py traces.json logs.csv service.log --output rapport.html
```

### Arguments

| Argument | Description |
|---|---|
| `files` | Un ou plusieurs fichiers à analyser (`.log`, `.txt`, `.json`, `.csv`) |
| `--dir`, `-d` | Répertoire à scanner (tous les `.log`, `.json`, `.csv`, `.txt`) |
| `--output`, `-o` | Chemin du rapport HTML de sortie (défaut : `audit_log_report.html`) |

---

## Checks implémentés

### [S] Sécurité

| ID | Détection |
|---|---|
| S-01 | Secrets et credentials en clair : `password=`, `secret=`, `api_key=`, `token=`, `Bearer`, JWT, bcrypt/SHA hash, clés privées SSH/PGP, certificats X.509, URLs JDBC, clés hexadécimales ≥ 64 chars, DSN |
| S-02 | IPs internes exposées (RFC 1918 : `10.x`, `172.16-31.x`, `192.168.x`) |
| S-03 | Stack traces exposées (Java, Python) |
| S-04 | Requêtes SQL complètes dans les logs |
| S-05 | Niveau de verbosité DEBUG actif (> 5% des entrées) |

### [F] Forensique

| ID | Détection |
|---|---|
| F-01 | Plage temporelle de l'extraction |
| F-02 | Couverture des horodatages (% de lignes avec timestamp reconnu) |
| F-03 | Empreinte SHA-256 du fichier (intégrité) |

### [A] Authentification

| ID | Détection |
|---|---|
| A-01 | Sessions sans logout correspondant |
| A-02 | Activité tracée après logout |
| A-03 | Échecs d'authentification répétés (`401`, `403`, `login failed`, `access denied`…) |

### [P] Privilèges

| ID | Détection |
|---|---|
| P-01 | Commandes sensibles (`configure`, `commit`, `sudo`, `chmod`, `reset password`, `addKeystore`…) |
| P-02 | Absence d'actions d'écriture (GET-only sans PUT/POST/DELETE) |
| P-03 | Activité entre 22h et 5h avec login ou commande sensible |

### [D] Données personnelles et métier

| ID | Détection | Niveau |
|---|---|---|
| D-01 | Numéros MSISDN sénégalais (`221[37]…`) | CRITIQUE |
| D-01b | Adresses email | ÉLEVÉ |
| D-02 | Noms complets en clair (heuristique) | ÉLEVÉ |
| D-03 | Champs PII dans les structures JSON (`userId`, `email`, `sessionId`…) | ÉLEVÉ |
| D-04 | Données financières Mobile Money (`solde`, `FCFA`, `Orange Money`, `balance`…) | ÉLEVÉ |
| D-05 | Numéros de carte bancaire — PAN (vérification Luhn + filtre contextuel) | CRITIQUE |
| D-07 | Codes OTP / PIN en clair (`otp=`, `pin=`, `totp=` + valeur numérique) | CRITIQUE |
| D-08 | Données d'identité par label (`cni=`, `passport=`, `dob=`, `date_naissance=`…) | CRITIQUE |
| D-10 | Identifiants télécom : IMEI (15 chiffres), ICCID (`89…`), IMSI (`608…`), numéros de contrat | ÉLEVÉ |

### [C] Conformité / Complétude

29 exigences vérifiées couvrant :

- Événements de sécurité généraux (activités utilisateur, exceptions, défaillances, actions CRUD)
- Authentification (réussites, échecs, mécanismes utilisés, élévations de privilèges)
- Gestion des comptes (ajout/suppression de comptes, droits, modifications d'authentification)
- Accès aux ressources (lecture, écriture, tentatives refusées)
- Modifications de stratégies de sécurité
- Activité des processus et du système (démarrages, arrêts, dysfonctionnements, modules)
- Format et qualité des logs (horodatage, identité utilisateur, IP source, valeurs avant/après modification)
- Masquage des données sensibles (contrôle croisé avec S-01)

Chaque exigence est évaluée comme **CONFORME**, **GAP CRITIQUE** ou **GAP MODÉRÉ**, avec un taux de conformité global calculé par fichier.

---

## Rapport HTML

Le rapport généré contient quatre onglets :

| Onglet | Contenu |
|---|---|
| **Findings sécurité** | Findings détaillés filtrables par criticité et catégorie, avec extraits de logs et commandes `grep` copy-paste |
| **Synthèse sécurité** | Tableau consolidé de tous les findings non-OK triés par criticité |
| **Conformité / Complétude** | Tableau par fichier avec barre de progression et statut exigence par exigence |
| **Récap gaps** | Liste consolidée des exigences non satisfaites |

Le header affiche simultanément le **niveau de risque sécurité** et le **statut de conformité** (NON CONFORME / PARTIELLEMENT CONFORME / CONFORME).

---

## Niveaux de criticité

| Niveau | Description |
|---|---|
| CRITIQUE | Exposition directe de données sensibles ou absence d'un contrôle de sécurité fondamental |
| ÉLEVÉ | Données personnelles exposées, stack traces, commandes privilégiées non tracées |
| MODÉRÉ | IPs internes, SQL verbose, actes hors horaires, gaps de conformité non bloquants |
| FAIBLE | Informations contextuelles à vérifier manuellement |
| INFO | Données de contexte (plage temporelle, volume, empreinte) |

---

## Formats de logs supportés

| Format | Détection | Traitement spécifique |
|---|---|---|
| Texte brut | Extension `.log` / `.txt` | Nettoyage ANSI, fusion stack traces multilignes Java |
| JSON | Extension `.json` ou détection auto | Parcours récursif de l'arbre (valeurs imbriquées détectées) |
| CSV | Extension `.csv` ou détection auto | Détection automatique du séparateur (`;`, `,`, `\t`, `\|`) |

---

## Limites connues

- **D-02 (noms)** : heuristique basée sur les séquences en majuscules — peut générer des faux positifs sur les acronymes techniques ou noms de classes Java. Qualification manuelle recommandée.
- **D-05 (PAN)** : la vérification Luhn élimine la plupart des faux positifs, mais des identifiants techniques longs peuvent passer le test par coïncidence. Un filtre contextuel exclut les lignes contenant des termes statistiques ou réseau (`OLS`, `regression`, `packet`, `counter`…).
- **D-08 (identité)** : détecte uniquement si un label contextuel est présent (`cni=`, `dob=`…). Les valeurs nues sans contexte ne sont pas détectées.
- **D-10 (IMEI)** : les IMEI (15 chiffres) peuvent matcher des timestamps epoch ou des identifiants techniques. Un filtre exclut les lignes avec des séquences de 16+ chiffres continus.
- Les checks d'authentification (A-01, A-02) supposent que login et logout sont dans le même fichier. Un logging fragmenté sur plusieurs fichiers peut générer des faux positifs.

---

## Exemple de sortie console

```
[*] service.log       (3842 entrées, format=text)
[*] traces.json       (1561 entrées, format=json)
[*] logs_voicebot.csv (1452 entrées, format=csv)

[+] Rapport généré : audit_log_report.html

--- Findings sécurité ---
  [CRITIQUE] D-01   Numéros MSISDN en clair : 19 numéro(s) distinct(s)
  [CRITIQUE] S-01   Secrets / credentials exposés (147 occurrence(s))
  [ÉLEVÉ   ] D-01b  Adresses email en clair : 4 adresse(s) distincte(s)
  [ÉLEVÉ   ] D-03   Champs PII dans les traces JSON : 250 occurrence(s)
  ... et 31 finding(s) supplémentaire(s)

--- Conformité : 53.1% (77/145) -- Gaps critiques : 33  Gaps modérés : 35 ---
```
