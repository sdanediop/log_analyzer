# log_analyzer

Outil d'audit de sécurité pour fichiers logs — génère un rapport HTML unique couvrant la sécurité des logs, la détection de données personnelles et la conformité aux exigences de journalisation.

Les patterns de détection et les exigences de conformité sont **externalisés dans des fichiers YAML**, modifiables sans toucher au code.

---

## Structure du projet

```
log_analyzer/
├── log_analyzer.py    # Moteur d'analyse et génération du rapport HTML
├── patterns/
│   ├── patterns.yaml      # Patterns de détection (sécurité, PII, auth, privilèges)
│   └── compliance.yaml    # Exigences de conformité (C-01 à C-29)
└── README.md
```

---

## Prérequis

- Python 3.8+
- `pyyaml` (seule dépendance externe)

---

## Installation

```bash
git clone https://github.com/sdanediop/log_analyzer.git
cd log_analyzer

# Créer un environnement virtuel (recommandé — obligatoire sur macOS/Homebrew)
python3 -m venv venv
source venv/bin/activate        # macOS / Linux
# venv\Scripts\activate         # Windows

pip install pyyaml
```

> **macOS avec Homebrew** — Si `pip install` échoue avec `externally-managed-environment`,
> utilise obligatoirement le venv ci-dessus, ou lance directement : `venv/bin/python3 log_analyzer.py`

---

## Usage

```bash
# Analyser un fichier unique
python3 log_analyzer.py fichier.log

# Analyser plusieurs fichiers (texte, JSON, CSV)
python3 log_analyzer.py audit.log traces.json events.csv

# Scanner un répertoire entier
python3 log_analyzer.py --dir /var/log/appli/

# Nommer le rapport de sortie
python3 log_analyzer.py --dir /var/log/appli/ --output rapport_audit.html
```

### Arguments

| Argument | Défaut | Description |
|---|---|---|
| `files` | — | Un ou plusieurs fichiers à analyser (`.log`, `.txt`, `.json`, `.csv`) |
| `--dir`, `-d` | — | Répertoire à scanner (tous les `.log`, `.json`, `.csv`, `.txt`) |
| `--output`, `-o` | `audit_log_report.html` | Chemin du rapport HTML de sortie |

---

## Formats de logs supportés

| Format | Détection | Traitement spécifique |
|---|---|---|
| Texte brut | Extension `.log` / `.txt` | Nettoyage codes ANSI, fusion stack traces multilignes Java |
| JSON | Extension `.json` ou détection auto | Parcours récursif de l'arbre — valeurs imbriquées détectées |
| CSV | Extension `.csv` ou détection auto | Détection automatique du séparateur (`;`, `,`, `\t`, `\|`) |

Formats testés : Spring Boot, syslog CEF, Allot DSC, logs applicatifs custom.

---

## Checks implémentés

### [S] Sécurité

| ID | Détection | Niveau |
|---|---|---|
| S-01 | Secrets et credentials en clair : `password=`, `token=`, `Bearer`, JWT, clés SSH/PGP, certificats X.509, URLs JDBC, hashes bcrypt/SHA, clés hex ≥ 64 chars, DSN | CRITIQUE |
| S-02 | IPs internes exposées (RFC 1918 : `10.x`, `172.16-31.x`, `192.168.x`) | MODÉRÉ |
| S-03 | Stack traces exposées (Java, Python) — noms de classes, chemins, numéros de lignes | ÉLEVÉ |
| S-04 | Requêtes SQL complètes loggées — schéma de BDD exposé | MODÉRÉ |
| S-05 | Niveau de verbosité DEBUG actif (> 5% des entrées) | MODÉRÉ |

### [F] Forensique

| ID | Détection |
|---|---|
| F-01 | Plage temporelle de l'extraction |
| F-02 | Couverture des horodatages (% de lignes avec timestamp reconnu) |
| F-03 | Empreinte SHA-256 du fichier (intégrité) |

### [A] Authentification

| ID | Détection | Niveau |
|---|---|---|
| A-01 | Sessions sans logout correspondant | MODÉRÉ |
| A-02 | Activité tracée après logout (session non invalidée côté serveur) | ÉLEVÉ |
| A-03 | Échecs d'authentification (`401`, `403`, `login failed`, `access denied`…) | MODÉRÉ / ÉLEVÉ |

### [P] Privilèges

| ID | Détection | Niveau |
|---|---|---|
| P-01 | Commandes administratives (`configure`, `commit`, `sudo`, `chmod`, `reset password`, `addKeystore`…) | ÉLEVÉ |
| P-02 | Traçabilité des actions : présence de `url.path`, `event.action`, verbes HTTP | INFO / CRITIQUE |
| P-03 | Activité entre 22h et 5h avec login ou commande sensible | MODÉRÉ |

### [D] Données personnelles et métier

| ID | Détection | Niveau |
|---|---|---|
| D-01 | Numéros MSISDN sénégalais (`221[37]…`, `221[77]…`) | CRITIQUE |
| D-01b | Adresses email en clair | ÉLEVÉ |
| D-02 | Noms de personnes par label contextuel (`nom=`, `fullname=`, `client_name=`…) | ÉLEVÉ |
| D-03 | Champs PII dans structures JSON (`userId`, `email`, `client.ip`, `sessionId`…) | ÉLEVÉ |
| D-04 | Données financières Mobile Money (`solde`, `FCFA`, `Orange Money`, `balance`…) | ÉLEVÉ |
| D-05 | Numéros de carte bancaire PAN — vérification Luhn + filtre contextuel configurable | CRITIQUE |
| D-07 | Codes OTP / PIN en clair (`otp=`, `pin=`, `totp=` + valeur numérique) | CRITIQUE |
| D-08 | Données d'identité par label (`cni=`, `passport=`, `dob=`, `date_naissance=`…) | CRITIQUE |
| D-10 | Identifiants télécom : IMEI (15 chiffres), ICCID (`89…`), IMSI (`608…`), numéros de contrat | ÉLEVÉ |

### [C] Conformité / Complétude

29 exigences vérifiées couvrant :

- Événements de sécurité généraux (activités utilisateur, exceptions, défaillances, actions CRUD)
- Authentification (réussites, échecs, mécanismes, élévations de privilèges)
- Gestion des comptes (ajout/suppression de comptes, droits, données d'authentification)
- Accès aux ressources (lecture, écriture, tentatives refusées)
- Modifications de stratégies de sécurité
- Activité des processus et du système (démarrages, arrêts, dysfonctionnements, modules)
- Format et qualité des logs (horodatage, identité utilisateur, IP source, valeurs avant/après)
- Masquage des données sensibles (contrôle croisé avec S-01)

Chaque exigence est évaluée **CONFORME**, **GAP CRITIQUE** ou **GAP MODÉRÉ**, avec taux de conformité calculé par fichier.

---

## Rapport HTML

Le rapport unique contient quatre onglets navigables :

| Onglet | Contenu |
|---|---|
| **Findings sécurité** | Findings filtrables par criticité et catégorie, avec extraits de logs et commandes `grep` copy-paste |
| **Synthèse sécurité** | Tableau consolidé de tous les findings triés par criticité |
| **Conformité / Complétude** | Tableau par fichier avec barre de progression et statut exigence par exigence |
| **Récap gaps** | Liste consolidée des exigences non satisfaites |

Le header affiche simultanément le **niveau de risque sécurité** et le **statut de conformité** (NON CONFORME / PARTIELLEMENT CONFORME / CONFORME).

---

## Configuration des patterns (patterns/patterns.yaml)

Tous les patterns de détection sont dans `patterns/patterns.yaml`. Aucune modification du code n'est nécessaire pour ajuster la détection.

**Modifier un pattern :**
```yaml
- id: S-01-password
  group: Secrets / Credentials
  pattern: '(?i)\bpasswd?\s*[=:]\s*\S{3,}'
  description: Mot de passe en clair
  level: CRITIQUE
```

**Désactiver un pattern sans le supprimer :**
```yaml
- id: S-01-x509_cert
  enabled: false
  ...
```

**Ajouter un terme à une liste d'exclusion (faux positifs) :**
```yaml
# Faux positifs D-05 (PAN carte bancaire)
pan_exclusion_terms:
  - OLS
  - regression
  - MON_CONTEXTE_TECHNIQUE   # ajouter ici

# Faux positifs D-10 (identifiants télécom)
telecom_exclusion_terms:
  - FloodAnalyzer
  - RequestCapture
  - MON_COMPOSANT             # ajouter ici
```

**Ajouter une clé PII pour la détection JSON (D-03) :**
```yaml
pii_json_keys:
  - userid
  - ma_nouvelle_cle
```

> **Note sur D-02 (noms de personnes)** — Ce pattern utilise une approche par label contextuel
> (`nom=`, `fullname=`, `client_name=`…) et est défini directement dans le code pour des raisons
> de compatibilité regex (word boundaries et accents ne survivent pas au parsing YAML).
> Pour l'étendre, modifier `FULLNAME_RE` dans `log_analyzer.py`.

---

## Configuration des exigences de conformité (patterns/compliance.yaml)

```yaml
- id: C-08
  group: Authentification
  title: Réussites d'authentification
  level_if_absent: CRITIQUE    # CRITIQUE ou MODERE
  pattern: '\b(login|auth.*success|authenticated)\b'
  gap_description: |
    Aucune réussite d'authentification détectée.
    Exigence CRITIQUE : chaque connexion réussie doit être journalisée
    avec l'identité, l'horodatage et l'IP source.
```

**Désactiver une exigence :**
```yaml
- id: C-21
  enabled: false
  ...
```

---

## Niveaux de criticité

| Niveau | Description |
|---|---|
| CRITIQUE | Exposition directe de données sensibles ou absence d'un contrôle fondamental |
| ÉLEVÉ | Données personnelles exposées, stack traces, commandes privilégiées |
| MODÉRÉ | IPs internes, SQL verbose, accès hors horaires, gaps de conformité non bloquants |
| FAIBLE | Informations contextuelles à vérifier manuellement |
| INFO | Données de contexte (plage temporelle, volume, empreinte SHA-256) |

---

## Limites connues

- **D-02 (noms)** — détection par label contextuel (`nom=`, `fullname=`, `client_name=`…) avec séparateur strict (`=`, `:`, `"`). Ne détecte que les noms précédés d'un champ identifié — zéro faux positif sur les termes techniques, SQL ou composants applicatifs. Pour ajouter un nouveau label, modifier `FULLNAME_RE` dans `log_analyzer.py`.
- **D-05 (PAN)** — vérification Luhn appliquée. Des valeurs numériques statistiques (modèles OLS, coefficients anti-DDoS) peuvent passer le test par coïncidence. Filtre contextuel via `pan_exclusion_terms`.
- **D-08 (identité)** — détection par label uniquement (`cni=`, `dob=`…). Les valeurs sans label contextuel ne sont pas détectées.
- **D-10 (IMEI)** — filtre contextuel via `telecom_exclusion_terms` pour exclure les faux positifs liés aux modèles statistiques réseau.
- **A-01 / A-02** — supposent que login et logout sont dans le même fichier. Un logging fragmenté génère des sessions sans logout apparentes.
- **P-02 GET-only** — le finding CRITIQUE indique que les actions d'écriture ne sont pas tracées dans les logs analysés. Ce n'est pas nécessairement un problème si le composant est en lecture seule ou si les logs de modification sont dans un autre fichier non inclus dans l'analyse.

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

---

## Licence

MIT
