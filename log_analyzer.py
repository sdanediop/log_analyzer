#!/usr/bin/env python3
"""
log_analyzer.py  v3.0
Audit de sécurité — fichiers logs (texte, JSON, CSV)

Les patterns de détection et les exigences de conformité sont définis
dans des fichiers YAML séparés, dans le même répertoire que ce script :
    patterns.yaml   — patterns regex sécurité, PII, auth, privilèges
    compliance.yaml — exigences de conformité C-01 à C-29

Usage:
    python3 log_analyzer.py fichier.log
    python3 log_analyzer.py *.log *.json *.csv --output rapport.html
    python3 log_analyzer.py --dir /chemin/logs --output rapport.html

Formats supportés:
    - Texte brut / semi-structuré (Spring Boot, syslog, custom)
    - JSON (tableau ou objet avec clé data[])
    - CSV (délimiteur auto-détecté)

Dépendance : pyyaml  (pip install pyyaml)
"""

import re
import sys
import csv
import json
import argparse
import hashlib
import io
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter

try:
    import yaml
except ImportError:
    print("Erreur : pyyaml requis — pip install pyyaml")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────
# CHARGEMENT DES PATTERNS YAML
# ─────────────────────────────────────────────────────────────────

_SCRIPT_DIR = Path(__file__).parent

def _load_yaml(filename: str) -> dict:
    path = _SCRIPT_DIR / filename
    if not path.exists():
        print(f"Erreur : fichier de configuration introuvable : {path}")
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)

def _compile(pattern: str, flags_str: str = "IGNORECASE") -> re.Pattern:
    """Compile une regex depuis une chaîne avec flags optionnels."""
    flags = 0
    if flags_str:
        for flag in flags_str.split("|"):
            flag = flag.strip()
            if flag == "IGNORECASE":
                flags |= re.IGNORECASE
            elif flag == "MULTILINE":
                flags |= re.MULTILINE
    return re.compile(pattern, flags)

def _load_patterns():
    """Charge patterns.yaml et retourne les structures utilisées par run_checks."""
    data = _load_yaml("patterns.yaml")

    # Patterns de sécurité S-01 : liste de (id, group, regex)
    # Exclusions : patterns qui ont leur propre check dédié dans run_checks
    S01_EXCLUSIONS = {"S-02-internal_ip", "S-03-stack_trace", "S-04-sql_query", "S-05-debug_level"}
    sensitive_patterns = []
    for p in data.get("security_patterns", []):
        if not p.get("enabled", True):
            continue
        if p["id"] in S01_EXCLUSIONS:
            continue
        sensitive_patterns.append((
            p["id"],
            p.get("group", ""),
            _compile(p["pattern"], p.get("flags", "IGNORECASE"))
        ))

    # Patterns par identifiant pour accès direct
    by_id = {}
    for section in ["security_patterns", "auth_patterns", "privilege_patterns",
                    "pii_patterns", "forensic_patterns"]:
        for p in data.get(section, []):
            if not p.get("enabled", True):
                continue
            by_id[p["id"]] = _compile(p["pattern"], p.get("flags", "IGNORECASE"))

    pii_json_keys       = set(k.lower() for k in data.get("pii_json_keys", []))
    sensitive_json_keys = set(k.lower() for k in data.get("sensitive_json_keys", []))

    def _build_exclusion_re(terms):
        if not terms:
            return None
        return re.compile("|".join(re.escape(t) for t in terms), re.IGNORECASE)

    pan_exclusion_re      = _build_exclusion_re(data.get("pan_exclusion_terms", []))
    fullname_exclusion_re = _build_exclusion_re(data.get("fullname_exclusion_terms", []))
    telecom_exclusion_re  = _build_exclusion_re(data.get("telecom_exclusion_terms", []))

    return (sensitive_patterns, by_id, pii_json_keys, sensitive_json_keys,
            pan_exclusion_re, fullname_exclusion_re, telecom_exclusion_re)

def _load_compliance():
    """Charge compliance.yaml et retourne COMPLIANCE_CHECKS."""
    data = _load_yaml("compliance.yaml")
    checks = []
    for c in data.get("compliance_checks", []):
        if not c.get("enabled", True):
            continue
        pattern = _compile(c["pattern"]) if c.get("pattern") else None
        checks.append((
            c["id"],
            c["title"],
            c["level_if_absent"],
            pattern,
            c.get("gap_description", "").strip()
        ))
    return checks

# Chargement au démarrage du module
(SENSITIVE_PATTERNS,
 _PAT,
 PII_JSON_KEYS,
 SENSITIVE_JSON_KEYS,
 PAN_EXCLUSION_RE,
 FULLNAME_EXCLUSION_RE,
 TELECOM_EXCLUSION_RE) = _load_patterns()

COMPLIANCE_CHECKS = _load_compliance()

# Constantes internes (non exposées dans les YAML — logique pure)
ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mGKHF]|\x1b\([AB]|\x1b=[0-9]*')

# Raccourcis vers les patterns fréquemment utilisés
INTERNAL_IP_RE   = _PAT.get("S-02-internal_ip",
    re.compile(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'))
STACK_TRACE_OPEN_RE = _PAT.get("S-03-stack_trace",
    re.compile(r'(Exception|NullPointerException|Traceback)', re.IGNORECASE))
STACK_FRAME_RE   = re.compile(r'^\s+at [\w.$]+\([\w.]+(?::\d+)?\)')
SQL_RE           = _PAT.get("S-04-sql_query",
    re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE)\b', re.IGNORECASE))
LOGIN_RE         = _PAT.get("A-login",
    re.compile(r'\b(login|authentification)\b', re.IGNORECASE))
LOGOUT_RE        = _PAT.get("A-logout",
    re.compile(r'\b(logout|déconnexion)\b', re.IGNORECASE))
USER_RE          = _PAT.get("A-user",
    re.compile(r'user[\w._-]*[=:"\'\s]+([A-Za-z0-9._@\-]{3,60})', re.IGNORECASE))
WRITE_ACTIONS_RE = _PAT.get("P-02-write_action",
    re.compile(r'\b(PUT|POST|DELETE|PATCH)\b', re.IGNORECASE))
ACTION_TRACE_RE  = _PAT.get("P-02-action_trace",
    re.compile(r'url\.path|event\.action', re.IGNORECASE))
PRIVILEGED_RE    = _PAT.get("P-01-privileged_cmd",
    re.compile(r'\b(sudo|configure|commit)\b', re.IGNORECASE))
NIGHT_TS_RE      = _PAT.get("P-03-night_activity",
    re.compile(r'[T\s](0[0-5]|2[2-3]):\d{2}:\d{2}'))
MSISDN_RE        = _PAT.get("D-01-msisdn",
    re.compile(r'\b221[37]\d{7,8}\b'))
EMAIL_RE         = _PAT.get("D-01b-email",
    re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,10}\b'))
FULLNAME_RE      = re.compile(r'\b([A-Z]{2,}(?:\s+[A-Z]{2,}){1,3})\b')
OTP_PIN_RE       = _PAT.get("D-07-otp_pin",
    re.compile(r'(?i)\b(otp|pin)\s*[=:]\s*\d{4,8}\b'))
IDENTITY_LABEL_RE = _PAT.get("D-08-identity_label",
    re.compile(r'(?i)\b(cni|passport)\s*[=:]\s*[A-Z0-9]{5,20}'))
DOB_LABEL_RE     = _PAT.get("D-08-dob_label",
    re.compile(r'(?i)\b(dob|date.naissance)\s*[=:]\s*\d{2}.\d{2}.\d{4}'))
CONTRACT_RE      = _PAT.get("D-10-contract",
    re.compile(r'(?i)\b(contract|abonnement)\s*[=:]\s*[A-Z0-9]{5,25}'))
IMEI_RE          = _PAT.get("D-10-imei",   re.compile(r'\b\d{15}\b'))
ICCID_RE         = _PAT.get("D-10-iccid",  re.compile(r'\b89\d{17,18}\b'))
IMSI_RE          = _PAT.get("D-10-imsi",   re.compile(r'\b608\d{12}\b'))
PAN_RE           = _PAT.get("D-05-pan",    re.compile(r'\b(?:\d[ \-]?){13,19}\d\b'))

# Timestamps
TS_PATTERNS = [
    _PAT.get("F-01-timestamp_iso",    re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}')),
    _PAT.get("F-01-timestamp_clf",    re.compile(r'\d{2}/[A-Za-z]{3}/\d{4}[: ]\d{2}:\d{2}:\d{2}')),
    _PAT.get("F-01-timestamp_syslog", re.compile(r'[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}')),
    _PAT.get("F-01-timestamp_custom", re.compile(r'\d{2}/\d{2}/\d{4}[; ]\d{2}:\d{2}:\d{2}')),
]


# ─────────────────────────────────────────────────────────────────
# MODELE DE DONNEES
# ─────────────────────────────────────────────────────────────────

class Finding:
    LEVELS = {"CRITIQUE": 0, "ELEVE": 1, "MODERE": 2, "FAIBLE": 3, "INFO": 4, "OK": 5}
    COLORS = {
        "CRITIQUE": "#e53e3e", "ELEVE": "#dd6b20", "MODERE": "#d69e2e",
        "FAIBLE": "#3182ce", "INFO": "#718096", "OK": "#38a169"
    }
    LABELS = {
        "CRITIQUE": "CRITIQUE", "ELEVE": "ELEVE", "MODERE": "MODERE",
        "FAIBLE": "FAIBLE", "INFO": "INFO", "OK": "OK"
    }
    CAT_LABELS = {
        "S": "Sécurité", "F": "Forensique", "A": "Auth",
        "P": "Privilèges", "D": "Données", "C": "Conformité"
    }

    def __init__(self, check_id, category, title, level, description, excerpt, grep_hint=""):
        self.check_id    = check_id
        self.category    = category
        self.title       = title
        self.level       = level
        self.description = description
        self.excerpt     = excerpt
        self.grep_hint   = grep_hint

    def sort_key(self):
        return (self.LEVELS.get(self.level, 9), self.check_id)

    @property
    def color(self):
        return self.COLORS.get(self.level, "#718096")

    @property
    def label(self):
        return self.LABELS.get(self.level, self.level)

    @property
    def cat_label(self):
        return self.CAT_LABELS.get(self.category, self.category)


# ─────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────

def strip_ansi(text):
    return ANSI_RE.sub('', text)

def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "N/A"

def extract_timestamp(line):
    for pat in TS_PATTERNS:
        m = pat.search(line)
        if m:
            return m.group(0)
    return None

def extract_user(line):
    m = USER_RE.search(line)
    if m:
        val = m.group(1).strip('"\'')
        if val.lower() not in ('null', 'none', 'unknown', 'true', 'false', '-', ''):
            return val
    return None

def fmt_excerpt(hits, max_n=4):
    out = []
    for lineno, line in hits[:max_n]:
        clean = strip_ansi(str(line)).strip()[:180]
        if len(strip_ansi(str(line)).strip()) > 180:
            clean += "..."
        prefix = f"L{lineno:>6}: " if isinstance(lineno, int) and lineno > 0 else "        "
        out.append(f"{prefix}{clean}")
    if len(hits) > max_n:
        out.append(f"         ... et {len(hits) - max_n} occurrence(s) supplémentaire(s)")
    return out


# ─────────────────────────────────────────────────────────────────
# DETECTION FORMAT ET LECTURE
# ─────────────────────────────────────────────────────────────────

def detect_format(path, raw):
    ext = path.suffix.lower()
    if ext == '.json':
        return 'json'
    if ext == '.csv':
        return 'csv'
    if ext in ('.log', '.txt'):
        return 'text'
    stripped = raw.lstrip()
    if stripped.startswith(('{', '[')):
        try:
            json.loads(raw)
            return 'json'
        except Exception:
            pass
    first = raw.split('\n')[0] if raw else ''
    for sep in [';', ',', '\t', '|']:
        if first.count(sep) >= 2:
            return 'csv'
    return 'text'

def read_file(path):
    try:
        raw = path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return None, [], ""
    fmt = detect_format(path, raw)
    if fmt == 'json':
        lines = _flatten_json(raw)
    elif fmt == 'csv':
        lines = _flatten_csv(raw)
    else:
        lines = _merge_multiline(raw)
    return fmt, lines, raw

def _merge_multiline(raw):
    result = []
    buf_lineno = None
    buf_lines  = []
    for i, line in enumerate(raw.splitlines(), 1):
        clean = strip_ansi(line)
        if STACK_FRAME_RE.match(clean):
            if buf_lines:
                buf_lines.append(clean.strip())
            continue
        if buf_lines:
            result.append((buf_lineno, ' | '.join(buf_lines)))
            buf_lines = []
        buf_lineno = i
        buf_lines  = [clean]
    if buf_lines:
        result.append((buf_lineno, ' | '.join(buf_lines)))
    return result

def _flatten_json(raw):
    result = []
    try:
        data = json.loads(raw)
    except Exception:
        return [(i + 1, strip_ansi(l)) for i, l in enumerate(raw.splitlines())]
    if isinstance(data, dict):
        candidates = data.get('data', [data])
        if isinstance(candidates, dict):
            candidates = [candidates]
    elif isinstance(data, list):
        candidates = data
    else:
        candidates = [data]
    for idx, record in enumerate(candidates):
        _json_walk(record, result, record_idx=idx + 1)
    return result

def _json_walk(node, result, path="", record_idx=0):
    if isinstance(node, dict):
        for k, v in node.items():
            _json_walk(v, result, path=f"{path}.{k}" if path else k, record_idx=record_idx)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _json_walk(v, result, path=f"{path}[{i}]", record_idx=record_idx)
    elif node is not None:
        val_str = str(node)
        if val_str.strip():
            result.append((record_idx, f"{path}={val_str}"))

def _flatten_csv(raw):
    result = []
    first_line = raw.split('\n')[0] if raw else ''
    sep = ';'
    for s in [';', ',', '\t', '|']:
        if first_line.count(s) >= 2:
            sep = s
            break
    for i, line in enumerate(raw.splitlines(), 1):
        result.append((i, strip_ansi(line)))
    return result


# ─────────────────────────────────────────────────────────────────
# CHECKS
# ─────────────────────────────────────────────────────────────────

def _luhn_ok(n: str) -> bool:
    """Vérifie qu'un numéro de carte passe l'algorithme de Luhn."""
    digits = [int(c) for c in str(n)]
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def run_checks(path, fmt, lines):
    findings = []
    total = len(lines)

    def grep(pattern):
        rx = pattern if hasattr(pattern, 'search') else re.compile(pattern, re.IGNORECASE)
        return [(ln, t) for ln, t in lines if rx.search(t)]

    # ── [S] SECURITE ────────────────────────────────────────────

    # S-01 Secrets / credentials
    secret_hits = []
    seen = set()
    for pat_id, pat_group, pat_re in SENSITIVE_PATTERNS:
        for ln, text in lines:
            if pat_re.search(text) and ln not in seen:
                secret_hits.append((ln, f"[{pat_id}] {text}"))
                seen.add(ln)

    if secret_hits:
        findings.append(Finding(
            "S-01", "S",
            f"Secrets / credentials exposes ({len(secret_hits)} occurrence(s))",
            "CRITIQUE",
            f"{len(secret_hits)} occurrence(s) détectée(s) : mots de passe, tokens, clés API, "
            "JWT, URLs JDBC, clés hexadecimales.\n"
            "Chaque occurrence doit être analysee et corrigee avant mise en production.",
            fmt_excerpt(secret_hits),
            f"grep -iP '(passwd?|secret|api.key|token|bearer|jdbc:|private.key)' {path.name}"
        ))
    else:
        findings.append(Finding("S-01", "S", "Aucun secret ou credential détecté", "OK", "", []))

    # S-02 IPs internes
    ip_counter = Counter()
    for _, text in lines:
        for ip in INTERNAL_IP_RE.findall(text):
            ip_counter[ip] += 1
    if ip_counter:
        ex = [(0, f"{ip}  --  {n} occurrence(s)") for ip, n in ip_counter.most_common(5)]
        findings.append(Finding(
            "S-02", "S",
            f"IPs internes exposees ({len(ip_counter)} adresses distinctes)",
            "MODERE",
            "Des adresses RFC 1918 apparaissent dans les logs. "
            "Elles documentent partiellement la topologie réseau interne.",
            fmt_excerpt(ex),
            f"grep -oE '10\\.[0-9.]+|192\\.168\\.[0-9.]+|172\\.(1[6-9]|2[0-9]|3[01])\\.[0-9.]+' "
            f"{path.name} | sort | uniq -c | sort -rn"
        ))

    # S-03 Stack traces (agregees)
    st_hits = []
    for ln, text in lines:
        if STACK_TRACE_OPEN_RE.search(text):
            st_hits.append((ln, text))
        elif '|' in text and STACK_FRAME_RE.search(text.split('|')[-1]):
            st_hits.append((ln, text))
    if st_hits:
        findings.append(Finding(
            "S-03", "S",
            f"Stack tracés présentes ({len(st_hits)} bloc(s))",
            "ELEVE",
            "Des tracés d'exception revelent la structure interne de l'application : "
            "noms de classes, chemins, numéros de lignes. "
            "A désactiver ou filtrer en production.",
            fmt_excerpt(st_hits),
            f"grep -nP '(Exception|Traceback|NullPointer|StackTrace)' {path.name}"
        ))
    else:
        findings.append(Finding("S-03", "S", "Aucune stack trace détectée", "OK", "", []))

    # S-04 Requetes SQL
    sql_hits = grep(SQL_RE)
    if sql_hits:
        findings.append(Finding(
            "S-04", "S",
            f"Requêtes SQL completes dans les logs ({len(sql_hits)} occurrence(s))",
            "MODERE",
            "Des requêtes SQL exposent le schema de la base de données. "
            "Le mode de log SQL verbose doit être desactive en production.",
            fmt_excerpt(sql_hits),
            f"grep -inP '\\b(SELECT|INSERT|UPDATE|DELETE|DROP)\\b' {path.name}"
        ))

    # S-05 Verbosité DEBUG
    debug_hits = grep(re.compile(r'\b(DEBUG|TRACE)\b'))
    if total > 0 and len(debug_hits) / total > 0.05:
        pct = round(100 * len(debug_hits) / total, 1)
        findings.append(Finding(
            "S-05", "S",
            f"Niveau DEBUG actif : {pct}% des entrées",
            "MODERE",
            f"{len(debug_hits)} entrées DEBUG/TRACE sur {total}. "
            "Un log level DEBUG en production expose des details d'implementation.",
            fmt_excerpt(debug_hits[:3]),
            f"grep -c '\\bDEBUG\\b' {path.name}"
        ))

    # ── [F] FORENSIQUE ──────────────────────────────────────────

    # F-01 Plage temporelle
    timestamps = [extract_timestamp(t) for _, t in lines if extract_timestamp(t)]
    if timestamps:
        first_ts, last_ts = timestamps[0], timestamps[-1]
        duration_str = "inconnue"
        for dfmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                     "%d/%b/%Y:%H:%M:%S", "%d/%m/%Y %H:%M:%S"]:
            try:
                t0 = datetime.strptime(first_ts[:19], dfmt)
                t1 = datetime.strptime(last_ts[:19],  dfmt)
                duration_str = f"{abs((t1 - t0).days)} jour(s)"
                break
            except Exception:
                continue
        findings.append(Finding(
            "F-01", "F",
            f"Plage temporelle : {duration_str}",
            "INFO",
            f"Premier événement : {first_ts}\nDernier événement  : {last_ts}\n"
            f"Duree de l'extraction : {duration_str}",
            [(0, f"Debut : {first_ts}"), (0, f"Fin   : {last_ts}")], ""
        ))
    else:
        findings.append(Finding(
            "F-01", "F",
            "Aucun horodatage reconnu dans les logs",
            "CRITIQUE",
            "Sans timestamp exploitable, la reconstitution d'une chronologie est impossible. "
            "Ce fichier ne peut pas servir de preuve forensique.",
            [], ""
        ))

    # F-02 Couverture des horodatages
    ts_count = sum(1 for _, t in lines if extract_timestamp(t))
    if total > 0:
        pct = round(100 * ts_count / total, 1)
        level = "OK" if pct > 80 else ("MODERE" if pct > 40 else "ELEVE")
        findings.append(Finding(
            "F-02", "F",
            f"Couverture des horodatages : {pct}% des entrées",
            level,
            f"{ts_count} entrées sur {total} contiennent un timestamp reconnu.",
            [], ""
        ))

    # F-03 Hash integrite
    sha = sha256_file(path)
    size_kb = round(path.stat().st_size / 1024, 1) if path.exists() else 0
    findings.append(Finding(
        "F-03", "F",
        "Empreinte d'intégrité du fichier",
        "INFO",
        f"SHA-256 : {sha}\nTaille  : {size_kb} Ko -- {total} entrées analysees\n\n"
        "Conserver cette empreinte pour attester l'intégrité du fichier lors d'une analyse.",
        [(0, f"sha256({path.name}) = {sha[:48]}...")],
        f"sha256sum {path.name}"
    ))

    # ── [A] AUTHENTIFICATION ─────────────────────────────────────

    # A-01 Sessions sans logout
    logins  = defaultdict(list)
    logouts = defaultdict(list)
    for ln, text in lines:
        user = extract_user(text)
        if not user:
            continue
        if LOGIN_RE.search(text):
            logins[user].append(ln)
        if LOGOUT_RE.search(text):
            logouts[user].append(ln)

    orphans = {u for u in logins if u not in logouts}
    if orphans:
        ex = [(logins[u][0], f"user={u} -- Login L{logins[u][0]}, aucun Logout trouve")
              for u in sorted(orphans)[:5]]
        findings.append(Finding(
            "A-01", "A",
            f"Sessions sans logout : {len(orphans)} utilisateur(s)",
            "MODERE",
            "Des utilisateurs présentent un Login sans Logout correspondant. "
            "Peut indiquer des sessions non invalidees ou un logging fragmente.",
            fmt_excerpt(ex),
            f"grep -iP '(login|logout|session)' {path.name}"
        ))
    elif logins:
        findings.append(Finding("A-01", "A", "Toutes les sessions ont un logout correspondant", "OK", "", []))
    else:
        findings.append(Finding(
            "A-01", "A",
            "Aucun événement d'authentification détecté",
            "FAIBLE",
            "Aucun pattern login/logout reconnu. "
            "Les événements d'authentification sont peut-être dans un fichier dédié.",
            [],
            f"grep -iP '(login|logout|auth|session)' {path.name}"
        ))

    # A-02 Activite post-logout
    post_logout = []
    for user, lo_lines in logouts.items():
        last_lo = max(lo_lines)
        for ln, text in lines:
            if ln > last_lo and re.search(re.escape(user), text, re.IGNORECASE):
                if not LOGOUT_RE.search(text) and not LOGIN_RE.search(text):
                    post_logout.append((user, last_lo, ln, text))
                    break
    if post_logout:
        ex = [(ln, f"user={u} -- logout L{lo}, activité L{ln}")
              for u, lo, ln, _ in post_logout[:4]]
        findings.append(Finding(
            "A-02", "A",
            f"Activité après logout : {len(post_logout)} cas",
            "ELEVE",
            "Des actions sont tracées après la deconnexion d'un utilisateur. "
            "Causes possibles : session non invalidee cote serveur, compte partage.",
            fmt_excerpt(ex),
            f"grep -iP '(logout|session.end)' {path.name}"
        ))

    # A-03 Echecs d'authentification
    fail_hits = grep(re.compile(
        r'(auth.{0,20}fail|login.{0,20}fail|invalid.{0,20}password'
        r'|wrong.{0,20}password|authentication.{0,20}error'
        r'|\b(401|403)\b|access.denied|permission.denied'
        r'|challengePassword|Invalid Authentication)',
        re.IGNORECASE
    ))
    if fail_hits:
        fail_ctx = Counter()
        for _, t in fail_hits:
            u = extract_user(t)
            if u:
                fail_ctx[u] += 1
            for ip in INTERNAL_IP_RE.findall(t):
                fail_ctx[ip] += 1
        level = "ELEVE" if len(fail_hits) > 10 else "MODERE"
        findings.append(Finding(
            "A-03", "A",
            f"Échecs d'authentification : {len(fail_hits)} événement(s)",
            level,
            f"Sources les plus actives : {fail_ctx.most_common(3)}\n"
            "A corréler avec des tentatives de brute force ou des configurations erronees.",
            fmt_excerpt(fail_hits),
            f"grep -iP '(auth.*fail|login.*fail|401|403|accèss.denied)' {path.name}"
        ))
    else:
        findings.append(Finding("A-03", "A", "Aucun échec d'authentification détecté", "OK", "", []))

    # ── [P] PRIVILEGES ───────────────────────────────────────────

    # P-01 Commandes privilegiees
    priv_hits = [
        (ln, t) for ln, t in grep(PRIVILEGED_RE)
        if not re.search(r'(command not found|invalid command|no such|Unknown)', t, re.IGNORECASE)
    ]
    if priv_hits:
        cmd_counts = Counter()
        for _, t in priv_hits:
            m = PRIVILEGED_RE.search(t)
            if m:
                cmd_counts[m.group(0).lower().split()[0]] += 1
        findings.append(Finding(
            "P-01", "P",
            f"Commandes privilegiees tracées : {len(priv_hits)} occurrence(s)",
            "ELEVE",
            f"Commandes sensibles : {dict(cmd_counts.most_common(5))}\n"
            "Vérifier que chaque execution est associee a un opérateur identifié "
            "et a un changement approuve.",
            fmt_excerpt(priv_hits),
            f"grep -iP '(configure|commit|debug|dump|reset.password|sudo|addKeystore)' {path.name}"
        ))
    else:
        findings.append(Finding("P-01", "P", "Aucune commande privilegiee détectée", "OK", "", []))

    # P-02 Traçabilité des actions (URL / event.action / verbe HTTP)
    action_trace_hits = grep(ACTION_TRACE_RE)
    write_hits        = grep(WRITE_ACTIONS_RE)
    read_hits         = grep(re.compile(
        r'\bGET\b|http\.request\.method\s*[=:]\s*["\']?GET["\']?', re.IGNORECASE
    ))

    if action_trace_hits:
        write_count = len(write_hits)
        findings.append(Finding(
            "P-02", "P",
            f"Actions applicatives tracées : {len(action_trace_hits)} événement(s) avec URL/action",
            "OK",
            f"Les appels sont tracés avec leur URL ou libellé d'action ({len(action_trace_hits)} occurrences).\n"
            f"Actions d'écriture détectées en complément : {write_count}.",
            fmt_excerpt(action_trace_hits[:3]), ""
        ))
    elif read_hits and not write_hits:
        findings.append(Finding(
            "P-02", "P",
            "Seules les lectures (GET) sont tracées — aucune action d'écriture",
            "CRITIQUE",
            f"{len(read_hits)} GET détectés, 0 PUT/POST/DELETE/PATCH.\n"
            "Sans trace des modifications, la reconstitution d'une séquence d'actions "
            "est impossible lors d'un incident.",
            fmt_excerpt(read_hits[:3]),
            f"grep -iP '(PUT|POST|DELETE|PATCH|url\\.path|event\\.action)' {path.name}"
        ))
    elif write_hits:
        wt = Counter()
        for _, t in write_hits:
            m = WRITE_ACTIONS_RE.search(t)
            if m:
                val = next((g for g in m.groups() if g), '?')
                wt[val.upper()] += 1
        findings.append(Finding(
            "P-02", "P",
            f"Actions d'écriture tracées : {dict(wt.most_common())}",
            "OK",
            "Les opérations de modification sont présentes dans les logs.",
            fmt_excerpt(write_hits[:2]), ""
        ))
    else:
        findings.append(Finding(
            "P-02", "P",
            "Aucune action tracée (pas d'URL, d'event.action ni de verbe HTTP)",
            "FAIBLE",
            "Le fichier ne contient pas de traces d'appels HTTP, d'URL ou d'actions métier identifiables.",
            [], f"grep -iP '(url\\.path|event\\.action|GET|POST|PUT|DELETE)' {path.name}"
        ))

    # P-03 Acces hors horaires
    off_hours = []
    for ln, text in lines:
        if NIGHT_TS_RE.search(text):
            user = extract_user(text)
            if user and (LOGIN_RE.search(text) or PRIVILEGED_RE.search(text)):
                off_hours.append((ln, text))
    if off_hours:
        findings.append(Finding(
            "P-03", "P",
            f"Activité hors horaires (00h-05h / 22h-23h) : {len(off_hours)} événement(s)",
            "MODERE",
            "Connexions ou commandes sensibles détectées la nuit. "
            "A corréler avec les astreintes planifiees.",
            fmt_excerpt(off_hours),
            f"grep -P 'T(0[0-5]|2[2-3]):\\d{{2}}:\\d{{2}}' {path.name}"
        ))

    # ── [D] DONNEES PERSONNELLES / METIER ────────────────────────

    # D-01 MSISDN senegalais
    msisdn_hits = grep(MSISDN_RE)
    if msisdn_hits:
        msisdns = set()
        for _, t in msisdn_hits:
            for m in MSISDN_RE.finditer(t):
                msisdns.add(m.group(0))
        findings.append(Finding(
            "D-01", "D",
            f"Numéros MSISDN en clair : {len(msisdns)} numéro(s) distinct(s)",
            "CRITIQUE",
            f"Des numéros de téléphone senegalais (221...) sont tracés en clair.\n"
            f"Exemples : {', '.join(sorted(msisdns)[:5])}\n\n"
            "Données personnelles directement identifiantes (loi 2008-12). "
            "Masquér ou pseudonymiser avant mise en production.",
            fmt_excerpt(msisdn_hits),
            f"grep -oP '221[37]\\d{{7,8}}' {path.name} | sort | uniq -c | sort -rn"
        ))

    # D-01b Adresses email en clair
    email_hits = grep(EMAIL_RE)
    # Filtrer les faux positifs évidents : extensions de fichiers, URLs techniques
    email_hits = [
        (ln, t) for ln, t in email_hits
        if not re.search(
            r'@(example|test|localhost|dummy|noreply|no-reply|domain|company)\.'
            r'|\.(?:java|log|xml|yml|json|png|jpg|css|js|html|py|txt|sh|gz|zip)\b',
            t, re.IGNORECASE
        )
    ]
    if email_hits:
        emails = set()
        for _, t in email_hits:
            for m in EMAIL_RE.finditer(t):
                val = m.group(0)
                if not re.search(r'@(example|test|localhost|dummy|domain)\.', val, re.IGNORECASE):
                    emails.add(val)
        findings.append(Finding(
            "D-01b", "D",
            f"Adresses email en clair : {len(emails)} adresse(s) distincte(s)",
            "ELEVE",
            f"Des adresses email apparaissent en clair dans les logs.\n"
            f"Exemples : {', '.join(sorted(emails)[:5])}\n\n"
            "Donnée personnelle identifiante (loi 2008-12 / RGPD). "
            "Masquer ou pseudonymiser avant mise en production.",
            fmt_excerpt(email_hits),
            f"grep -oP '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{{2,}}' {path.name} | sort | uniq"
        ))

    # D-02 Noms complets en clair (heuristique)
    name_hits = []
    for ln, text in lines:
        # Exclure les lignes dont le contexte est clairement technique
        if FULLNAME_EXCLUSION_RE and FULLNAME_EXCLUSION_RE.search(text):
            continue
        for m in FULLNAME_RE.finditer(text):
            val = m.group(0)
            if (len(val.split()) >= 2
                    and not re.search(r'\.(java|log|xml|yml|json)$', val, re.IGNORECASE)):
                name_hits.append((ln, f"Nom détecté : {val}  |  {text[:100]}"))
                break
    if name_hits:
        findings.append(Finding(
            "D-02", "D",
            f"Noms de personnes potentiellement exposes : {len(name_hits)} occurrence(s)",
            "ELEVE",
            "Des chaines correspondant a des noms propres complets apparaissent dans les logs. "
            "Vérifier s'il s'agit de données client reelles. "
            "Si oui : pseudonymiser ou remplacer par un identifiant technique.",
            fmt_excerpt(name_hits),
            f"grep -oP '[A-Z]{{2,}}(\\s+[A-Z]{{2,}}){{1,3}}' {path.name}"
        ))

    # D-03 PII dans les champs JSON
    if fmt == 'json':
        pii_hits = []
        for ln, text in lines:
            if '=' in text:
                key_part = text.split('=')[0].split('.')[-1].split('[')[0]
                val_part = text.split('=', 1)[1] if '=' in text else ''
                if key_part.lower() in PII_JSON_KEYS and val_part.strip():
                    pii_hits.append((ln, text))
        if pii_hits:
            keys_found = Counter()
            for _, t in pii_hits:
                k = t.split('=')[0].split('.')[-1].split('[')[0]
                keys_found[k] += 1
            findings.append(Finding(
                "D-03", "D",
                f"Champs PII dans les tracés JSON : {len(pii_hits)} occurrence(s)",
                "ELEVE",
                f"Champs identifiants trouves : {dict(keys_found.most_common(8))}\n\n"
                "Les tracés contiennent des identifiants utilisateur, sessions et données de profil. "
                "Évaluer si ces champs sont nécessaires et, si non, les exclure du logging.",
                fmt_excerpt(pii_hits),
                ""
            ))

    # D-04 Donnees metier / financieres
    biz_hits = grep(re.compile(
        r'(balance|solde|montant|amount|transaction|paiement|payment'
        r'|FCFA|XOF|Orange\s*Money|OM\s+balance)',
        re.IGNORECASE
    ))
    if biz_hits:
        findings.append(Finding(
            "D-04", "D",
            f"Données financières / métier dans les logs : {len(biz_hits)} occurrence(s)",
            "ELEVE",
            "Des informations financières (soldes, transactions, montants) sont tracées. "
            "Ces données sont soumises a des exigences de confidentialite renforcees "
            "dans le contexte Mobile Money.",
            fmt_excerpt(biz_hits),
            f"grep -iP '(balance|solde|montant|amount|FCFA|Orange.Money)' {path.name}"
        ))

    # D-05 PAN carte bancaire (vérification Luhn)
    # Filtre contextuel chargé depuis pan_exclusion_terms dans patterns.yaml
    pan_hits = []
    for ln, text in lines:
        if PAN_EXCLUSION_RE and PAN_EXCLUSION_RE.search(text):
            continue
        for m in PAN_RE.finditer(text):
            raw = re.sub(r'[ \-]', '', m.group(0))
            if 13 <= len(raw) <= 19 and raw.isdigit() and _luhn_ok(raw):
                pan_hits.append((ln, text))
                break
    if pan_hits:
        findings.append(Finding(
            "D-05", "D",
            f"Numéros de carte bancaire (PAN) détectés : {len(pan_hits)} ligne(s)",
            "CRITIQUE",
            "Des numéros de carte bancaire valides (vérification Luhn réussie) apparaissent "
            "dans les logs. Donnée de paiement hautement sensible — exposition interdite "
            "par PCI-DSS (exigence 3.4) et la loi 2008-12.\n"
            "Action immédiate requise : masquage (afficher seulement les 4 derniers chiffres).",
            fmt_excerpt(pan_hits),
            f"grep -oP '\\b(?:\\d[ -]?){{13,19}}\\d\\b' {path.name}"
        ))

    # D-07 OTP / PIN en clair
    otp_hits = grep(OTP_PIN_RE)
    if otp_hits:
        findings.append(Finding(
            "D-07", "D",
            f"Codes OTP / PIN en clair : {len(otp_hits)} occurrence(s)",
            "CRITIQUE",
            "Des codes d'authentification unique (OTP) ou codes PIN apparaissent en clair.\n"
            "Un OTP loggué est exploitable en rejeu si la fenêtre de validité n'est pas expirée. "
            "Ces valeurs ne doivent jamais apparaître dans les logs.",
            fmt_excerpt(otp_hits),
            f"grep -iP '(otp|pin|totp|code.secret|auth.code)\\s*[=:]\\s*\\d{{4,8}}' {path.name}"
        ))

    # D-08 Données identitaires par label (CNI, passeport, date naissance)
    id_hits  = grep(IDENTITY_LABEL_RE)
    dob_hits = grep(DOB_LABEL_RE)
    all_id_hits = id_hits + dob_hits
    if all_id_hits:
        findings.append(Finding(
            "D-08", "D",
            f"Données d'identité (CNI / passeport / date de naissance) : {len(all_id_hits)} occurrence(s)",
            "CRITIQUE",
            "Des données d'identité directement identifiantes sont présentes dans les logs :\n"
            f"  — Identifiants nationaux : {len(id_hits)} occurrence(s)\n"
            f"  — Dates de naissance     : {len(dob_hits)} occurrence(s)\n\n"
            "Catégorie sensible au sens de la loi 2008-12 et du RGPD. "
            "Masquage ou exclusion obligatoire avant mise en production.",
            fmt_excerpt(all_id_hits),
            f"grep -iP '(cni|passport|dob|date.naissance|nin|ssn)\\s*[=:]' {path.name}"
        ))

    # D-10 Identifiants télécom (IMEI, ICCID, IMSI, contrat)
    # Filtre contextuel : exclure les lignes techniques (statistiques, réseau, anti-DDoS)
    def _not_telecom_noise(t):
        return not (TELECOM_EXCLUSION_RE and TELECOM_EXCLUSION_RE.search(t))

    imei_hits = [(ln, t) for ln, t in grep(IMEI_RE)
                 if not re.search(r'\d{16,}', t) and _not_telecom_noise(t)]
    iccid_hits    = [(ln, t) for ln, t in grep(ICCID_RE)    if _not_telecom_noise(t)]
    imsi_hits     = [(ln, t) for ln, t in grep(IMSI_RE)     if _not_telecom_noise(t)]
    contract_hits = [(ln, t) for ln, t in grep(CONTRACT_RE) if _not_telecom_noise(t)]
    telecom_total = len(imei_hits) + len(iccid_hits) + len(imsi_hits) + len(contract_hits)
    if telecom_total > 0:
        ex = fmt_excerpt((contract_hits + imsi_hits + iccid_hits + imei_hits)[:8])
        findings.append(Finding(
            "D-10", "D",
            f"Identifiants télécom en clair : {telecom_total} occurrence(s)",
            "ELEVE",
            f"Identifiants télécom détectés :\n"
            f"  — Numéros de contrat / abonnement : {len(contract_hits)}\n"
            f"  — IMSI (identifiant SIM)           : {len(imsi_hits)}\n"
            f"  — ICCID (numéro de carte SIM)      : {len(iccid_hits)}\n"
            f"  — IMEI (identifiant terminal)      : {len(imei_hits)}\n\n"
            "Ces identifiants permettent de tracer un abonné ou un équipement. "
            "À pseudonymiser avant mise en production.",
            ex,
            f"grep -oP '(89\\d{{17,18}}|608\\d{{12}}|\\b\\d{{15}}\\b)' {path.name}"
        ))

    return findings

def run_compliance_checks(path, fmt, lines, security_findings):
    """
    Verifie la presence de chaque categorie d'événements exigee.
    Retourne une liste de Finding de categorie C.
    security_findings : findings [S] déjà calcules (pour C-29).
    """
    findings = []
    total = len(lines)

    def any_match(pattern):
        if pattern is None:
            return False
        return any(pattern.search(t) for _, t in lines)

    def sample_hits(pattern, max_n=3):
        if pattern is None:
            return []
        hits = [(ln, t) for ln, t in lines if pattern.search(t)]
        return hits[:max_n]

    for check_id, libelle, level_if_absent, pattern, gap_desc in COMPLIANCE_CHECKS:

        # C-29 : check inverse — present si S-01 a trouve des secrets
        if check_id == "C-29":
            s01_hit = any(
                f.check_id == "S-01" and f.level == "CRITIQUE"
                for f in security_findings
            )
            if s01_hit:
                findings.append(Finding(
                    check_id, "C",
                    f"[CONFORME] {libelle} — ECHEC : données sensibles détectées en clair",
                    "CRITIQUE",
                    gap_desc,
                    [],
                    f"grep -iP '(passwd?|token|secret|pin|api.key)' {path.name}"
                ))
            else:
                findings.append(Finding(
                    check_id, "C",
                    f"[CONFORME] {libelle}",
                    "OK",
                    "Aucune donnée sensible en clair détectée (contrôle automatique).",
                    [], ""
                ))
            continue

        if any_match(pattern):
            hits = sample_hits(pattern)
            findings.append(Finding(
                check_id, "C",
                f"[CONFORME] {libelle}",
                "OK",
                f"Événements de type '{libelle}' détectés dans les logs.",
                fmt_excerpt(hits) if hits else [],
                ""
            ))
        else:
            findings.append(Finding(
                check_id, "C",
                f"[GAP] {libelle}",
                level_if_absent,
                gap_desc + (
                    "\n\nNote : l'absence de ces événements dans cette extraction ne signifie pas "
                    "nécessairement qu'ils ne sont jamais générés. À vérifier sur une "
                    "extraction plus large ou en simulant l'événement."
                    if level_if_absent == "MODERE" else
                    "\n\nGap CRITIQUE : cette absence doit être levee avant mise en production. "
                    "Vérifier la configuration du logging et rejouer un scenario de test."
                ),
                [],
                f"grep -iP '{pattern.pattern[:80]}' {path.name}" if pattern else ""
            ))

    return findings

def generate_unified_html(results, compliance_results, output_path):
    """Rapport unique : section Sécurité/Données + section Conformité/Complétude."""
    now = datetime.now().strftime("%d/%m/%Y a %H:%M")

    all_findings = [f for flist in results.values() for f in flist
                    if f.level not in ("OK", "INFO")]
    counts = Counter(f.level for f in all_findings)

    weights = {"CRITIQUE": 10, "ELEVE": 5, "MODERE": 2, "FAIBLE": 1}
    score = sum(weights.get(f.level, 0) for f in all_findings)
    if score == 0:
        risk_label, risk_color = "FAIBLE", "#38a169"
    elif score < 10:
        risk_label, risk_color = "MODERE", "#d69e2e"
    elif score < 30:
        risk_label, risk_color = "ELEVE", "#dd6b20"
    else:
        risk_label, risk_color = "CRITIQUE", "#e53e3e"

    def esc(s):
        return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                      .replace(">", "&gt;").replace('"', "&quot;"))

    def badge(level):
        c = Finding.COLORS.get(level, "#718096")
        lbl = Finding.LABELS.get(level, level)
        return f'<span class="badge" style="background:{c}">{esc(lbl)}</span>'

    def render_finding(f, idx):
        exc_html = ""
        if f.excerpt:
            rows = "".join(f"<tr><td>{esc(e)}</td></tr>" for e in f.excerpt)
            exc_html = (f'<div class="excerpt-block">'
                        f'<table class="excerpt-table">{rows}</table></div>')
        grep_html = ""
        if f.grep_hint:
            grep_html = (f'<div class="grep-hint">'
                         f'<span class="grep-label">GREP</span>'
                         f'<code>{esc(f.grep_hint)}</code></div>')
        desc_html = "<br>".join(esc(l) for l in f.description.splitlines())
        css_level = re.sub(r'[^a-z]', '', f.level.lower())
        return f'''
        <div class="finding finding-{css_level}" id="f-{idx}">
          <div class="finding-header">
            <span class="finding-id">{esc(f.check_id)}</span>
            {badge(f.level)}
            <span class="cat-badge cat-{f.category}">{esc(f.cat_label)}</span>
            <span class="finding-title">{esc(f.title)}</span>
          </div>
          <div class="finding-body">
            <p class="finding-desc">{desc_html}</p>
            {exc_html}{grep_html}
          </div>
        </div>'''

    files_html = ""
    for file_path, flist in results.items():
        non_ok = sorted([f for f in flist if f.level != "OK"], key=lambda f: f.sort_key())
        ok     = [f for f in flist if f.level == "OK"]
        fc = Counter(f.level for f in non_ok if f.level != "INFO")
        badges_html = " ".join(
            f'<span class="badge" style="background:{Finding.COLORS.get(l, "#718096")}">'
            f'{n} {Finding.LABELS.get(l, l)}</span>'
            for l, n in sorted(fc.items(), key=lambda x: Finding.LEVELS.get(x[0], 9))
        )
        body = "".join(render_finding(f, f"{file_path.stem}-{i}") for i, f in enumerate(non_ok))
        if ok:
            body += (f'<div class="ok-summary">Checks sans anomalie : '
                     f'{esc(", ".join(f.check_id for f in ok))}</div>')
        files_html += f'''
        <section class="file-section">
          <div class="file-header">
            <span class="file-icon">&#128196;</span>
            <span class="file-name">{esc(file_path.name)}</span>
            <span class="file-badges">{badges_html}</span>
          </div>{body}
        </section>'''

    # ── SECTION CONFORMITE ───────────────────────────────────────
    all_c    = [f for flist in compliance_results.values() for f in flist]
    ok_c     = sum(1 for f in all_c if f.level == "OK")
    crit_c   = sum(1 for f in all_c if f.level == "CRITIQUE")
    mod_c    = sum(1 for f in all_c if f.level == "MODERE")
    total_c  = len(all_c)
    pct_ok   = round(100 * ok_c / total_c, 1) if total_c > 0 else 0
    all_gaps = [f for f in all_c if f.level != "OK"]
    all_gaps.sort(key=lambda f: f.sort_key())

    if crit_c > 0:
        comp_color, comp_label = "#e53e3e", "NON CONFORME"
    elif mod_c > 0:
        comp_color, comp_label = "#dd6b20", "PARTIELLEMENT CONFORME"
    else:
        comp_color, comp_label = "#38a169", "CONFORME"

    def status_badge(level):
        if level == "OK":
            return '<span class="status-ok">CONFORME</span>'
        elif level == "CRITIQUE":
            return '<span class="status-crit">GAP CRITIQUE</span>'
        elif level == "MODERE":
            return '<span class="status-mod">GAP MODERE</span>'
        return f'<span class="status-info">{esc(level)}</span>'

    # Tableau conformite par fichier
    comp_tables = ""
    for file_path, flist in compliance_results.items():
        fsorted  = sorted(flist, key=lambda f: f.sort_key())
        file_ok  = sum(1 for f in fsorted if f.level == "OK")
        file_tot = len(fsorted)
        file_pct = round(100 * file_ok / file_tot, 1) if file_tot > 0 else 0
        file_crit = sum(1 for f in fsorted if f.level == "CRITIQUE")
        bar_color = "#e53e3e" if file_crit > 0 else ("#d69e2e" if file_pct < 100 else "#38a169")
        rows = ""
        for f in fsorted:
            desc_html_c = f.description.replace('\n', '<br>')
            rows += (f'<tr class="req-row req-{f.level.lower()}">'
                     f'<td class="req-id">{esc(f.check_id)}</td>'
                     f'<td class="req-title">{esc(f.title)}</td>'
                     f'<td class="req-status">{status_badge(f.level)}</td>'
                     f'<td class="req-detail">{desc_html_c if f.level != "OK" else "—"}</td>'
                     f'</tr>')
        comp_tables += f'''
        <section class="file-section comp-section">
          <div class="file-header">
            <span class="file-icon">&#128196;</span>
            <span class="file-name">{esc(file_path.name)}</span>
            <span class="file-score">
              <div class="score-bar-wrap"><div class="score-bar" style="width:{file_pct}%;background:{bar_color}"></div></div>
              <span class="score-pct" style="color:{bar_color}">{file_pct}%</span>
              <span class="score-label">conforme ({file_ok}/{file_tot})</span>
            </span>
          </div>
          <table class="req-table">
            <thead><tr><th style="width:56px">ID</th><th>Exigence</th><th style="width:150px">Statut</th><th>Detail / Gap</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </section>'''

    # Recap gaps
    gap_rows_html = "".join(
        f'<tr><td class="req-id">{esc(f.check_id)}</td>'
        f'<td>{esc(f.title)}</td>'
        f'<td>{status_badge(f.level)}</td></tr>'
        for f in all_gaps
    )

    # ── TABLEAU SYNTHESE SECURITE ─────────────────────────────────
    summary_rows = ""
    for fp, flist in results.items():
        for f in sorted([x for x in flist if x.level not in ("OK", "INFO")],
                        key=lambda x: x.sort_key()):
            summary_rows += (
                f'<tr><td>{esc(fp.name)}</td>'
                f'<td><span class="check-id">{esc(f.check_id)}</span></td>'
                f'<td class="cat-cell cat-{f.category}">{esc(f.cat_label)}</td>'
                f'<td>{badge(f.level)}</td>'
                f'<td>{esc(f.title)}</td></tr>'
            )

    html = f'''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rapport audit logs</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#0d1117;--sf:#161b22;--sf2:#1c2128;--bd:#30363d;--tx:#e6edf3;--muted:#8b949e;
--sans:'IBM Plex Sans',sans-serif;--mono:'IBM Plex Mono',monospace;
--red:#e53e3e;--ora:#dd6b20;--yel:#d69e2e;--blu:#3182ce;--grn:#38a169;--acc:#58a6ff}}
body{{font-family:var(--sans);background:var(--bg);color:var(--tx);line-height:1.6;font-size:14px}}

/* HEADER */
.report-header{{background:var(--sf);border-bottom:1px solid var(--bd);padding:28px 48px;
display:flex;align-items:flex-start;justify-content:space-between;gap:24px;flex-wrap:wrap}}
.header-left h1{{font-size:20px;font-weight:600;letter-spacing:-.3px}}
.header-left .sub{{color:var(--muted);font-size:12px;margin-top:4px;font-family:var(--mono)}}
.pills{{display:flex;gap:10px;flex-wrap:wrap;align-items:center}}
.pill{{padding:6px 16px;border-radius:6px;font-weight:600;font-size:11px;
font-family:var(--mono);letter-spacing:.5px;text-transform:uppercase;border:1.5px solid currentColor}}

/* STATS DOUBLE */
.dual-stats{{background:var(--sf2);border-bottom:1px solid var(--bd);padding:14px 48px;
display:flex;gap:0;flex-wrap:wrap}}
.stats-block{{display:flex;gap:24px;flex-wrap:wrap;align-items:center;padding:6px 24px 6px 0;
border-right:1px solid var(--bd);margin-right:24px}}
.stats-block:last-child{{border-right:none;margin-right:0}}
.stats-block-label{{font-size:10px;text-transform:uppercase;letter-spacing:.5px;
color:var(--muted);font-family:var(--mono);margin-bottom:6px;display:block}}
.stat-item{{display:flex;align-items:center;gap:7px;font-size:13px}}
.stat-count{{font-family:var(--mono);font-size:18px;font-weight:700}}
.stat-label{{color:var(--muted);font-size:12px}}
.progress-inline{{display:flex;align-items:center;gap:10px}}
.progress-wrap{{width:100px;height:7px;background:var(--bd);border-radius:4px;overflow:hidden}}
.progress-fill{{height:100%;border-radius:4px}}

/* TABS */
.tabs{{background:var(--sf);border-bottom:1px solid var(--bd);padding:0 48px;display:flex}}
.tab{{padding:12px 20px;cursor:pointer;font-size:13px;font-weight:500;color:var(--muted);
border-bottom:2px solid transparent;transition:all .15s;user-select:none;white-space:nowrap}}
.tab:hover{{color:var(--tx)}} .tab.active{{color:var(--acc);border-bottom-color:var(--acc)}}
.tab-group-sep{{width:1px;background:var(--bd);margin:8px 8px}}

/* MAIN */
.main{{padding:28px 48px;max-width:1500px}}
.tab-panel{{display:none}} .tab-panel.active{{display:block}}

/* SECTION TITRE */
.section-title{{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;
letter-spacing:.5px;margin-bottom:18px;padding-bottom:8px;border-bottom:1px solid var(--bd)}}

/* FINDINGS SECURITE */
.file-section{{margin-bottom:36px}}
.file-header{{display:flex;align-items:center;gap:10px;padding:11px 16px;background:var(--sf);
border:1px solid var(--bd);border-radius:8px 8px 0 0;font-family:var(--mono);font-size:12px;font-weight:600}}
.file-name{{color:var(--acc)}}
.file-badges{{margin-left:auto;display:flex;gap:5px;flex-wrap:wrap}}
.file-score{{margin-left:auto;display:flex;align-items:center;gap:10px}}
.score-bar-wrap{{width:110px;height:7px;background:var(--bd);border-radius:4px;overflow:hidden}}
.score-bar{{height:100%;border-radius:4px}}
.score-pct{{font-weight:700;font-size:13px}}
.score-label{{color:var(--muted);font-size:11px}}
.finding{{border:1px solid var(--bd);border-top:none;background:var(--sf);transition:background .1s}}
.finding:last-of-type{{border-radius:0 0 8px 8px}}
.finding:hover{{background:var(--sf2)}}
.finding-header{{display:flex;align-items:center;gap:9px;padding:11px 16px;
cursor:pointer;border-top:1px solid var(--bd)}}
.finding-id{{font-family:var(--mono);font-size:11px;color:var(--muted);min-width:40px}}
.finding-title{{font-weight:500;font-size:13px;flex:1}}
.finding-body{{padding:0 16px 16px 66px;display:none}}
.finding.open .finding-body{{display:block}}
.finding.open .finding-header{{border-bottom:1px solid var(--bd)}}
.finding-desc{{color:var(--muted);font-size:13px;margin-top:11px;line-height:1.7}}
.excerpt-block{{margin-top:11px;background:#0d1117;border:1px solid var(--bd);border-radius:6px;overflow:hidden}}
.excerpt-table{{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:11px}}
.excerpt-table td{{padding:5px 12px;color:#7ee787;border-bottom:1px solid var(--bd);
white-space:pre;overflow:hidden;text-overflow:ellipsis;max-width:900px}}
.excerpt-table tr:last-child td{{border-bottom:none}}
.grep-hint{{margin-top:9px;display:flex;align-items:center;gap:7px;background:#161b22;
border:1px solid var(--bd);border-radius:6px;padding:7px 12px}}
.grep-label{{font-family:var(--mono);font-size:10px;font-weight:600;color:var(--acc);
background:rgba(88,166,255,.1);padding:2px 6px;border-radius:3px;white-space:nowrap}}
.grep-hint code{{font-family:var(--mono);font-size:11px;color:#e6edf3;word-break:break-all}}
.ok-summary{{border:1px solid var(--bd);border-top:none;background:rgba(56,161,105,.05);
color:var(--grn);font-size:12px;padding:9px 16px;font-family:var(--mono);border-radius:0 0 8px 8px}}

/* BADGES */
.badge{{font-size:10px;font-weight:600;font-family:var(--mono);padding:2px 7px;border-radius:4px;color:#fff;white-space:nowrap}}
.cat-badge{{font-size:10px;font-weight:500;padding:2px 7px;border-radius:4px;white-space:nowrap;font-family:var(--mono)}}
.cat-S{{background:rgba(229,62,62,.15);color:#fc8181}}
.cat-F{{background:rgba(49,130,206,.15);color:#63b3ed}}
.cat-A{{background:rgba(159,122,234,.15);color:#b794f4}}
.cat-P{{background:rgba(237,137,54,.15);color:#f6ad55}}
.cat-D{{background:rgba(128,90,213,.15);color:#d6bcfa}}
.cat-C{{background:rgba(56,161,105,.15);color:#68d391}}
.check-id{{font-family:var(--mono);font-size:11px;color:var(--muted)}}

/* FILTER */
.filter-bar{{display:flex;gap:7px;margin-bottom:18px;flex-wrap:wrap}}
.filter-btn{{padding:5px 13px;border-radius:20px;border:1px solid var(--bd);background:transparent;
color:var(--muted);font-size:12px;font-family:var(--sans);cursor:pointer;transition:all .15s}}
.filter-btn:hover,.filter-btn.active{{background:var(--acc);border-color:var(--acc);color:#0d1117;font-weight:600}}

/* SUMMARY TABLE */
.summary-table{{width:100%;border-collapse:collapse;font-size:13px}}
.summary-table th{{text-align:left;padding:9px 14px;background:var(--sf2);color:var(--muted);
font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--bd)}}
.summary-table td{{padding:9px 14px;border-bottom:1px solid var(--bd);vertical-align:middle}}
.summary-table tr:last-child td{{border-bottom:none}}
.summary-table tr:hover td{{background:var(--sf2)}}

/* CONFORMITE */
.comp-section{{margin-bottom:36px}}
.req-table{{width:100%;border-collapse:collapse;font-size:13px;border:1px solid var(--bd);border-top:none}}
.req-table th{{text-align:left;padding:9px 14px;background:var(--sf2);color:var(--muted);
font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--bd)}}
.req-table td{{padding:9px 14px;border-bottom:1px solid var(--bd);vertical-align:top}}
.req-table tr:last-child td{{border-bottom:none}}
.req-row:hover td{{background:var(--sf2)}}
.req-row.req-critique td{{border-left:3px solid var(--red)}}
.req-row.req-modere td{{border-left:3px solid var(--yel)}}
.req-row.req-ok td{{border-left:3px solid var(--grn)}}
.req-id{{font-family:var(--mono);font-size:11px;color:var(--muted);white-space:nowrap}}
.req-title{{font-weight:500}}
.req-status{{white-space:nowrap;text-align:center}}
.req-detail{{color:var(--muted);font-size:12px;line-height:1.6}}
.status-ok{{background:rgba(56,161,105,.15);color:#68d391;font-family:var(--mono);
font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;display:inline-block}}
.status-crit{{background:rgba(229,62,62,.15);color:#fc8181;font-family:var(--mono);
font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;display:inline-block}}
.status-mod{{background:rgba(214,158,46,.15);color:#f6e05e;font-family:var(--mono);
font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;display:inline-block}}
.gap-table{{width:100%;border-collapse:collapse;font-size:13px}}
.gap-table th{{text-align:left;padding:9px 14px;background:var(--sf2);color:var(--muted);
font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--bd)}}
.gap-table td{{padding:9px 14px;border-bottom:1px solid var(--bd);vertical-align:middle}}
.gap-table tr:last-child td{{border-bottom:none}}
.gap-table tr:hover td{{background:var(--sf2)}}

@media(max-width:768px){{
.report-header,.dual-stats,.tabs,.main{{padding-left:16px;padding-right:16px}}
.finding-body{{padding-left:16px}}
.stats-block{{border-right:none;padding-right:0;margin-right:0}}
}}
</style>
</head>
<body>

<!-- HEADER -->
<header class="report-header">
  <div class="header-left">
    <h1>Rapport d'audit -- Fichiers logs</h1>
    <div class="sub">Généré le {now} &middot; {len(results)} fichier(s) analyse(s)</div>
  </div>
  <div class="pills">
    <div class="pill" style="color:{risk_color};border-color:{risk_color}">Sécurité : {risk_label}</div>
    <div class="pill" style="color:{comp_color};border-color:{comp_color}">{comp_label}</div>
  </div>
</header>

<!-- STATS DOUBLES -->
<div class="dual-stats">
  <div class="stats-block">
    <span class="stats-block-label">Sécurité / Données personnelles</span>
    <div class="stat-item"><span class="stat-count" style="color:{Finding.COLORS['CRITIQUE']}">{counts.get('CRITIQUE',0)}</span><span class="stat-label">Critique</span></div>
    <div class="stat-item"><span class="stat-count" style="color:{Finding.COLORS['ELEVE']}">{counts.get('ELEVE',0)}</span><span class="stat-label">Eleve</span></div>
    <div class="stat-item"><span class="stat-count" style="color:{Finding.COLORS['MODERE']}">{counts.get('MODERE',0)}</span><span class="stat-label">Modere</span></div>
    <div class="stat-item"><span class="stat-count" style="color:{Finding.COLORS['FAIBLE']}">{counts.get('FAIBLE',0)}</span><span class="stat-label">Faible</span></div>
  </div>
  <div class="stats-block">
    <span class="stats-block-label">Conformité / Complétude ({pct_ok}% conforme)</span>
    <div class="stat-item"><span class="stat-count" style="color:#38a169">{ok_c}</span><span class="stat-label">Conformes</span></div>
    <div class="stat-item"><span class="stat-count" style="color:#e53e3e">{crit_c}</span><span class="stat-label">Gaps critiques</span></div>
    <div class="stat-item"><span class="stat-count" style="color:#d69e2e">{mod_c}</span><span class="stat-label">Gaps moderes</span></div>
    <div class="stat-item">
      <div class="progress-inline">
        <div class="progress-wrap"><div class="progress-fill" style="width:{pct_ok}%;background:{comp_color}"></div></div>
        <span style="font-family:var(--mono);font-size:12px;color:{comp_color};font-weight:700">{pct_ok}%</span>
      </div>
    </div>
  </div>
</div>

<!-- NAVIGATION -->
<div class="tabs">
  <div class="tab active" onclick="switchTab('sec-findings',this)">Findings sécurité</div>
  <div class="tab" onclick="switchTab('sec-summary',this)">Synthese sécurité</div>
  <div class="tab-group-sep"></div>
  <div class="tab" onclick="switchTab('comp-detail',this)">Conformité / Complétude</div>
  <div class="tab" onclick="switchTab('comp-gaps',this)">Recap gaps ({len(all_gaps)})</div>
</div>

<div class="main">

  <!-- TAB : FINDINGS SECURITE -->
  <div class="tab-panel active" id="tab-sec-findings">
    <div class="section-title">Sécurité des logs &amp; Données personnelles</div>
    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterFindings('ALL',this)">Tous</button>
      <button class="filter-btn" onclick="filterFindings('CRITIQUE',this)">Critique</button>
      <button class="filter-btn" onclick="filterFindings('ELEVE',this)">Eleve</button>
      <button class="filter-btn" onclick="filterFindings('MODERE',this)">Modere</button>
      <button class="filter-btn" onclick="filterFindings('FAIBLE',this)">Faible</button>
      <button class="filter-btn" onclick="filterFindings('S',this)" style="margin-left:10px">Sécurité</button>
      <button class="filter-btn" onclick="filterFindings('F',this)">Forensique</button>
      <button class="filter-btn" onclick="filterFindings('A',this)">Auth</button>
      <button class="filter-btn" onclick="filterFindings('P',this)">Privilèges</button>
      <button class="filter-btn" onclick="filterFindings('D',this)">Données</button>
    </div>
    {files_html}
  </div>

  <!-- TAB : SYNTHESE SECURITE -->
  <div class="tab-panel" id="tab-sec-summary">
    <div class="section-title">Tableau de synthese -- findings sécurité</div>
    <table class="summary-table">
      <thead><tr><th>Fichier</th><th>ID</th><th>Categorie</th><th>Criticite</th><th>Titre</th></tr></thead>
      <tbody>{summary_rows}</tbody>
    </table>
  </div>

  <!-- TAB : CONFORMITE DETAIL -->
  <div class="tab-panel" id="tab-comp-detail">
    <div class="section-title">Conformité &amp; Complétude des logs -- detail par fichier</div>
    {comp_tables}
  </div>

  <!-- TAB : RECAP GAPS -->
  <div class="tab-panel" id="tab-comp-gaps">
    <div class="section-title">Recapitulatif des gaps de conformité ({len(all_gaps)} exigence(s) non satisfaite(s))</div>
    <table class="gap-table">
      <thead><tr><th style="width:60px">ID</th><th>Exigence</th><th style="width:150px">Statut</th></tr></thead>
      <tbody>{gap_rows_html}</tbody>
    </table>
  </div>

</div>

<script>
function switchTab(n,el){{
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('tab-'+n).classList.add('active');
}}
document.querySelectorAll('.finding-header').forEach(h=>{{
  h.addEventListener('click',()=>h.closest('.finding').classList.toggle('open'));
}});
document.querySelectorAll('.finding-critique,.finding-eleve').forEach(f=>f.classList.add('open'));
function filterFindings(val,btn){{
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding').forEach(f=>{{
    if(val==='ALL'){{f.style.display='';return;}}
    const lvl=f.querySelector('.badge')?.textContent.trim().toUpperCase();
    const cat=f.querySelector('.cat-badge')?.classList.contains('cat-'+val);
    f.style.display=(lvl===val||cat)?'':'none';
  }});
}}
</script>
</body>
</html>'''

    output_path.write_text(html, encoding='utf-8')


# ─────────────────────────────────────────────────────────────────
# POINT D'ENTREE
# ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Audit de sécurité -- fichiers logs (texte, JSON, CSV)"
    )
    parser.add_argument("files", nargs="*",
                        help="Fichier(s) a analyser (.log, .json, .csv, .txt)")
    parser.add_argument("--dir", "-d",
                        help="Repertoire a scanner (*.log, *.json, *.csv, *.txt)")
    parser.add_argument("--output", "-o", default="audit_log_report.html",
                        help="Rapport sécurité HTML (defaut: audit_log_report.html)")
    parser.add_argument("--compliance", "-c", default=None,
                        help="Rapport conformité HTML (defaut: <output>_conformité.html)")
    args = parser.parse_args()

    targets = []
    if args.dir:
        d = Path(args.dir)
        for ext in ("*.log", "*.txt", "*.json", "*.csv"):
            targets += list(d.glob(ext))
    for f in args.files:
        p = Path(f)
        if '*' in p.name:
            targets += list(p.parent.glob(p.name))
        else:
            targets.append(p)

    targets = sorted(set(targets))

    if not targets:
        print("Aucun fichier trouvé. Usage :")
        print("  python3 log_analyzer.py fichier.log")
        print("  python3 log_analyzer.py --dir /chemin/logs")
        sys.exit(1)

    results            = {}
    compliance_results = {}

    for path in targets:
        fmt, lines, raw = read_file(path)
        if not lines:
            print(f"[!] Impossible de lire ou fichier vide : {path}")
            continue
        print(f"[*] {path.name}  ({len(lines)} entrées, format={fmt})")

        sec_findings  = run_checks(path, fmt, lines)
        sec_findings.sort(key=lambda f: f.sort_key())
        results[path] = sec_findings
        comp_findings = run_compliance_checks(path, fmt, lines, sec_findings)
        comp_findings.sort(key=lambda f: f.sort_key())
        compliance_results[path] = comp_findings

    if not results:
        print("Aucun fichier analyse.")
        sys.exit(1)

    out = Path(args.output)
    generate_unified_html(results, compliance_results, out)
    print(f"\n[+] Rapport généré : {out.resolve()}")

    actionable = sorted(
        [f for flist in results.values() for f in flist if f.level not in ("OK", "INFO")],
        key=lambda f: f.sort_key()
    )
    print("\n--- Findings sécurité ---")
    for f in actionable[:8]:
        print(f"  [{f.label:<8}] {f.check_id}  {f.title}")
    if len(actionable) > 8:
        print(f"  ... et {len(actionable) - 8} finding(s) supplémentaire(s)")

    all_comp = [f for flist in compliance_results.values() for f in flist]
    ok_c   = sum(1 for f in all_comp if f.level == "OK")
    crit_c = sum(1 for f in all_comp if f.level == "CRITIQUE")
    mod_c  = sum(1 for f in all_comp if f.level == "MODERE")
    pct    = round(100 * ok_c / len(all_comp), 1) if all_comp else 0
    print(f"\n--- Conformité : {pct}% ({ok_c}/{len(all_comp)}) -- Gaps critiques : {crit_c}  Gaps moderes : {mod_c} ---")


if __name__ == "__main__":
    main()
