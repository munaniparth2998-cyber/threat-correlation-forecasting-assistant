import pandas as pd
from datetime import timedelta

# ======================================================================== #
# SINGLE SOURCE OF TRUTH — TECHNIQUE SCORING TABLE                         #
#                                                                           #
# Explainable risk-prioritization score inspired by structured              #
# severity-scoring principles. NOT CVSS.                                    #
#                                                                           #
# Design rationale for each weight:                                         #
#   T1595  2 pts — Reconnaissance only; no access gained yet.               #
#   T1110  5 pts — Active credential attack; breach is possible but not     #
#                  confirmed.                                                #
#   T1098  7 pts — Attacker has manipulated an account; persistent or       #
#                  elevated access is now likely.                            #
#   T1048  8 pts — Data has left the environment; highest-impact outcome.   #
#   T1498  6 pts — Service disruption confirmed; may mask concurrent        #
#                  intrusion activity.                                       #
#                                                                           #
# MAX_SCORE = sum of all five unique weights = 2+5+7+8+6 = 28.             #
# Any group scoring ≥ 16 is classified HIGH.                                #
# Repeated occurrences of the same technique in one group are counted       #
# once only (deduplication — see score_and_forecast()).                     #
# ======================================================================== #
TECHNIQUE_SCORES = {
    # code : (points, tactic,              plain-English reason)
    "T1595": (2, "Reconnaissance",      "Active reconnaissance / port scanning detected against this host"),
    "T1110": (5, "Credential Access",   "Repeated failed login attempts (brute force) observed from this IP"),
    "T1098": (7, "Persistence/PrivEsc", "Account settings manipulated to maintain or elevate access on this system"),
    "T1048": (8, "Exfiltration",        "Data transferred out over a non-standard or alternative protocol"),
    "T1498": (6, "Impact",              "High-volume traffic spike consistent with a denial-of-service attack"),
}

# Derived constant — computed, never hand-typed, so it stays correct if
# weights are ever updated. Used by scoring, reports, and the dashboard.
MAX_SCORE = sum(pts for pts, _, _ in TECHNIQUE_SCORES.values())  # = 28

# Risk-level thresholds
RISK_LEVELS = [
    (16, "HIGH"),
    ( 6, "MEDIUM"),
    ( 0, "LOW"),
]


def classify_score(score):
    """Return LOW / MEDIUM / HIGH for a numeric score."""
    for threshold, label in RISK_LEVELS:
        if score >= threshold:
            return label
    return "LOW"


def score_breakdown_lines(seen_codes):
    """
    Return a list of strings showing per-technique points and the total,
    e.g. ['  T1595 →  2 pts  (Reconnaissance)', ..., '  Total → 22/28'].
    seen_codes is an ordered list of unique technique codes that contributed.
    """
    lines = []
    total = 0
    for code in seen_codes:
        pts, tactic, _ = TECHNIQUE_SCORES[code]
        lines.append(f"  {code}  →  {pts:>2} pts  ({tactic})")
        total += pts
    lines.append(f"  {'─'*34}")
    lines.append(f"  Total  →  {total:>2}/{MAX_SCORE}")
    return lines


def validate_score(score):
    """
    Raise ValueError if score exceeds MAX_SCORE.
    Prevents silent inconsistency between score and displayed maximum.
    """
    if score > MAX_SCORE:
        raise ValueError(
            f"Computed score {score} exceeds MAX_SCORE {MAX_SCORE}. "
            "Check TECHNIQUE_SCORES for duplicate or erroneous entries."
        )


# ======================================================================== #
# KNOWLEDGE-BASE FOR FORECASTING                                            #
#                                                                           #
# Label: "Knowledge-Based Forecasting using documented MITRE ATT&CK         #
#         relationships"                                                    #
#                                                                           #
# This is NOT machine-learning prediction.                                  #
# This is NOT a probability score.                                          #
# This does NOT guarantee future attacker behaviour.                        #
#                                                                           #
# Each entry maps the LAST observed MITRE technique in a group to a         #
# set of plausible follow-on activities documented in the MITRE ATT&CK      #
# framework.                                                                #
#                                                                           #
# Structure per entry:                                                      #
#   "observed_technique" : human-readable name of what was last seen        #
#   "next_techniques"    : list of dicts, each with:                        #
#       "technique"      : MITRE ID + name of the plausible follow-on       #
#       "explanation"    : plain-English reason why this association exists  #
#       "wording"        : cautious sentence for display in reports/UI       #
#       "source"         : reference justifying the relationship             #
#   "why_this_forecast"  : one-sentence explanation of the overall forecast  #
#   "fallback"           : True means this is a no-evidence fallback entry  #
#                                                                           #
# Rules for adding new entries:                                             #
#   - Only add relationships documented in MITRE ATT&CK or equivalent       #
#     threat intelligence sources.                                           #
#   - Never add a relationship based on intuition alone.                    #
#   - Never use words like "will", "guaranteed", or percentages.            #
# ======================================================================== #
FORECAST_KB = {

    # ------------------------------------------------------------------ #
    # T1048 — Exfiltration Over Alternative Protocol                       #
    # Observed last: data was transferred out via non-standard channel.    #
    # ------------------------------------------------------------------ #
    "T1048": {
        "observed_technique": "T1048 - Exfiltration Over Alternative Protocol",
        "why_this_forecast": (
            "Exfiltration is typically a late-stage technique. "
            "Post-exfiltration activity documented in ATT&CK includes "
            "defense evasion (removing evidence) and lateral movement "
            "to expand the breach to adjacent systems."
        ),
        "next_techniques": [
            {
                "technique":   "T1070 - Indicator Removal",
                "explanation": (
                    "After exfiltrating data, adversaries commonly attempt to "
                    "remove logs, clear command history, or delete staging files "
                    "to hinder forensic investigation."
                ),
                "wording": (
                    "A plausible next step is defense evasion activity. "
                    "Monitor for log clearing, file deletion in staging areas, "
                    "or changes to audit policies (T1070 - Indicator Removal)."
                ),
                "source": "MITRE ATT&CK T1070 — https://attack.mitre.org/techniques/T1070/",
            },
            {
                "technique":   "T1021 - Remote Services (Lateral Movement)",
                "explanation": (
                    "Once data has been extracted from one host, adversaries "
                    "commonly move laterally to access additional systems and "
                    "repeat the collection-exfiltration cycle."
                ),
                "wording": (
                    "Commonly associated follow-on activity includes lateral movement. "
                    "Monitor for unusual remote service connections, RDP, SSH, "
                    "or SMB activity from this host to adjacent systems "
                    "(T1021 - Remote Services)."
                ),
                "source": "MITRE ATT&CK T1021 — https://attack.mitre.org/techniques/T1021/",
            },
        ],
        "fallback": False,
    },

    # ------------------------------------------------------------------ #
    # T1098 — Account Manipulation                                         #
    # Observed last: account settings were modified for persistence/access.#
    # ------------------------------------------------------------------ #
    "T1098": {
        "observed_technique": "T1098 - Account Manipulation",
        "why_this_forecast": (
            "Account manipulation is documented as a Persistence and "
            "Privilege Escalation technique. Once an adversary controls "
            "an elevated account, ATT&CK documents common follow-on "
            "steps as data collection, exfiltration, and defence evasion."
        ),
        "next_techniques": [
            {
                "technique":   "T1048 - Exfiltration Over Alternative Protocol",
                "explanation": (
                    "With elevated account access established, adversaries "
                    "are positioned to collect and exfiltrate sensitive data "
                    "using the newly manipulated account's permissions."
                ),
                "wording": (
                    "A plausible next step is data collection and exfiltration. "
                    "Monitor for large or unusual outbound data transfers, "
                    "especially from the account that was manipulated "
                    "(T1048 - Exfiltration Over Alternative Protocol)."
                ),
                "source": "MITRE ATT&CK T1048 — https://attack.mitre.org/techniques/T1048/",
            },
            {
                "technique":   "T1070 - Indicator Removal",
                "explanation": (
                    "Adversaries may attempt to cover traces of account "
                    "manipulation by removing relevant log entries or "
                    "audit trail records."
                ),
                "wording": (
                    "Commonly associated follow-on activity includes defense evasion. "
                    "Monitor for tampering with account audit logs or security "
                    "event logs on this host (T1070 - Indicator Removal)."
                ),
                "source": "MITRE ATT&CK T1070 — https://attack.mitre.org/techniques/T1070/",
            },
        ],
        "fallback": False,
    },

    # ------------------------------------------------------------------ #
    # T1110 — Brute Force                                                  #
    # Observed last: repeated failed (or successful) login attempts.       #
    # ------------------------------------------------------------------ #
    "T1110": {
        "observed_technique": "T1110 - Brute Force",
        "why_this_forecast": (
            "Brute force is a Credential Access technique. "
            "ATT&CK documents that successful credential access is "
            "commonly followed by account manipulation for persistence, "
            "or reuse of compromised credentials across other systems."
        ),
        "next_techniques": [
            {
                "technique":   "T1098 - Account Manipulation",
                "explanation": (
                    "Successful brute force gives the adversary valid credentials. "
                    "A commonly documented next step is manipulating the compromised "
                    "account (e.g. adding roles, changing passwords) to establish "
                    "persistent access."
                ),
                "wording": (
                    "A plausible next step is account manipulation. "
                    "Monitor for unexpected changes to account roles, permissions, "
                    "or credentials on systems targeted by this IP "
                    "(T1098 - Account Manipulation)."
                ),
                "source": "MITRE ATT&CK T1098 — https://attack.mitre.org/techniques/T1098/",
            },
            {
                "technique":   "T1078 - Valid Accounts",
                "explanation": (
                    "Compromised credentials may be reused across other services "
                    "or systems, allowing the adversary to authenticate legitimately "
                    "and evade detection."
                ),
                "wording": (
                    "Commonly associated follow-on activity includes credential "
                    "reuse. Monitor for this IP or the targeted account authenticating "
                    "to other systems or services (T1078 - Valid Accounts)."
                ),
                "source": "MITRE ATT&CK T1078 — https://attack.mitre.org/techniques/T1078/",
            },
        ],
        "fallback": False,
    },

    # ------------------------------------------------------------------ #
    # T1595 — Active Scanning                                              #
    # Observed last: port/service scanning was the most recent activity.   #
    # ------------------------------------------------------------------ #
    "T1595": {
        "observed_technique": "T1595 - Active Scanning",
        "why_this_forecast": (
            "Active scanning is a Reconnaissance technique. "
            "ATT&CK documents that reconnaissance commonly precedes "
            "credential attacks against discovered open services, "
            "or exploitation of identified public-facing applications."
        ),
        "next_techniques": [
            {
                "technique":   "T1110 - Brute Force",
                "explanation": (
                    "Open services discovered during scanning are common targets "
                    "for follow-on credential attacks. Brute force is a "
                    "well-documented post-recon technique."
                ),
                "wording": (
                    "A plausible next step is a credential attack against "
                    "services identified during scanning. Monitor for repeated "
                    "authentication failures on open ports from this IP "
                    "(T1110 - Brute Force)."
                ),
                "source": "MITRE ATT&CK T1110 — https://attack.mitre.org/techniques/T1110/",
            },
            {
                "technique":   "T1190 - Exploit Public-Facing Application",
                "explanation": (
                    "Scanning may identify vulnerable public-facing services. "
                    "Exploitation of those services is a documented follow-on step."
                ),
                "wording": (
                    "Commonly associated follow-on activity includes exploitation "
                    "of services identified during scanning. Monitor for unusual "
                    "request patterns or error rates on exposed services "
                    "(T1190 - Exploit Public-Facing Application)."
                ),
                "source": "MITRE ATT&CK T1190 — https://attack.mitre.org/techniques/T1190/",
            },
        ],
        "fallback": False,
    },

    # ------------------------------------------------------------------ #
    # T1498 — Network Denial of Service                                    #
    # Observed last: high-volume traffic / DDoS activity.                  #
    # ------------------------------------------------------------------ #
    "T1498": {
        "observed_technique": "T1498 - Network Denial of Service",
        "why_this_forecast": (
            "DDoS is an Impact technique. ATT&CK and threat intelligence "
            "report that volumetric attacks are sometimes used as a "
            "distraction to mask concurrent intrusion activity on other "
            "systems or services."
        ),
        "next_techniques": [
            {
                "technique":   "T1070 - Indicator Removal",
                "explanation": (
                    "A DDoS event may be used to generate noise that obscures "
                    "concurrent attacker activity in logs. Monitor for log "
                    "tampering or unusual activity on other systems during "
                    "the flood window."
                ),
                "wording": (
                    "Commonly associated with concurrent defense evasion activity. "
                    "Monitor for log clearing or unusual access patterns on other "
                    "systems during or immediately after the traffic flood "
                    "(T1070 - Indicator Removal)."
                ),
                "source": "MITRE ATT&CK T1070 — https://attack.mitre.org/techniques/T1070/",
            },
            {
                "technique":   "T1595 - Active Scanning (concurrent or follow-on)",
                "explanation": (
                    "DDoS is documented as a distraction technique. Concurrent "
                    "scanning or intrusion activity on other hosts during the "
                    "flood window is a documented threat pattern."
                ),
                "wording": (
                    "A plausible associated activity is concurrent reconnaissance "
                    "or intrusion on other systems while this flood is active. "
                    "Review traffic to other hosts during this time window."
                ),
                "source": (
                    "MITRE ATT&CK T1498 procedure examples — "
                    "https://attack.mitre.org/techniques/T1498/"
                ),
            },
        ],
        "fallback": False,
    },

    # ------------------------------------------------------------------ #
    # T1078 — Valid Accounts                                               #
    # Observed last: adversary authenticated using legitimate credentials, #
    # either stolen via brute force or obtained through prior compromise.  #
    # ------------------------------------------------------------------ #
    "T1078": {
        "observed_technique": "T1078 - Valid Accounts",
        "why_this_forecast": (
            "Use of valid accounts is documented across multiple ATT&CK tactics "
            "(Initial Access, Persistence, Privilege Escalation, Defense Evasion). "
            "Once an adversary holds working credentials, ATT&CK documents common "
            "follow-on steps as lateral movement to additional systems and data "
            "collection ahead of exfiltration."
        ),
        "next_techniques": [
            {
                "technique":   "T1021 - Remote Services (Lateral Movement)",
                "explanation": (
                    "Legitimate credentials allow the adversary to authenticate "
                    "to remote services (RDP, SSH, SMB) without triggering "
                    "brute-force alerts. Lateral movement to additional hosts "
                    "is a well-documented follow-on step."
                ),
                "wording": (
                    "A plausible next step is lateral movement using the obtained "
                    "credentials. Monitor for this account authenticating to other "
                    "systems via remote services such as RDP, SSH, or SMB "
                    "(T1021 - Remote Services)."
                ),
                "source": "MITRE ATT&CK T1021 — https://attack.mitre.org/techniques/T1021/",
            },
            {
                "technique":   "T1098 - Account Manipulation",
                "explanation": (
                    "With valid credentials, an adversary may modify account "
                    "properties to escalate privileges or create additional "
                    "persistent access paths."
                ),
                "wording": (
                    "Commonly associated follow-on activity includes account "
                    "manipulation. Monitor for unexpected changes to roles, group "
                    "membership, or password policies associated with this account "
                    "(T1098 - Account Manipulation)."
                ),
                "source": "MITRE ATT&CK T1098 — https://attack.mitre.org/techniques/T1098/",
            },
        ],
        "fallback": False,
    },

    # ------------------------------------------------------------------ #
    # FALLBACK — no technique code matched                                 #
    # ------------------------------------------------------------------ #
    "__fallback__": {
        "observed_technique": "Unknown / no mapped technique",
        "why_this_forecast": (
            "The last observed technique in this group could not be mapped "
            "to a MITRE ATT&CK technique with sufficient confidence to "
            "produce a knowledge-based forecast."
        ),
        "next_techniques": [
            {
                "technique":   "N/A",
                "explanation": "Insufficient evidence for a specific technique association.",
                "wording": (
                    "No strong knowledge-based forecast available; "
                    "continue monitoring this IP for further activity."
                ),
                "source": "N/A",
            },
        ],
        "fallback": True,
    },
}


def get_forecast(tagged_sequence):
    """
    Knowledge-Based Forecasting using documented MITRE ATT&CK relationships.

    This is NOT machine-learning prediction.
    This does NOT assign probability scores or confidence percentages.
    This does NOT guarantee future attacker behaviour.

    Looks at the LAST technique code in tagged_sequence that has an entry
    in FORECAST_KB and returns the corresponding forecast dict.
    If no match is found, returns the __fallback__ entry.

    Returns a dict with keys:
        observed_technique  — what was last seen
        why_this_forecast   — one-sentence explanation of this forecast
        next_techniques     — list of {technique, explanation, wording, source}
        fallback            — True if this is the no-evidence fallback
        last_code           — the technique code used for the lookup (or None)
    """
    last_code = None
    for tag in reversed(tagged_sequence):
        code = tag[:5] if tag[:1] == "T" else None
        if code and code in FORECAST_KB:
            last_code = code
            break

    entry = FORECAST_KB.get(last_code, FORECAST_KB["__fallback__"])
    return {
        "observed_technique": entry["observed_technique"],
        "why_this_forecast":  entry["why_this_forecast"],
        "next_techniques":    entry["next_techniques"],
        "fallback":           entry["fallback"],
        "last_code":          last_code,
    }


# ── Known multi-stage attack patterns (rule-based, not ML) ──────────── #
# A group matches a pattern if its alert_types list contains ALL stages   #
# of any entry below (in any order). Add more patterns here to expand     #
# detection without touching the correlation algorithm.                   #
MULTI_STAGE_PATTERNS = [
    # Classic recon-to-exfil kill chain
    {"PortScan", "Brute Force", "Privilege Escalation", "Data Exfiltration"},
    # Brute force leading to account compromise and exfiltration
    {"Brute Force", "Privilege Escalation", "Data Exfiltration"},
    # Scanning followed by direct exfiltration (skipped priv-esc step)
    {"PortScan", "Data Exfiltration"},
    # Credential attack followed by DDoS (distraction + disruption pattern)
    {"Brute Force", "DDoS"},
]

# Alert types that are non-benign on their own
SUSPICIOUS_ALERT_TYPES = {
    "PortScan", "Brute Force", "Privilege Escalation",
    "Data Exfiltration", "DDoS",
}


def _classify_group(alert_types):
    """
    Rule-based group classification. Returns one of:
      MULTI-STAGE ATTACK  — group contains all stages of a known pattern
      SUSPICIOUS          — group contains ≥ 1 non-benign alert type
      BENIGN/NOISE        — group contains only BENIGN (or unmapped) alerts

    Classification is deterministic and explainable: no ML, no probabilities.
    """
    type_set = set(alert_types)

    # Check multi-stage patterns first (most specific)
    for pattern in MULTI_STAGE_PATTERNS:
        if pattern.issubset(type_set):
            return "MULTI-STAGE ATTACK"

    # Any single suspicious alert type makes the group SUSPICIOUS
    if type_set & SUSPICIOUS_ALERT_TYPES:
        return "SUSPICIOUS"

    return "BENIGN/NOISE"


def correlate_alerts(filepath="alerts.csv"):
    # ------------------------------------------------------------------ #
    # 1. Read the CSV                                                       #
    # ------------------------------------------------------------------ #
    df = pd.read_csv(filepath)
    total_raw = len(df)

    # ------------------------------------------------------------------ #
    # 2. Data quality — three passes, each counted separately              #
    # ------------------------------------------------------------------ #

    # Pass A: remove exact duplicate rows
    before_dedup = len(df)
    df = df.drop_duplicates()
    dupes_removed = before_dedup - len(df)

    # Pass B: remove rows where timestamp is missing or blank
    before_ts = len(df)
    df = df[df["timestamp"].notna() & (df["timestamp"].astype(str).str.strip() != "")]
    missing_ts_removed = before_ts - len(df)

    # Pass C: parse timestamps; rows that cannot be parsed are invalid
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    before_invalid = len(df)
    df = df[df["timestamp"].notna()]
    invalid_ts_removed = before_invalid - len(df)

    # Total rows removed for timestamp reasons
    ts_removed = missing_ts_removed + invalid_ts_removed

    # Sort chronologically
    df = df.sort_values("timestamp").reset_index(drop=True)
    total_after_quality = len(df)

    # ------------------------------------------------------------------ #
    # 3. Grouping rule (unchanged):                                        #
    #    same source_ip AND gap to previous alert in group ≤ 10 minutes   #
    #    gap > 10 minutes → new group for that IP                          #
    #                                                                      #
    # No alert is dropped. Every alert appears in exactly one group,       #
    # even if it is a lone BENIGN event.                                   #
    # ------------------------------------------------------------------ #
    WINDOW = timedelta(minutes=10)

    groups     = []       # final list of enriched group dicts
    open_groups = {}      # ip -> index of its currently open group

    for _, row in df.iterrows():
        ip    = row["source_ip"]
        ts    = row["timestamp"]
        alert = row["alert_type"]

        if ip in open_groups:
            grp = groups[open_groups[ip]]
            # Gap is measured from the LAST alert in the open group
            if ts - grp["end_time"] <= WINDOW:
                grp["alert_types"].append(alert)
                grp["end_time"]   = ts
                grp["alert_count"] += 1
                continue  # still in the same group

        # First alert for this IP, or gap exceeded → open a new group
        new_grp = {
            "source_ip":   ip,
            "alert_types": [alert],
            "start_time":  ts,
            "end_time":    ts,
            "alert_count": 1,
        }
        groups.append(new_grp)
        open_groups[ip] = len(groups) - 1

    # ------------------------------------------------------------------ #
    # 4. Enrich every group with metadata                                  #
    # ------------------------------------------------------------------ #
    for idx, grp in enumerate(groups):
        duration_td = grp["end_time"] - grp["start_time"]
        dur_secs    = int(duration_td.total_seconds())
        dur_str     = (
            f"{dur_secs // 60}m {dur_secs % 60}s"
            if dur_secs >= 60 else f"{dur_secs}s"
        )
        type_set        = set(grp["alert_types"])
        has_suspicious  = bool(type_set & SUSPICIOUS_ALERT_TYPES)
        classification  = _classify_group(grp["alert_types"])

        # Check which pattern(s) matched (for reporting)
        matched_patterns = []
        for pattern in MULTI_STAGE_PATTERNS:
            if pattern.issubset(type_set):
                matched_patterns.append(sorted(pattern))

        grp.update({
            "group_id":         idx + 1,
            "duration":         dur_str,
            "duration_secs":    dur_secs,
            "has_suspicious":   has_suspicious,
            "matches_multi_stage": len(matched_patterns) > 0,
            "matched_patterns": matched_patterns,
            "classification":   classification,
            # Keep legacy key for downstream compatibility
            "count":            grp["alert_count"],
        })

    # ------------------------------------------------------------------ #
    # 5. Summary statistics                                                #
    # ------------------------------------------------------------------ #
    n_groups        = len(groups)
    n_benign        = sum(1 for g in groups if g["classification"] == "BENIGN/NOISE")
    n_suspicious    = sum(1 for g in groups if g["classification"] == "SUSPICIOUS")
    n_multi         = sum(1 for g in groups if g["classification"] == "MULTI-STAGE ATTACK")
    alerts_in_multi = sum(g["alert_count"] for g in groups if g["classification"] == "MULTI-STAGE ATTACK")
    alerts_in_sus   = sum(g["alert_count"] for g in groups if g["classification"] == "SUSPICIOUS")

    # ------------------------------------------------------------------ #
    # 6. Print correlation summary                                         #
    # ------------------------------------------------------------------ #
    SEP  = "=" * 62
    SEP2 = "-" * 62

    print(f"\n{SEP}")
    print(f"  CORRELATION ENGINE — DATA QUALITY REPORT")
    print(SEP2)
    print(f"  Raw alerts loaded          : {total_raw:>5}")
    print(f"  Exact duplicates removed   : {dupes_removed:>5}")
    print(f"  Missing timestamps removed : {ts_removed:>5}")
    print(f"  Alerts after quality pass  : {total_after_quality:>5}")
    print(SEP2)
    print(f"  CORRELATION RESULTS")
    print(SEP2)
    print(f"  Before: {total_after_quality} individual alerts")
    print(f"  After : {n_groups} correlated groups")
    print(f"  Compression ratio: {total_after_quality}/{n_groups} "
          f"({total_after_quality - n_groups} alerts merged into groups)")
    print(SEP2)
    print(f"  GROUP CLASSIFICATION BREAKDOWN")
    print(SEP2)
    print(f"  BENIGN/NOISE          : {n_benign:>4} group(s)")
    print(f"  SUSPICIOUS            : {n_suspicious:>4} group(s)  "
          f"({alerts_in_sus} alerts compressed)")
    print(f"  MULTI-STAGE ATTACK    : {n_multi:>4} group(s)  "
          f"({alerts_in_multi} alerts compressed into {n_multi} attack chain(s))")
    print(SEP2)
    print(f"  MAIN ATTACK CHAINS DETECTED")
    print(SEP2)
    for g in groups:
        if g["classification"] == "MULTI-STAGE ATTACK":
            seq = " → ".join(g["alert_types"])
            print(f"  Group {g['group_id']:>3} | {g['source_ip']:<18} | "
                  f"{g['alert_count']} alerts | {g['duration']}")
            print(f"           Sequence : {seq}")
    print(SEP2)
    print(f"  VALUE OF CORRELATION")
    print(SEP2)
    print(f"  Without correlation : {total_after_quality} separate alert lines to review")
    print(f"  With correlation    : {n_groups} groups — analyst focuses on "
          f"{n_multi + n_suspicious} actionable group(s)")
    print(f"  {alerts_in_multi} attack-chain alerts compressed into "
          f"{n_multi} readable story/stories")
    print(f"  {n_benign} benign/noise groups deprioritised automatically")
    print(f"{SEP}\n")

    return groups


def tag_with_mitre(groups):
    # ------------------------------------------------------------------ #
    # 1. MITRE ATT&CK lookup dictionary                                    #
    #                                                                      #
    # MAPPING TABLE (see audit notes below each entry):                    #
    #                                                                      #
    # alert_type          | Technique ID | Technique Name              | Tactic              | Status                    #
    # --------------------|--------------|------------------------------|---------------------|---------------------------#
    # PortScan            | T1595        | Active Scanning              | Reconnaissance      | Approximate mapping       #
    # Brute Force         | T1110        | Brute Force                  | Credential Access   | Direct mapping            #
    # Privilege Escalation| T1098        | Account Manipulation         | Persistence/PrivEsc | Approximate mapping       #
    # Data Exfiltration   | T1048        | Exfiltration Over Alt. Proto | Exfiltration        | Approximate mapping       #
    # DDoS                | T1498        | Network Denial of Service    | Impact              | Direct mapping            #
    # BENIGN              | N/A          | No MITRE tag                 | N/A                 | Not applicable            #
    # ------------------------------------------------------------------ #
    mitre_map = {
        # T1595 - Active Scanning (Tactic: Reconnaissance / TA0043)
        # Status: Approximate mapping.
        # "PortScan" describes active probing of ports/services on a target.
        # T1595 is the correct technique family; sub-technique T1595.002
        # (Vulnerability Scanning) is more precise but requires sub-technique
        # resolution not supported in this pipeline. T1595 parent is defensible.
        "PortScan":             "T1595 - Active Scanning",

        # T1110 - Brute Force (Tactic: Credential Access / TA0006)
        # Status: Direct mapping.
        # The alert label "Brute Force" is textually and behaviourally
        # identical to the MITRE technique name. Strongest mapping in the set.
        "Brute Force":          "T1110 - Brute Force",

        # T1098 - Account Manipulation (Tactic: Persistence + Privilege Escalation / TA0003 + TA0004)
        # Status: Approximate mapping.
        # IMPORTANT: "Privilege Escalation" is a TACTIC (TA0004) in ATT&CK,
        # NOT a technique. This alert represents an admin-rights grant event.
        # T1098 (Account Manipulation — modifying account settings to maintain
        # or elevate access) is the closest single technique for that behaviour,
        # but it does not cover all privilege escalation methods.
        # Do NOT treat this tag as equivalent to the TA0004 tactic category.
        "Privilege Escalation": "T1098 - Account Manipulation",

        # T1048 - Exfiltration Over Alternative Protocol (Tactic: Exfiltration / TA0010)
        # Status: Approximate mapping.
        # CORRECTED from old mapping of T1005 (Data from Local System).
        # T1005 is a COLLECTION technique (TA0009) — it describes staging data
        # locally BEFORE sending it out. "Data Exfiltration" (large outbound
        # transfer) belongs to the Exfiltration tactic (TA0010), not Collection.
        # T1048 covers exfiltration over non-standard/alternative channels and
        # is the most defensible general mapping for an "outbound transfer" alert
        # without more protocol-specific context.
        "Data Exfiltration":    "T1048 - Exfiltration Over Alternative Protocol",

        # T1498 - Network Denial of Service (Tactic: Impact / TA0040)
        # Status: Direct mapping.
        # "DDoS" (Distributed Denial of Service) is a direct behavioural match
        # to T1498. Sub-techniques T1498.001/.002 exist but the parent is
        # appropriate without sub-technique resolution.
        "DDoS":                 "T1498 - Network Denial of Service",

        # No MITRE tag — normal/benign traffic has no ATT&CK technique.
        "BENIGN":               "No MITRE tag (normal traffic)",
    }

    # ------------------------------------------------------------------ #
    # 2 & 3. Tag each group's alert sequence                               #
    # ------------------------------------------------------------------ #
    tagged_groups = []
    for grp in groups:
        tagged_sequence = [
            mitre_map.get(alert, "Unmapped")   # step 3: default to "Unmapped"
            for alert in grp["alert_types"]
        ]
        tagged_groups.append({
            "source_ip":       grp["source_ip"],
            "start_time":      grp["start_time"],
            "end_time":        grp["end_time"],
            "count":           grp["count"],
            "original_types":  grp["alert_types"],
            "tagged_sequence": tagged_sequence,
        })

    # ------------------------------------------------------------------ #
    # 4. Print MITRE-tagged output                                         #
    # ------------------------------------------------------------------ #
    print(f"\n{'='*70}")
    print("  MITRE ATT&CK TAGGED GROUPS")
    print(f"{'='*70}")

    for i, grp in enumerate(tagged_groups, start=1):
        sequence_str = " -> ".join(grp["tagged_sequence"])
        print(
            f"\nGroup {i:>3} (IP: {grp['source_ip']}):\n"
            f"          {sequence_str}"
        )

    print(f"\n{'='*70}\n")
    return tagged_groups


def score_and_forecast(tagged_groups):
    # ------------------------------------------------------------------ #
    # PART 1 — RISK SCORING                                                #
    #                                                                      #
    # Weights and reasons come entirely from the module-level              #
    # TECHNIQUE_SCORES dict — no local copies.                             #
    # Deduplication: each technique code is counted at most once per       #
    # group. If the same technique appears twice (e.g. two port scans)     #
    # it only adds points once. This prevents score inflation from         #
    # repeated alerts and keeps MAX_SCORE meaningful.                      #
    # ------------------------------------------------------------------ #

    # ------------------------------------------------------------------ #
    # PART 2 — KNOWLEDGE-BASED FORECASTING                                 #
    # Uses the module-level FORECAST_KB via get_forecast().                #
    # No forecast dict is defined here — all rules live in FORECAST_KB.   #
    # ------------------------------------------------------------------ #

    # ------------------------------------------------------------------ #
    # Process each group                                                   #
    # ------------------------------------------------------------------ #
    results = []

    for grp in tagged_groups:
        total_score  = 0
        seen_codes   = []   # ordered list of unique codes that scored (dedup)
        why_items    = []   # list of (code, pts, reason) tuples

        # Track which codes have already been counted in this group
        counted = set()

        for tag in grp["tagged_sequence"]:
            # Extract technique code (first 5 chars, e.g. "T1595")
            code = tag[:5] if tag[:1] == "T" else None

            if code and code in TECHNIQUE_SCORES and code not in counted:
                pts, _, reason = TECHNIQUE_SCORES[code]
                total_score += pts
                seen_codes.append(code)
                why_items.append((code, pts, reason))
                counted.add(code)
            # Techniques already counted, "No MITRE tag", and "Unmapped"
            # contribute 0 additional points.

        # Validate: score must never exceed MAX_SCORE
        validate_score(total_score)

        level    = classify_score(total_score)
        bdl      = score_breakdown_lines(seen_codes)

        # Forecast via FORECAST_KB — returns structured dict, not raw strings
        forecast = get_forecast(grp["tagged_sequence"])

        results.append({
            "source_ip":   grp["source_ip"],
            "score":       total_score,
            "level":       level,
            "why_items":   why_items,    # (code, pts, reason) — for breakdown
            "breakdown":   bdl,          # formatted breakdown lines
            "forecast":    forecast,     # structured dict from FORECAST_KB
            "tagged_seq":  grp["tagged_sequence"],
        })

    # ------------------------------------------------------------------ #
    # Print results                                                         #
    # ------------------------------------------------------------------ #
    print(f"\n{'='*70}")
    print(f"  RISK SCORING & FORECAST REPORT  (max score: {MAX_SCORE})")
    print(f"  Explainable risk-prioritization score — NOT CVSS")
    print(f"{'='*70}")

    for i, r in enumerate(results, start=1):
        seq_str = " -> ".join(r["tagged_seq"])
        fc      = r["forecast"]
        print(f"\n--- Group {i} | IP: {r['source_ip']} ---")
        print(f"  Sequence   : {seq_str}")
        print(f"  Risk Score : {r['score']}/{MAX_SCORE}  ({r['level']})")
        print(f"  Breakdown  :")
        for line in r["breakdown"]:
            print(f"  {line}")
        print(f"  Why        :")
        if r["why_items"]:
            for code, pts, reason in r["why_items"]:
                print(f"               • [{code}] {reason}")
        else:
            print(f"               • No threat indicators in this group")
        print(f"  Knowledge-Based Forecast — Not ML Prediction")
        print(f"  Observed last : {fc['observed_technique']}")
        print(f"  Why forecast  : {fc['why_this_forecast']}")
        for nt in fc["next_techniques"]:
            print(f"               • {nt['wording']}")
            print(f"                 Source: {nt['source']}")

    print(f"\n{'='*70}\n")
    return results


def generate_report(scored_results, tagged_groups, output_file="final_report.txt"):
    """
    Generates BLUF-style threat reports from scored + tagged group data.

    Language rules (enforced throughout):
      - Never claim an attack definitively occurred unless the data proves it.
      - Use: "indicates suspicious activity", "consistent with a possible
        multi-stage attack", "requires investigation".
      - Never invent usernames, machines, files, credentials, or business impact
        that do not exist in the dataset.
      - Scores are an explainable risk-prioritization tool — NOT CVSS.
      - Forecasts are knowledge-based — NOT ML predictions.
    """
    from datetime import timedelta as _td

    # ------------------------------------------------------------------ #
    # BOTTOM LINE templates — keyed by (risk_level, last_technique_code)   #
    # Language: cautious, evidence-based. No invented facts.               #
    # ------------------------------------------------------------------ #
    bottom_line_templates = {
        ("HIGH", "T1048"): (
            "Alert data from this IP indicates suspicious activity consistent with "
            "a possible multi-stage attack sequence: reconnaissance, credential "
            "access attempts, account manipulation, and outbound data transfer "
            "were all observed. This requires immediate investigation and containment."
        ),
        ("HIGH", "T1098"): (
            "Alert data indicates suspicious activity consistent with credential "
            "access followed by account manipulation from this source IP. "
            "Possible privilege escalation requires investigation — outbound data "
            "transfer activity should be reviewed as a plausible follow-on risk."
        ),
        ("HIGH", "T1498"): (
            "High-volume traffic consistent with a denial-of-service attempt was "
            "observed from this IP. This requires investigation to determine whether "
            "concurrent intrusion activity may be masked by the traffic flood."
        ),
        ("MEDIUM", "T1498"): (
            "Repeated credential access attempts were observed from this IP, followed "
            "by high-volume traffic consistent with a denial-of-service attempt. "
            "This pattern may indicate a distraction-and-intrusion combination — "
            "review concurrent activity on other hosts during the flood window."
        ),
        ("MEDIUM", "T1110"): (
            "Repeated authentication failure patterns consistent with a brute-force "
            "attempt were observed from this IP. No confirmed credential compromise "
            "in this dataset — further investigation is required."
        ),
        ("MEDIUM", "T1595"): (
            "Port scanning activity was observed from this IP, indicating possible "
            "reconnaissance. No confirmed intrusion attempt in this dataset — "
            "monitor for follow-on credential or exploitation activity."
        ),
        ("LOW", None): (
            "No significant threat indicators were found in this group. "
            "Continue standard monitoring."
        ),
    }

    # ------------------------------------------------------------------ #
    # RECOMMENDED ACTIONS — keyed by (risk_level, last_technique_code)    #
    # Actions are based on observed data only — no invented context.       #
    # ------------------------------------------------------------------ #
    recommended_actions = {
        ("HIGH", "T1048"): [
            "Block this source IP at the perimeter firewall pending investigation.",
            "Review outbound network transfers from this host during the observed "
            "time window and assess whether sensitive data may have been involved.",
            "Audit authentication and account-change logs for the period covered "
            "by this alert group.",
        ],
        ("HIGH", "T1098"): [
            "Block this source IP at the perimeter firewall pending investigation.",
            "Review account change logs on systems reachable from this IP during "
            "the observed time window.",
            "Preserve authentication and privilege-change logs for forensic review.",
        ],
        ("HIGH", "T1498"): [
            "Engage upstream provider to rate-limit or null-route this source IP.",
            "Review logs of other hosts during the flood window for signs of "
            "concurrent intrusion activity.",
            "Activate DDoS mitigation controls if not already in place.",
        ],
        ("MEDIUM", "T1498"): [
            "Activate or verify DDoS mitigation controls for this source IP.",
            "Review authentication logs on targeted services during the time window "
            "to determine whether the brute-force component succeeded.",
            "Inspect logs of other hosts during the flood window for signs of "
            "concurrent intrusion or lateral movement activity.",
        ],
        ("MEDIUM", "T1110"): [
            "Review authentication logs for the targeted service during this time "
            "window to determine whether any login succeeded.",
            "Consider temporarily restricting access from this IP if the pattern "
            "continues.",
            "Enable or verify multi-factor authentication on the targeted service.",
        ],
        ("MEDIUM", "T1595"): [
            "Review firewall logs for this source IP and assess whether follow-on "
            "activity was observed.",
            "Audit exposed services identified during the scan window and close "
            "any that are not required.",
        ],
        ("LOW", None): [
            "No immediate action required based on available data.",
            "Continue routine monitoring.",
        ],
    }

    def _get_last_code(tagged_seq):
        """Return the last scored MITRE technique code, or None."""
        for tag in reversed(tagged_seq):
            code = tag[:5] if tag[:1] == "T" else None
            if code and code in TECHNIQUE_SCORES:
                return code
        return None

    def _get_bottom_line(level, last_code):
        key = (level, last_code)
        if key in bottom_line_templates:
            return bottom_line_templates[key]
        if level == "HIGH":
            return (
                "Multiple high-severity alert types were observed from this source IP "
                "within a short time window. This is consistent with suspicious activity "
                "and requires immediate investigation."
            )
        if level == "MEDIUM":
            return (
                "Suspicious alert activity was observed from this source IP. "
                "Review the timeline and assess whether further action is warranted."
            )
        return bottom_line_templates[("LOW", None)]

    def _get_actions(level, last_code):
        key = (level, last_code)
        if key in recommended_actions:
            return recommended_actions[key]
        if level == "HIGH":
            return [
                "Block this source IP at the perimeter firewall pending investigation.",
                "Review logs for affected systems during the observed time window.",
                "Preserve logs for forensic review.",
            ]
        if level == "MEDIUM":
            return [
                "Monitor this IP for further suspicious activity.",
                "Review logs for the affected service during this time window.",
            ]
        return recommended_actions[("LOW", None)]

    def _interpolated_times(start_ts, end_ts, n):
        """
        Return a list of n timestamps evenly spaced between start_ts and end_ts.
        Used only when per-alert timestamps are not available at this stage
        of the pipeline. Labelled as approximate in the report.
        """
        if n <= 1:
            return [start_ts]
        step = int((end_ts - start_ts).total_seconds() / (n - 1))
        return [start_ts + _td(seconds=i * step) for i in range(n)]

    # ------------------------------------------------------------------ #
    # Build one report block per result                                    #
    # MAX_SCORE is the module-level computed constant — not overridden.    #
    # ------------------------------------------------------------------ #
    BORDER   = "=" * 60
    DIVIDER  = "-" * 60

    all_reports = []

    for result, grp in zip(scored_results, tagged_groups):
        ip         = result["source_ip"]
        score      = result["score"]
        level      = result["level"]
        why_items  = result["why_items"]     # [(code, pts, reason), ...]
        breakdown  = result["breakdown"]     # pre-formatted score lines
        forecast   = result["forecast"]      # FORECAST_KB structured dict
        tagged_seq = result["tagged_seq"]
        last_code  = _get_last_code(tagged_seq)

        start_ts   = grp["start_time"]
        end_ts     = grp["end_time"]
        n          = len(tagged_seq)
        alert_count = grp.get("count", n)

        # Duration string
        dur_secs = int((end_ts - start_ts).total_seconds())
        if dur_secs >= 3600:
            dur_str = f"{dur_secs // 3600}h {(dur_secs % 3600) // 60}m {dur_secs % 60}s"
        elif dur_secs >= 60:
            dur_str = f"{dur_secs // 60}m {dur_secs % 60}s"
        else:
            dur_str = f"{dur_secs}s"

        # Distinct technique codes (scored only)
        distinct_codes = [
            tag[:5] for tag in tagged_seq
            if tag[:1] == "T" and tag[:5] in TECHNIQUE_SCORES
        ]
        distinct_codes_unique = list(dict.fromkeys(distinct_codes))  # ordered dedup

        # Interpolated timestamps (best available — per-alert times not
        # carried through tag_with_mitre; labelled approximate below)
        step_times = _interpolated_times(start_ts, end_ts, n)

        # Max gap between consecutive interpolated events
        gaps = []
        for j in range(1, len(step_times)):
            gaps.append(int((step_times[j] - step_times[j - 1]).total_seconds()))
        max_gap_secs = max(gaps) if gaps else 0
        if max_gap_secs >= 60:
            max_gap_str = f"{max_gap_secs // 60}m {max_gap_secs % 60}s"
        else:
            max_gap_str = f"{max_gap_secs}s"

        # Attack chain (arrow-joined technique names, no codes)
        chain_parts = []
        for tag in tagged_seq:
            if " - " in tag and tag[:1] == "T":
                chain_parts.append(tag.split(" - ", 1)[1])
            else:
                chain_parts.append(tag)
        attack_chain = " → ".join(chain_parts)

        # Timeline lines (approximate timestamps)
        timeline_lines = []
        for idx, (tag, ts) in enumerate(zip(tagged_seq, step_times)):
            if " - " in tag and tag[:1] == "T":
                code_part, name_part = tag.split(" - ", 1)
            else:
                code_part, name_part = "N/A", tag
            timeline_lines.append(
                f"  {ts.strftime('%Y-%m-%d %H:%M:%S')}  {code_part:<6}  {name_part}"
            )

        bottom_line = _get_bottom_line(level, last_code)
        actions     = _get_actions(level, last_code)

        # ── Assemble the report block ──────────────────────────────── #
        lines = [
            BORDER,
            f"THREAT REPORT — IP: {ip}",
            BORDER,
            f"RISK LEVEL : {level}",
            f"SCORE      : {score}/{MAX_SCORE}  "
            f"(Explainable risk-prioritization score — NOT CVSS)",
            "",
            "BOTTOM LINE:",
            f"  {bottom_line}",
            "",
            DIVIDER,
            "ATTACK CHAIN:",
            f"  {attack_chain}",
            "",
            "TIMELINE:  (timestamps approximate — evenly interpolated from",
            f"            group start {start_ts.strftime('%H:%M:%S')} to"
            f" end {end_ts.strftime('%H:%M:%S')})",
        ]
        lines += timeline_lines
        lines += [
            "",
            DIVIDER,
            "WHY THIS SCORE:",
        ]
        if why_items:
            for code, pts, reason in why_items:
                lines.append(f"  {code}  {pts:>2} pts  — {reason}")
            lines += [
                f"  {'-'*40}",
                f"  Total  {score:>2}/{MAX_SCORE}",
                "",
                f"  Note: {len(distinct_codes_unique)} distinct technique(s) observed from the "
                f"same source IP within {dur_str}.",
                "  Co-occurrence of multiple techniques in a short time window",
                "  increases the significance of this group.",
            ]
        else:
            lines.append("  No scored threat indicators in this group.")
        lines += [
            "",
            DIVIDER,
            "CORRELATION EVIDENCE:",
            f"  Source IP              : {ip}",
            f"  Total alerts in group  : {alert_count}",
            f"  Group time span        : {start_ts.strftime('%Y-%m-%d %H:%M:%S')}"
            f" — {end_ts.strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Duration               : {dur_str}",
            f"  Distinct techniques    : {len(distinct_codes_unique)}  "
            f"({', '.join(distinct_codes_unique)})",
            f"  Max gap between events : {max_gap_str}  (interpolated)",
            "  Correlation rule       : same source_ip + gap ≤ 10 minutes",
        ]
        lines += [
            "",
            DIVIDER,
            "KNOWLEDGE-BASED FORECAST — NOT ML PREDICTION:",
            f"  Observed last technique : {forecast['observed_technique']}",
        ]
        lines += [
            "",
            "WHY THIS FORECAST:",
            f"  {forecast['why_this_forecast']}",
            "",
            "  Plausible follow-on activity (documented ATT&CK relationships only):",
        ]
        for nt in forecast["next_techniques"]:
            lines.append(f"  • {nt['wording']}")
            lines.append(f"    Reference: {nt['source']}")
        lines += [
            "",
            DIVIDER,
            "RECOMMENDED ACTION:",
        ]
        for idx, a in enumerate(actions, start=1):
            lines.append(f"  {idx}. {a}")
        lines.append(BORDER)

        all_reports.append("\n".join(lines))

    full_output = "\n\n".join(all_reports)

    # ── Print to console ──────────────────────────────────────────────── #
    print(full_output)

    # ── Save to file ──────────────────────────────────────────────────── #
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(full_output)
        f.write("\n")

    print(f"\n[Saved] All {len(all_reports)} report(s) written to '{output_file}'")
    return all_reports


def generate_json_export(scored_results, tagged_groups, output_file="threat_export.json"):
    """
    Exports the full pipeline results to a structured JSON file.

    Each entry in the output corresponds to one correlated group and contains:
      source_ip         — originating IP address
      risk_level        — HIGH / MEDIUM / LOW
      score             — numeric risk score
      max_score         — MAX_SCORE constant (computed, not hand-typed)
      attack_chain      — list of MITRE technique strings in observed order
      last_technique    — last scored technique code (used for forecast lookup)
      score_breakdown   — list of {code, points, tactic, reason} dicts
      forecast          — structured dict from FORECAST_KB
      group_start       — ISO-8601 start timestamp of the group
      group_end         — ISO-8601 end timestamp of the group
      duration_secs     — integer seconds from first to last alert in group
      alert_count       — number of raw alerts in the group

    The file is UTF-8 encoded JSON (indent=2). No ML data, no invented fields.
    Every value traces directly to pipeline output.
    """
    import json

    def _get_last_code(tagged_seq):
        for tag in reversed(tagged_seq):
            code = tag[:5] if tag[:1] == "T" else None
            if code and code in TECHNIQUE_SCORES:
                return code
        return None

    export_rows = []

    for result, grp in zip(scored_results, tagged_groups):
        ip         = result["source_ip"]
        score      = result["score"]
        level      = result["level"]
        why_items  = result["why_items"]     # [(code, pts, reason), ...]
        forecast   = result["forecast"]
        tagged_seq = result["tagged_seq"]
        last_code  = _get_last_code(tagged_seq)

        start_ts   = grp["start_time"]
        end_ts     = grp["end_time"]
        dur_secs   = int((end_ts - start_ts).total_seconds())

        score_breakdown = [
            {
                "technique_code": code,
                "points":         pts,
                "tactic":         TECHNIQUE_SCORES[code][1],
                "reason":         reason,
            }
            for code, pts, reason in why_items
        ]

        # Forecast: keep structured data, strip Python-only fields
        forecast_export = {
            "observed_technique": forecast["observed_technique"],
            "why_this_forecast":  forecast["why_this_forecast"],
            "is_fallback":        forecast["fallback"],
            "next_techniques": [
                {
                    "technique":   nt["technique"],
                    "explanation": nt["explanation"],
                    "wording":     nt["wording"],
                    "source":      nt["source"],
                }
                for nt in forecast["next_techniques"]
            ],
        }

        export_rows.append({
            "source_ip":       ip,
            "risk_level":      level,
            "score":           score,
            "max_score":       MAX_SCORE,
            "last_technique":  last_code,
            "attack_chain":    tagged_seq,
            "score_breakdown": score_breakdown,
            "forecast":        forecast_export,
            "group_start":     start_ts.isoformat(),
            "group_end":       end_ts.isoformat(),
            "duration_secs":   dur_secs,
            "alert_count":     grp.get("count", len(tagged_seq)),
        })

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(export_rows, f, indent=2, ensure_ascii=False)

    print(f"\n[Saved] JSON export ({len(export_rows)} group(s)) → '{output_file}'")
    return export_rows


if __name__ == "__main__":
    groups        = correlate_alerts()
    tagged_groups = tag_with_mitre(groups)
    # score_and_forecast operates on all 184 groups; generate_report only
    # needs the 4 attack chains — filter for groups with count > 1 and
    # a HIGH/MEDIUM score, or simply pass all and let the templates decide.
    all_scored    = score_and_forecast(tagged_groups)

    # Extract only attack-chain groups (score > MEDIUM floor, multi-step).
    # Uses TECHNIQUE_SCORES keys — no hardcoded technique list.
    attack_scored  = [r for r in all_scored if r["score"] > 5]
    attack_tagged  = [g for g in tagged_groups
                      if len(g["tagged_sequence"]) > 1
                      and any(
                          (t[:5] if t[:1] == "T" else None) in TECHNIQUE_SCORES
                          for t in g["tagged_sequence"]
                      )]

    generate_report(attack_scored, attack_tagged)
    generate_json_export(attack_scored, attack_tagged)
