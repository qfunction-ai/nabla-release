/**
 * The 29 numbered detection methods + 7 supplementary layers.
 *
 * Content source: docs/detection-methods.md — extracted from
 * nabla/detection.py, gcn_lof.py, exfiltration.py, provenance.py,
 * temporal.py, and rl/thresholds.py (2026-09-02). Numbers are code
 * defaults, never from memory. README names and code type strings
 * differ in places (typeLabel carries the string incidents display).
 */

export type MethodCategory = 'statistical' | 'endpoint' | 'advanced' | 'entity';

export interface DetectionMethod {
  number: number;
  name: string;
  typeLabel: string;
  category: MethodCategory;
  fn: string;
  logs: string[];
  catches: string;
  how: string[];
  tunable: { name: string; default: string }[];
  fp: string;
  baseline: boolean;
}

export interface SupplementaryLayer {
  name: string;
  summary: string;
  attck?: string[];
}

export const CATEGORY_LABELS: Record<MethodCategory, string> = {
  statistical: 'Statistical & Rule-Based (1–6)',
  endpoint: 'Endpoint Behavior (7–11)',
  advanced: 'Advanced Endpoint (12–20)',
  entity: 'Entity-Specific (21–29)',
};

export const DETECTION_METHODS: DetectionMethod[] = [
  {
    number: 1,
    name: 'Pre-flagged',
    typeLabel: 'pre_flagged',
    category: 'statistical',
    fn: 'detection.py §1',
    logs: ['any'],
    catches: 'Anomalies the log source itself already tagged (e.g. EDR verdicts), passed through as Nabla anomalies.',
    how: [
      'Any entry with a truthy anomaly field becomes an anomaly of this type at medium severity, copying details, user, source IP and timestamp verbatim.',
      'No statistics involved — Nabla trusts the upstream verdict.',
    ],
    tunable: [],
    fp: 'Whatever the upstream source flags; Nabla adds no filter of its own.',
    baseline: true,
  },
  {
    number: 2,
    name: 'Z-score spike',
    typeLabel: 'z_score_spike',
    category: 'statistical',
    fn: 'detection.py §2',
    logs: ['all'],
    catches: 'A user generating far more events than the batch average — beaconing, scripted activity, mass recon.',
    how: [
      'Computes per-user event counts, batch mean and population std (needs ≥2 users).',
      'Flags when z = (count − mean)/std exceeds the RL-tuned sigma (default 2.0); severity high when z > threshold + 1.0. Users in new_accounts are skipped.',
      'If an entity profile is warm (≥3 observations), this same block emits the entity variant (#21) instead.',
    ],
    tunable: [{ name: 'z_score_sigma', default: '2.0' }],
    fp: 'Genuinely high-volume users (service accounts, admins) on a quiet network inflate z; the entity-baseline path exists to suppress this.',
    baseline: false,
  },
  {
    number: 3,
    name: 'Brute force',
    typeLabel: 'brute_force_attempt',
    category: 'statistical',
    fn: 'detection.py §3 (failed_login_ratio)',
    logs: ['auth'],
    catches: 'Password guessing / spraying against accounts.',
    how: [
      'Counts login_success vs login_failure per user; requires ≥3 total auth events.',
      'Flags when the failure ratio exceeds the RL-tuned threshold (default 0.5) at high severity.',
      'If the user\u2019s entity profile has auth-failure-ratio variance, the entity variant (#22) takes precedence and this global check is skipped.',
    ],
    tunable: [{ name: 'brute_force_ratio', default: '0.5' }],
    fp: 'Expired/rotated credentials and service accounts with hard-coded bad passwords produce high failure ratios.',
    baseline: false,
  },
  {
    number: 4,
    name: 'Off-hours activity',
    typeLabel: 'off_hours',
    category: 'statistical',
    fn: 'detection.py §4',
    logs: ['all'],
    catches: 'Activity during the 22:00–06:00 UTC window when nobody should be working.',
    how: [
      'Parses HH from each timestamp; counts a user\u2019s events with hour < 6 or ≥ 22.',
      'Flags when that count reaches the RL-tuned minimum (default 3) at medium severity.',
      'With a warm entity profile, the entity variant (#23) instead flags hours outside the user\u2019s own typical_hours using the same count threshold.',
    ],
    tunable: [{ name: 'off_hours_count', default: '3' }],
    fp: 'Night-shift staff, global timezone offsets, and batch jobs — the fixed UTC window ignores local business hours (entity baselines fix this once warm).',
    baseline: false,
  },
  {
    number: 5,
    name: 'Impossible travel',
    typeLabel: 'multiple_source_ips',
    category: 'statistical',
    fn: 'detection.py §5 (multi_ip)',
    logs: ['auth', 'network', 'dns'],
    catches: 'One account appearing from many distinct addresses — credential sharing, proxying, or hijacked logins.',
    how: [
      'Collects routable source IPs per user; flags when the unique-IP count reaches the RL-tuned minimum (default 3) at high severity.',
      'Despite the name there is no geo/velocity math — it is a pure distinct-IP-count heuristic; the alert lists all IPs.',
      'Warm entity profiles switch this to the entity variant (#24: IPs new to this user).',
    ],
    tunable: [{ name: 'multi_ip_count', default: '3' }],
    fp: 'Road warriors, VPN pools, CGNAT, and CDNs legitimately inflate distinct-IP counts.',
    baseline: false,
  },
  {
    number: 6,
    name: 'Activity spike',
    typeLabel: 'activity_spike',
    category: 'statistical',
    fn: 'detection.py §6',
    logs: ['all'],
    catches: 'A sudden burst of activity from one user relative to the population mean.',
    how: [
      'Flags when a user\u2019s event count exceeds batch mean × the RL-tuned multiplier (default 3.0) at high severity; new_accounts are skipped.',
      'With a warm entity profile the comparison becomes count > the user\u2019s own EWMA × multiplier (#25).',
    ],
    tunable: [{ name: 'spike_multiplier', default: '3.0' }],
    fp: 'Month-end/quarter-end processing, ticket storms, and newly onboarded heavy users (mitigated by the new_accounts skip).',
    baseline: false,
  },
  {
    number: 7,
    name: 'LOLBIN abuse',
    typeLabel: 'lolbin_abuse',
    category: 'endpoint',
    fn: 'detection.py §7 (lolbin)',
    logs: ['endpoint'],
    catches: 'Living-off-the-land binary abuse — certutil/mshta/regsvr32/powershell etc. used to download, decode, or execute.',
    how: [
      'Matches process names against LOLBIN signatures (from the lolbin_db shared block, else a 9-entry fallback), then counts suspicious command-line substrings (urlcache, -enc, iex, /i:http, …).',
      'Pattern-match requirements scale with the RL-tuned sensitivity: 1 at default 0.7, 0 at ≥0.9 (name alone fires), 2 at <0.5.',
      'Processes under legitimate tool paths (SplunkUniversalForwarder, Program Files\\Microsoft) are skipped. High severity with MITRE IDs from the signature.',
    ],
    tunable: [{ name: 'lolbin_sensitivity', default: '0.7' }],
    fp: 'Legit admin scripts using -enc or iex, and software updates invoking bitsadmin from non-allowlisted paths.',
    baseline: true,
  },
  {
    number: 8,
    name: 'Suspicious parent-child',
    typeLabel: 'suspicious_parent_child',
    category: 'endpoint',
    fn: 'detection.py §8 (parent_child)',
    logs: ['endpoint'],
    catches: 'Office/browser/PDF readers spawning shells — the classic macro or drive-by payload.',
    how: [
      'Parent stem must be in the suspicious-parents set (winword, excel, powerpnt, outlook, acrobat, chrome, firefox, …) and child in the suspicious-children set (LOLBINs plus cmd, powershell, bash, python, perl).',
      'At default sensitivity 0.7 the pair alone fires at high; at <0.5 it additionally requires a suspicious command token (http://, -enc, iex, bypass, base64, …).',
    ],
    tunable: [{ name: 'parent_child_sensitivity', default: '0.7' }],
    fp: 'Office add-ins and document generators that legitimately shell out; browsers opening helper processes.',
    baseline: true,
  },
  {
    number: 9,
    name: 'Critical host escalation',
    typeLabel: 'critical_host_escalation',
    category: 'endpoint',
    fn: 'detection.py §9',
    logs: ['endpoint'],
    catches: 'Privilege-escalation commands on domain controllers, build, prod, or finance systems.',
    how: [
      'Critical hosts come from watchlist.hosts, else hostnames containing DC/DOMAIN/BUILD/PROD/FINANCE.',
      'Three tiers: (a) escalation commands or sudo/su/runas/psexec processes → critical; (b) UAC-bypass parents (fodhelper, eventvwr, …) spawning suspicious children → high; (c) at sensitivity ≥0.9, any execute by a non-admin user → medium.',
      'At sensitivity <0.5, non-critical findings are dropped.',
    ],
    tunable: [{ name: 'critical_host_sensitivity', default: '0.7' }],
    fp: 'Named admin accounts doing scheduled maintenance; tier (c) at 0.9 fires on every non-admin execution on a critical box.',
    baseline: true,
  },
  {
    number: 10,
    name: 'Unusual process per host',
    typeLabel: 'unusual_process_per_host',
    category: 'endpoint',
    fn: 'detection.py §10 (unusual_process)',
    logs: ['endpoint'],
    catches: 'A process appearing on a host for the first time — new tooling, implants, persistence.',
    how: [
      'Builds per-host process-name sets for the run and diffs against historical baselines: the host profile\u2019s typical_processes when warm, else baseline_host_procs from archival memory.',
      'Common processes (explorer, svchost, lsass, …) are excluded at sensitivity ≥0.5; below 0.5 only LOLBIN-named processes are considered.',
      'If no baseline map exists at all, nothing is flagged.',
    ],
    tunable: [{ name: 'unusual_process_sensitivity', default: '0.5' }],
    fp: 'Legitimate software installs/updates push many "new" process names at once — the entity-baseline path thresholds on a count to absorb this.',
    baseline: false,
  },
  {
    number: 11,
    name: 'Rapid action sequence',
    typeLabel: 'rapid_action_sequence',
    category: 'endpoint',
    fn: 'detection.py §11 (action_sequence)',
    logs: ['endpoint'],
    catches: 'Create → execute → delete compressed into minutes — dropper execution followed by artifact cleanup.',
    how: [
      'Actions come from the action field or are derived from the command line (echo/>/copy → create; del/rm → delete; else execute).',
      'Requires all three action types with ≥3 parseable timestamps; flags when the span is within the RL-tuned window (default 30 minutes) at high severity.',
    ],
    tunable: [{ name: 'action_sequence_window_minutes', default: '30' }],
    fp: 'Developer build/clean cycles and packaging scripts naturally do create-run-delete inside half an hour.',
    baseline: true,
  },
  {
    number: 12,
    name: 'GCN-LOF',
    typeLabel: 'gcn_lof_anomaly',
    category: 'advanced',
    fn: 'gcn_lof.py GCNLOFDetector.detect()',
    logs: ['all'],
    catches: 'Events that are outliers both in feature space and in their neighborhood on the event graph — compound anomalies no single rule sees.',
    how: [
      'Encodes each event as 23 features (one-hot log type and action, sin/cos hour, binary flags from earlier detectors, normalized counts), computes Local Outlier Factor (n_neighbors=20) as feature 24.',
      'Builds a cosine KNN graph (k=10) and trains a 2-layer GCN autoencoder to reconstruct its own inputs; score blends normalized LOF and reconstruction error via the RL-tuned alpha.',
      'Flags score above the RL-tuned threshold; high severity above 0.9. Skips batches <3 events; weights persist and fine-tune each run.',
    ],
    tunable: [
      { name: 'gcn_lof_alpha', default: '0.5' },
      { name: 'gcn_lof_threshold', default: '0.75' },
    ],
    fp: 'Rare-but-benign event shapes reconstruct poorly; scores are min-max normalized per batch, so a small batch always has a "worst" event.',
    baseline: true,
  },
  {
    number: 13,
    name: 'Known attack script',
    typeLabel: 'known_attack_script',
    category: 'advanced',
    fn: 'detection.py §10b (attack_script)',
    logs: ['endpoint'],
    catches: 'Named offensive tooling — Mimikatz, Rubeus, Cobalt Strike, Impacket, LinEnum, and ~800 more.',
    how: [
      'Primary source is the tool-name index built from the ATT&CK STIX bundle (800+ names), merged with a 47-entry fallback covering binary names (beacon.exe, msfvenom, godpotato).',
      'Word-boundary matched against command_line, target_file, and process via one pre-compiled regex. Critical severity with the tool\u2019s MITRE technique attached.',
    ],
    tunable: [],
    fp: 'Word-boundary collisions with innocuous substrings and security teams running the same tools in authorized tests.',
    baseline: true,
  },
  {
    number: 14,
    name: 'Renamed attack tool',
    typeLabel: 'renamed_attack_tool',
    category: 'advanced',
    fn: 'detection.py §10d (renamed_tool)',
    logs: ['endpoint'],
    catches: 'Attack tools whose binary was renamed — identified by command-line fingerprint instead of filename.',
    how: [
      '~47 fixed signature substrings (asktgt, kerberoast, sekurlsa::logonpasswords, lsadump::dcsync, cobaltstrike.jar, privilege::debug, …) matched in command_line.',
      'A hit is suppressed when the process name already contains the tool name — that is #13\u2019s job. Critical severity, MITRE ID per signature.',
    ],
    tunable: [],
    fp: 'Documentation, training material, or pentest reports pasted into command lines containing the same tokens.',
    baseline: true,
  },
  {
    number: 15,
    name: 'Suspicious file path',
    typeLabel: 'suspicious_file_path',
    category: 'advanced',
    fn: 'detection.py §12 (suspicious_path)',
    logs: ['endpoint'],
    catches: 'Executables running from staging locations attackers love — PerfLogs, AppData, Public, Temp, Downloads, or suspiciously shallow paths.',
    how: [
      'Process path regex-matched against 8 patterns plus a shallow-path rule (2–3 directory levels below the drive root — legit software installs deeper).',
      'Legitimate paths (Windows\\System32, Program Files, winsxs, …) are skipped; at sensitivity <0.5 at least 2 patterns must match.',
      'Severity high with ≥2 matches, medium otherwise.',
    ],
    tunable: [{ name: 'suspicious_path_sensitivity', default: '0.7' }],
    fp: 'User-installed portable apps, browser downloads executed from Downloads, and installers that unpack to Temp.',
    baseline: true,
  },
  {
    number: 16,
    name: 'Enumeration behavior',
    typeLabel: 'enumeration_behavior',
    category: 'advanced',
    fn: 'detection.py §10c',
    logs: ['endpoint'],
    catches: 'Host/AD/credential enumeration performed by renamed or custom scripts — caught by behavior, not name.',
    how: [
      'Three independent sub-checks: (a) one parent spawning ≥10 distinct children within 5 minutes; (b) one process touching ≥3 distinct sensitive-path categories (/etc/shadow, ~/.ssh, ntds.dit, …); (c) a user+host issuing ≥3 distinct enumeration commands (74 patterns: net user, whoami /all, reg query hklm, …).',
      'Thresholds double at sensitivity <0.7. All fire at high severity with T1082 plus T1057/T1005/T1059.',
    ],
    tunable: [{ name: 'enumeration_sensitivity', default: '0.7' }],
    fp: 'Inventory/CM agents, admin "check everything" scripts, and build systems that touch many sensitive paths in sequence.',
    baseline: true,
  },
  {
    number: 17,
    name: 'Integrity anomaly',
    typeLabel: 'integrity_anomaly',
    category: 'advanced',
    fn: 'detection.py §13',
    logs: ['endpoint'],
    catches: 'SYSTEM/high-integrity processes spawned by ordinary parents — token theft, service exploit, or UAC bypass.',
    how: [
      'Requires integrity_level ∈ {system, high} or NT AUTHORITY\\SYSTEM, and the parent\u2019s filename not in the SYSTEM_PARENTS allowlist (services, wininit, lsass, svchost, …).',
      'At sensitivity <0.5 the child must additionally be a LOLBIN name. High severity, reporting integrity level and parent.',
    ],
    tunable: [{ name: 'integrity_anomaly_sensitivity', default: '0.7' }],
    fp: 'Legitimate installers and deployment agents running elevated from non-allowlisted parents.',
    baseline: true,
  },
  {
    number: 18,
    name: 'Registry abuse',
    typeLabel: 'registry_abuse',
    category: 'advanced',
    fn: 'detection.py §14',
    logs: ['endpoint'],
    catches: 'Persistence and defense-evasion via high-value registry keys — Run/RunOnce, IFEO debugger injection, WINEVT channel config, service registration.',
    how: [
      'Only registry mutation events are considered. A hit requires the target to match critical patterns (CurrentVersion\\Run, RunOnce, IFEO, WINEVT\\Channels, Services\\) or — at sensitivity ≥0.5 — the writing process to live in a suspicious path.',
      'Legitimate-path processes are skipped unless sensitivity ≥0.9. High severity for critical keys, medium otherwise.',
    ],
    tunable: [{ name: 'registry_abuse_sensitivity', default: '0.7' }],
    fp: 'Software installers and GPO/endpoint agents legitimately writing Run keys and service entries.',
    baseline: true,
  },
  {
    number: 19,
    name: 'Network anomaly',
    typeLabel: 'network_anomaly',
    category: 'advanced',
    fn: 'detection.py §15',
    logs: ['endpoint'],
    catches: 'Outbound connections from processes that should never talk to the network — LOLBIN C2/download channels — or binaries dropped in staging paths.',
    how: [
      'Process stem checked against the network-LOLBIN list (certutil, mshta, regsvr32, bitsadmin, msbuild, msiexec, …) → high.',
      'Otherwise a process in a suspicious or shallow path → medium (dropped at sensitivity <0.5). Legitimate paths are skipped unless LOLBIN-listed.',
    ],
    tunable: [{ name: 'network_anomaly_sensitivity', default: '0.7' }],
    fp: 'Software updaters and license checks that legitimately phone home from temp/ProgramData paths.',
    baseline: true,
  },
  {
    number: 20,
    name: 'EWMA/CUSUM drift',
    typeLabel: 'ewma_drift / cusum_shift / cusum_drop',
    category: 'advanced',
    fn: 'detection.py §20-21 (two detectors)',
    logs: ['all'],
    catches: 'Gradual ramp-ups and sustained shifts in event rate that point z-scores miss — e.g. failed logins climbing 2→5→12 per interval.',
    how: [
      'Events binned per user into 5-minute bins (≥3 bins required).',
      'EWMA: flags a bin whose count exceeds the running average + 2.0σ — one high alert per user.',
      'CUSUM: reference mean/σ from the first half of bins; sustained positive drift past the decision limit → cusum_shift (high), negative → cusum_drop (medium).',
    ],
    tunable: [
      { name: 'ewma_sensitivity', default: '0.7' },
      { name: 'cusum_sensitivity', default: '0.7' },
    ],
    fp: 'Legitimate step changes — business-hours start, cron bursts, migration jobs — read as sustained shifts.',
    baseline: false,
  },
  {
    number: 21,
    name: 'Entity z-score',
    typeLabel: 'entity_event_count_spike',
    category: 'entity',
    fn: 'detection.py §2 (entity path)',
    logs: ['all'],
    catches: 'A user producing far more events than they usually do.',
    how: [
      'z-score of the run\u2019s event count against the profile\u2019s typical_event_count EWMA/std (profile needs ≥3 observations).',
      'Flags when z exceeds the RL-tuned sigma (default 2.0); high if z > threshold + 1.0. Replaces the batch z-score check when it fires.',
    ],
    tunable: [{ name: 'entity_event_count_sigma', default: '2.0' }],
    fp: 'Rare but legitimate busy days for a normally quiet user.',
    baseline: false,
  },
  {
    number: 22,
    name: 'Entity auth failure',
    typeLabel: 'entity_auth_failure_spike',
    category: 'entity',
    fn: 'detection.py §3 (entity path)',
    logs: ['auth'],
    catches: 'A user whose failure rate jumped relative to their own norm (normally 5%, now 60%) even if below the global 50% bar.',
    how: [
      'z-score of the current failure ratio against the profile\u2019s ratio EWMA (needs profile variance > 0).',
      'Flags when z exceeds the RL-tuned sigma (default 2.0) at high severity. Supersedes the global ratio check when it fires.',
    ],
    tunable: [{ name: 'entity_auth_failure_sigma', default: '2.0' }],
    fp: 'A single bad password cache flush after a credential rotation looks like a spike against a clean history.',
    baseline: false,
  },
  {
    number: 23,
    name: 'Entity off-hours',
    typeLabel: 'entity_off_hours_activity',
    category: 'entity',
    fn: 'detection.py §4 (entity path)',
    logs: ['all'],
    catches: 'Activity at hours this specific user never works — night-shift workers are no longer flagged.',
    how: [
      'Counts run events whose hour is absent from the user\u2019s typical_hours.',
      'Flags at the RL-tuned minimum count (default 3, shared with #4) at medium severity, reporting usual vs. unusual hour sets.',
    ],
    tunable: [{ name: 'off_hours_count', default: '3' }],
    fp: 'Schedule changes (new shift, travel) before the profile adapts.',
    baseline: false,
  },
  {
    number: 24,
    name: 'Entity new IP',
    typeLabel: 'entity_new_ip',
    category: 'entity',
    fn: 'detection.py §5 (entity path)',
    logs: ['auth', 'network', 'dns'],
    catches: 'An account surfacing from addresses it has never used — hijacked credentials or a new foothold.',
    how: [
      'New IPs = current routable IPs minus the profile\u2019s typical_ips.',
      'Flags when the count reaches the RL-tuned threshold (default 2); high at ≥3, else medium. Replaces the fixed multi-IP count check.',
    ],
    tunable: [{ name: 'entity_new_ip_threshold', default: '2' }],
    fp: 'VPN range changes, DHCP churn, and travel — anything that rotates the user\u2019s address pool.',
    baseline: false,
  },
  {
    number: 25,
    name: 'Entity activity spike',
    typeLabel: 'entity_activity_spike',
    category: 'entity',
    fn: 'detection.py §6 (entity path)',
    logs: ['all'],
    catches: 'A user suddenly several times busier than their own norm.',
    how: [
      'Flags when run event count exceeds profile EWMA × the RL-tuned multiplier (default 3.0, shared with #6) at high severity; new_accounts skipped.',
      'Replaces the batch-mean comparison.',
    ],
    tunable: [{ name: 'spike_multiplier', default: '3.0' }],
    fp: 'Periodic heavy workflows (month-end close) for a normally light user.',
    baseline: false,
  },
  {
    number: 26,
    name: 'Entity new process',
    typeLabel: 'entity_new_process',
    category: 'entity',
    fn: 'detection.py §10 (entity path)',
    logs: ['endpoint'],
    catches: 'A host suddenly running a batch of process names it has never run before.',
    how: [
      'Diffs the run\u2019s process names against the host profile\u2019s typical_processes (excluding common processes at sensitivity ≥0.5; at <0.5 only LOLBIN names count).',
      'Flags when the new count reaches the RL-tuned threshold (default 3); high at ≥2× the threshold, else medium.',
    ],
    tunable: [
      { name: 'entity_new_process_threshold', default: '3' },
      { name: 'unusual_process_sensitivity', default: '0.5' },
    ],
    fp: 'Patch Tuesday, software rollouts, and ephemeral tooling that legitimately introduces many new names.',
    baseline: false,
  },
  {
    number: 27,
    name: 'Entity unusual process',
    typeLabel: 'unusual_process_per_host',
    category: 'entity',
    fn: 'detection.py §10 (nested in #26)',
    logs: ['endpoint'],
    catches: 'A single new process on a host that is specifically a LOLBIN or known attack tool — high-signal subset of #26.',
    how: [
      'Iterates #26\u2019s new-process list and emits one high-severity alert per process matching a LOLBIN signature or the ATT&CK tool index — even when the bulk count threshold wouldn\u2019t fire on its own.',
      'Subject to the same sensitivity filtering as #26.',
    ],
    tunable: [{ name: 'unusual_process_sensitivity', default: '0.5' }],
    fp: 'Security tooling or admin utilities newly deployed that happen to share a name with a LOLBIN.',
    baseline: false,
  },
  {
    number: 28,
    name: 'Entity behavior composite',
    typeLabel: 'entity_behavior_composite',
    category: 'entity',
    fn: 'detection.py §22a',
    logs: ['all'],
    catches: 'Subtle account compromise where several indicators drift at once but none individually breaches its threshold.',
    how: [
      'Scores 4 signals — event-count z > 1.5, ≥1 new IP, ≥1 atypical hour, auth-failure z > 1.5 — as the fraction triggered.',
      'Flags when score ≥ the RL-tuned threshold AND at least 2 signals fired; high at score ≥0.75, else medium. Signal z-cutoffs are deliberately lower than single-detector bars.',
    ],
    tunable: [{ name: 'entity_behavior_composite_threshold', default: '0.6' }],
    fp: 'Any two mild deviations coinciding (new VPN IP + travel hours) cross the bar.',
    baseline: false,
  },
  {
    number: 29,
    name: 'Entity host composite',
    typeLabel: 'entity_host_composite',
    category: 'entity',
    fn: 'detection.py §22b',
    logs: ['all'],
    catches: 'A server drifting on multiple fronts at once — new software plus new logins plus failing auths.',
    how: [
      'Scores 3 signals — ≥1 new process name, ≥1 new user (RL-tuned), host auth-failure-ratio z > 1.5 — same scoring rule as #28.',
      'Flags when score ≥ the composite threshold and ≥2 signals fired; high at ≥0.75.',
    ],
    tunable: [
      { name: 'entity_behavior_composite_threshold', default: '0.6' },
      { name: 'entity_new_user_threshold', default: '1' },
    ],
    fp: 'Server maintenance windows and onboarding spikes produce simultaneous new-process + new-user signals.',
    baseline: false,
  },
];

export const SUPPLEMENTARY: SupplementaryLayer[] = [
  {
    name: 'Exfil volume (T1048)',
    summary:
      'Z-scores each user\u2019s network-event count against their entity profile\u2019s typical volume (needs ≥3 observations). Flags z > sigma — high above 1.5× sigma. The sigma is read from thresholds but is effectively static at 3.0 (the key is not in the RL dict). Main FP: legitimate large transfers (backups, uploads) that dwarf normal volume.',
    attck: ['T1048'],
  },
  {
    name: 'Exfil destination (T1567 / T1048)',
    summary:
      'Flags outbound connections to known cloud-storage/upload endpoints (Google Drive, Dropbox, OneDrive, Box, WeTransfer, transfer.sh, Mega, S3, …) at high, and ports outside the common set at medium. Peer-group destination comparison is scaffolded but inert until profiles track typical destinations. Static thresholds.',
    attck: ['T1567', 'T1048'],
  },
  {
    name: 'DNS tunneling (T1071 / T1041)',
    summary:
      'Flags DNS queries with any label over 40 characters or domain entropy above 3.5 bits (high, T1071), and more than 5 TXT queries per user (medium, T1041 — potential C2 channel). Static thresholds. Main FPs: machine-generated CDN/cloud domains and heavy legitimate TXT use (SPF/DKIM).',
    attck: ['T1071', 'T1041'],
  },
  {
    name: 'Exfil staging (T1048 + T1567)',
    summary:
      'Detects file creation → archival (.zip/.tar/…) → network transfer sequences within a window. The full archive+transfer pattern is critical; create→transfer without archival is high. Window is effectively static at 30 minutes (key not in the RL dict). Main FP: download-then-upload workflows — extremely common.',
    attck: ['T1048', 'T1567'],
  },
  {
    name: 'Provenance communities',
    summary:
      'Builds a graph of all events (7 node types, 8 edge types), prunes well-known benign processes, and runs Louvain community detection. A community is flagged when it has ≥ the RL-tuned minimum size (default 3) and anomaly density ≥ the RL-tuned bar (default 0.3), or high type diversity. Not phase-gated; needs ≥3 entries. Main FP: benign-but-large clusters (file shares, print servers) with a few real anomalies inside.',
  },
  {
    name: 'Temporal chains',
    summary:
      'Correlates anomalies already emitted by other detectors: anomalies sharing an entity (IP/user/host) within the RL-tuned window (default 30 min) are merged into chains via union-find, mapped to ATT&CK kill-chain phases, and scored on phase coverage, tightness, and entity overlap. Flags chains with ≥ the RL-tuned minimum length (default 3) and sufficient phase spread. Main FP: routine multi-step admin work (login → script → logoff).',
  },
  {
    name: 'Cross-type correlation',
    summary:
      'Groups anomalies by IP, user, and process across log types within 30-minute windows — the deterministic correlation stage that hands the supervisor pre-grouped findings with severity scores and ATT&CK enrichment.',
  },
];

export const BASELINE_NOTE =
  'During BASELINE phase, 17 baseline-dependent detectors are suppressed (methods 2–6, 10, 20–29, with #20 counting as two detectors: EWMA and CUSUM). 13 signature methods stay active, and the supplementary layers (GCN-LOF, provenance, temporal, exfiltration) are not phase-gated.';
