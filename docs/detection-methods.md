# Nabla Detection Methods — Reference

Source of truth: `nabla/detection.py` (`detect_anomalies()`), `nabla/gcn_lof.py`, `nabla/exfiltration.py`, `nabla/provenance.py`, `nabla/temporal.py`. Threshold defaults from `nabla/rl/calibration.py` (`THRESHOLDS`: name → min, max, step, default).

**Calibration status (N10/N13, round 4):** label-driven calibration moves a threshold ONLY for the 13 methods that emit a `raw_score` in the same units as their threshold — `z_score`, `entity_z_score`, `activity_spike`, `entity_activity_spike`, `failed_login_ratio`, `multi_ip`, `off_hours`, `entity_off_hours`, `entity_auth_failure`, `entity_new_ip`, `entity_new_process`, `entity_behavior_composite`, `entity_host_composite` (10 threshold keys; three keys are shared by two methods each). Every other key in `THRESHOLDS` — tier-gate sensitivities, window sizes, GCN-LOF, provenance, temporal, `risk_score_investigation_cutoff` — is **not calibratable**: those methods gate on severity tiers or windows, not a raw score, so labels have nothing to compare against (`NOT_CALIBRATABLE_METHODS` in `nabla/rl/calibration.py` is the code-side list). "Sensitivity" values below 0 disable a detector (all sensitivities default 0.7 except `unusual_process_sensitivity` = 0.5). See the generated threshold table at the end of this document.

## Baseline phase

During BASELINE phase, `detect_anomalies()` suppresses every block that needs statistical or entity history. **17 detectors are suppressed** — README methods 2, 3, 4, 5, 6, 10, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, with #20 (`ewma_cusum`) counting as two detectors (EWMA + CUSUM) = 17 total. **Signature methods 1, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19 (13 methods) stay active.** GCN-LOF, provenance, temporal, and exfiltration modules are *not* phase-gated in the pipeline, though exfil-volume is inert until entity profiles have ≥3 observations.

---

## Statistical & Rule-Based

### 1. pre_flagged
- **Function:** `pre_flagged` (`detection.py` §1)
- **Logs:** any (whatever the source marks)
- **Catches:** anomalies the log source itself already tagged (e.g. EDR verdicts), passed through as Nabla anomalies.
- **How:** Any entry with a truthy `anomaly` field becomes an anomaly of that type at `medium` severity, copying `details`, user, source IP and timestamp verbatim. No statistics involved.
- **Threshold:** none (signature-based, no tunable knob)
- **False positives:** Whatever the upstream source flags; Nabla adds no filter of its own.
- **Baseline phase:** runs

### 2. z_score
- **Function:** `z_score` → type `z_score_spike` (`detection.py` §2)
- **Logs:** all (counts every event per user)
- **Catches:** A user generating far more events than the batch average — beaconing, scripted activity, mass recon.
- **How:** Computes per-user event counts, batch mean and population std (needs ≥2 users). Flags when `z = (count − mean)/std > z_score_sigma` (default **2.0**, RL range 2.0–4.0 step 0.25); severity `high` when z > threshold + 1.0. Users in `new_accounts` are skipped. If an entity profile is warm (≥3 observations) this same block emits `entity_z_score` instead (see #21).
- **Calibratable (label-driven):** `z_score_sigma` = 2.0
- **False positives:** Genuinely high-volume users (service accounts, admins) on a quiet network inflate z; the entity-baseline path exists precisely to suppress this.
- **Baseline phase:** suppressed

### 3. brute_force
- **Function:** `failed_login_ratio` → type `brute_force_attempt` (`detection.py` §3)
- **Logs:** auth
- **Catches:** Password guessing / spraying against accounts.
- **How:** Counts `login_success` vs `login_failure` per user; requires ≥3 total auth events. Flags when failure ratio > `brute_force_ratio` (default **0.5**, RL range 0.3–0.8 step 0.1) at `high` severity. If the user's entity profile has auth-failure-ratio variance, `entity_auth_failure` (#22) takes precedence and this global check is skipped.
- **Calibratable (label-driven):** `brute_force_ratio` = 0.5
- **False positives:** Expired/rotated credentials and service accounts with hard-coded bad passwords produce high failure ratios.
- **Baseline phase:** suppressed

### 4. off_hours
- **Function:** `off_hours` (`detection.py` §4)
- **Logs:** all (timestamp hour of any event)
- **Catches:** Activity during the 22:00–06:00 UTC window when nobody should be working.
- **How:** Parses `HH` from each timestamp; counts a user's events with hour < 6 or ≥ 22. Flags when that count ≥ `off_hours_count` (default **3**, RL range 2–8) at `medium` severity. With a warm entity profile, `entity_off_hours` (#23) instead flags hours outside the user's own `typical_hours` using the same count threshold.
- **Calibratable (label-driven):** `off_hours_count` = 3
- **False positives:** Night-shift staff, global timezone offsets, and batch jobs — the fixed UTC window ignores local business hours (entity baselines fix this once warm).
- **Baseline phase:** suppressed

### 5. multiple_source_ips
- **Function:** `multi_ip` → type `multiple_source_ips` (`detection.py` §5)
- **Logs:** auth/network/dns (any event carrying a routable source IP)
- **Catches:** One account appearing from many distinct addresses — credential sharing, proxying, or geographically impossible logins.
- **How:** Collects routable source IPs (`is_routable_ip`) per user; flags when unique-IP count ≥ `multi_ip_count` (default **3**, RL range 2–6) at `high` severity. Despite the name there is **no geo/velocity math** — it is a pure distinct-IP-count heuristic; the alert lists all IPs. Warm entity profiles switch this to `entity_new_ip` (#24).
- **Calibratable (label-driven):** `multi_ip_count` = 3
- **False positives:** Road warriors, VPN pools, CGNAT, and CDNs legitimately inflate distinct-IP counts.
- **Baseline phase:** suppressed

### 6. activity_spike
- **Function:** `activity_spike` (`detection.py` §6)
- **Logs:** all
- **Catches:** A sudden burst of activity from one user relative to the population mean.
- **How:** Flags when a user's event count > batch mean × `spike_multiplier` (default **3.0**, RL range 2.0–6.0 step 0.5) at `high` severity; `new_accounts` are skipped. With a warm entity profile the comparison becomes count > the user's own EWMA × multiplier (`entity_activity_spike`, #25).
- **Calibratable (label-driven):** `spike_multiplier` = 3.0
- **False positives:** Month-end/quarter-end processing, ticket storms, and newly onboarded heavy users (mitigated by the `new_accounts` skip).
- **Baseline phase:** suppressed

## Endpoint Behavior

### 7. lolbin
- **Function:** `lolbin` → type `lolbin_abuse` (`detection.py` §7)
- **Logs:** endpoint
- **Catches:** Living-off-the-land binary abuse — certutil/mshta/regsvr32/powershell etc. used to download, decode, or execute.
- **How:** Matches process name against LOLBIN signatures (from the `lolbin_db` shared block, else a 9-entry fallback: certutil, mshta, wscript, cscript, regsvr32, rundll32, bitsadmin, powershell, wmic), then counts how many suspicious command-line substrings hit (`urlcache`, `-enc`, `iex`, `/i:http`, …). Needs ≥ `min_pattern_matches`: **1** at default `lolbin_sensitivity` (**0.7**, RL range 0.3–1.0), 0 at ≥0.9 (name alone fires, even with no command line), 2 at <0.5. Processes under `LEGITIMATE_TOOL_PATHS` (e.g. `\SplunkUniversalForwarder\`, `\Program Files\Microsoft\`) are skipped. `high` severity, MITRE ids from the signature.
- **Static (not calibratable):** `lolbin_sensitivity` = 0.7
- **False positives:** Legit admin scripts using `-enc` or `iex`, and software updates invoking bitsadmin from non-allowlisted paths.
- **Baseline phase:** runs

### 8. parent_child
- **Function:** `parent_child` → type `suspicious_parent_child` (`detection.py` §8)
- **Logs:** endpoint
- **Catches:** Office/browser/PDF readers spawning shells — the classic macro or drive-by payload.
- **How:** Parent stem must be in `SUSPICIOUS_PARENTS` (winword, excel, powerpnt, outlook, acrobat, reader, chrome, firefox, thunderbird, acrord32) and child in `suspicious_children` (all LOLBIN names plus cmd, powershell, bash, sh, python, python3, perl). At default `parent_child_sensitivity` (**0.7**, RL range 0.3–1.0) the pair alone fires at `high`; at ≥0.9 likewise; at <0.5 it additionally requires a suspicious command token (`http://`, `-enc`, `iex`, `bypass`, `base64`, …).
- **Static (not calibratable):** `parent_child_sensitivity` = 0.7
- **False positives:** Office add-ins and document generators that legitimately shell out; browsers opening helper processes.
- **Baseline phase:** runs

### 9. critical_host
- **Function:** `critical_host_escalation` (`detection.py` §9)
- **Logs:** endpoint
- **Catches:** Privilege-escalation commands on domain controllers, build, prod, or finance systems.
- **How:** Critical hosts come from `watchlist.hosts`, else hostnames containing DC/DOMAIN/BUILD/PROD/FINANCE. Three tiers: (a) command contains `sudo`, `runas`, `sedebugprivilege`, `setakeownershipprivilege`, `seloaddriverprivilege`, `su -`, `su root`, `pkexec`, or process is sudo/su/runas/psexec/pkexec → `critical`; (b) UAC-bypass parent (fodhelper, eventvwr, compmgmtlauncher, slui) spawning a suspicious child → `high`; (c) at `critical_host_sensitivity` ≥0.9, any `execute` by a user without admin/system/svc_ in the name → `medium`. At sensitivity <0.5, non-`critical` findings are dropped. Default **0.7**, RL range 0.3–1.0.
- **Static (not calibratable):** `critical_host_sensitivity` = 0.7
- **False positives:** Named admin accounts doing scheduled maintenance; tier (c) at 0.9 fires on every non-admin execution on a critical box.
- **Baseline phase:** runs

### 10. unusual_process
- **Function:** `unusual_process` → type `unusual_process_per_host` (`detection.py` §10)
- **Logs:** endpoint
- **Catches:** A process appearing on a host for the first time — new tooling, implants, persistence.
- **How:** Builds per-host process-name sets for the run and diffs against historical baselines: the host entity profile's `typical_processes` when warm (see #26/#27), else `baseline_host_procs` read from archival memory. With cold baselines it flags each unseen process name at `medium`. `COMMON_PROCESSES` (explorer, svchost, lsass, conhost, …) are excluded at sensitivity ≥0.5; below 0.5 only LOLBIN-named processes are considered. Note: if no baseline map exists at all, nothing is flagged. `unusual_process_sensitivity` default **0.5**, RL range 0.3–1.0.
- **Static (not calibratable):** `unusual_process_sensitivity` = 0.5
- **False positives:** Legitimate software installs/updates push many "new" process names at once — the entity-baseline path thresholds on a count to absorb this.
- **Baseline phase:** suppressed

### 11. action_sequence
- **Function:** `action_sequence` → type `rapid_action_sequence` (`detection.py` §11)
- **Logs:** endpoint
- **Catches:** Create → execute → delete compressed into minutes — dropper execution followed by artifact cleanup (lateral movement / anti-forensics).
- **How:** Per (user, host), actions come from the `action` field or are derived from the command line (`echo/>/copy/cp/new-item` → create; `del/rm/erase/remove-item/rmdir` → delete; otherwise execute). Requires all three action types present with timestamps and ≥3 parseable timestamps, then flags when span from earliest to latest ≤ `action_sequence_window_minutes` (default **30**, RL range 5–120 step 5) at `high` severity.
- **Static (not calibratable):** `action_sequence_window_minutes` = 30
- **False positives:** Developer build/clean cycles and packaging scripts naturally do create-run-delete inside half an hour.
- **Baseline phase:** runs

## Advanced Endpoint

### 12. gcn_lof
- **STATUS: DISABLED BY DEFAULT (round 3, R3; round 4, N11).** Not run unless `--gcn-lof` is passed, and passing it prints a loud warning: under the current z-score/bank anchoring it flagged 13-18% of BENIGN entities (77% of them high severity), poisoning quarantine and correlation. The full fix (percentile redesign + a harness-verified <1% benign ceiling) is deferred — treat every GCN-LOF finding as unvetted signal.
- **Function:** `GCNLOFDetector.detect()` in `gcn_lof.py` → type `gcn_lof_anomaly`
- **Logs:** all four (log type is a one-hot feature)
- **Catches:** Events that are outliers both in feature space and in their neighborhood on the event graph — catches compound anomalies no single rule sees.
- **How:** Encodes each event as 23 features (one-hot log type ×4, one-hot action ×8, sin/cos hour, 6 binary flags — off-hours, LOLBIN, suspicious parent, critical host, pre-flagged, suspicious cmdline — normalized unique-IP count, clipped event-count z, auth-failure ratio), computes Local Outlier Factor (n_neighbors=20) and appends it as feature 24. Builds a cosine-similarity KNN graph (k=10) and trains a 2-layer GCN autoencoder (hidden 32, embed 16; 5 epochs, lr 0.01, dropout 0.3) to reconstruct its own inputs. Score = `alpha` × normalized LOF + (1−`alpha`) × normalized reconstruction error; flags score > `gcn_lof_threshold`. Severity `high` above 0.9. Skips batches <3 events; model weights are persisted and fine-tuned each run.
- **Static (not calibratable):** `gcn_lof_alpha` = 0.5 (range 0.3–0.7), `gcn_lof_threshold` = 0.75 (range 0.5–0.95)
- **False positives:** Rare-but-benign event shapes (unusual actions from legit automation) reconstruct poorly; scores are min-max normalized per batch, so a small batch always has a "worst" event.
- **Baseline phase:** runs (not phase-gated)

### 13. attack_script
- **Function:** `attack_script` → type `known_attack_script` (`detection.py` §10b)
- **Logs:** endpoint
- **Catches:** Named offensive tooling — Mimikatz, Rubeus, Cobalt Strike, Impacket, LinEnum, and ~800 more.
- **How:** Primary source is `build_tool_name_index()` from the ATT&CK STIX bundle (800+ tool/malware names), merged with a 47-entry fallback list (covers binary names like `beacon.exe`, `msfvenom`, `godpotato`). Names are matched with word boundaries against `command_line`, `target_file`, and `process` via one pre-compiled regex. `critical` severity with the tool's MITRE technique, tool name, and display name attached.
- **Threshold:** none (signature-based, no tunable knob)
- **False positives:** Word-boundary collisions with innocuous substrings and security teams running the same tools in authorized tests.
- **Baseline phase:** runs

### 14. renamed_tool
- **Function:** `renamed_tool` → type `renamed_attack_tool` (`detection.py` §10d)
- **Logs:** endpoint
- **Catches:** Attack tools whose binary was renamed — identified by command-line fingerprint instead of filename.
- **How:** ~47 fixed signature substrings (`asktgt `, `kerberoast `, `sekurlsa::logonpasswords`, `lsadump::dcsync`, `--collectionmethod `, `cobaltstrike.jar`, `\msse-` pipe, `privilege::debug`, …) are matched in `command_line`; a hit is suppressed when the process name already contains the tool name (that's #13's job). One alert per entry, `critical`, MITRE id per signature.
- **Threshold:** none (signature-based, no tunable knob)
- **False positives:** Documentation, training material, or pentest reports pasted into command lines containing the same tokens.
- **Baseline phase:** runs

### 15. suspicious_path
- **Function:** `suspicious_path` → type `suspicious_file_path` (`detection.py` §12)
- **Logs:** endpoint
- **Catches:** Executables running from staging locations attackers love — `C:\PerfLogs\`, `AppData`, `C:\Users\Public`, `Temp`, `ProgramData`, `Downloads`, or suspiciously shallow paths like `C:\Intel\lb3.exe`.
- **How:** The process path is regex-matched against 8 patterns (plus a shallow-path rule: exactly 2–3 directory levels below the drive root, since legit software installs deeper). Anything under `LEGITIMATE_PATHS` (`\Windows\System32\`, `\Program Files\`, winsxs, servicing, assembly, …) is skipped. At `suspicious_path_sensitivity` <0.5 at least 2 patterns must match; severity is `high` with ≥2 matches, `medium` otherwise. Default **0.7**, RL range 0.3–1.0.
- **Static (not calibratable):** `suspicious_path_sensitivity` = 0.7
- **False positives:** User-installed portable apps, browser downloads executed from `Downloads`, and installers that unpack to `Temp`.
- **Baseline phase:** runs

### 16. enumeration
- **Function:** `enumeration_behavior` (`detection.py` §10c) — three independent sub-checks
- **Logs:** endpoint
- **Catches:** Host/AD/credential enumeration performed by renamed or custom scripts — caught by behavior, not name.
- **How:** (a) One parent (per user+host, excluding `SYSTEM_PARENTS` like services/svchost/splunkd) spawning ≥**10** distinct children within a **5-minute** window (≥20 if sensitivity <0.7). (b) One process touching ≥**3** distinct sensitive-path categories (≥5 if <0.7) from a list spanning `/etc/passwd`, `/etc/shadow`, `~/.ssh`, `/var/log/` and `\AppData\`, `\Users\`, `\ntds.dit`, `SAM`, `CurrentVersion\Run`. (c) A user+host issuing ≥**3** distinct enumeration commands (≥5 if <0.7) from 74 patterns (`find / -name`, `cat /etc/passwd`, `whoami /all`, `net user`, `systeminfo`, `reg query hklm`, `get-wmiobject`, …). All fire at `high` with T1082 plus T1057/T1005/T1059. `enumeration_sensitivity` default **0.7**, RL range 0.3–1.0.
- **Static (not calibratable):** `enumeration_sensitivity` = 0.7 (switches thresholds 10→20, 3→5)
- **False positives:** Inventory/CM agents, admin "check everything" scripts, and build systems that touch many sensitive paths in sequence.
- **Baseline phase:** runs

### 17. integrity_anomaly
- **Function:** `integrity_anomaly` (`detection.py` §13)
- **Logs:** endpoint
- **Catches:** SYSTEM/high-integrity processes spawned by ordinary parents — token theft, service exploit, or UAC bypass.
- **How:** Requires `integrity_level` ∈ {system, high} or the user being `NT AUTHORITY\SYSTEM`, and the parent's filename **not** in `SYSTEM_PARENTS` (services, wininit, lsass, csrss, svchost, smss, taskhostw, dwm, splunkd, splunk-*). At `integrity_anomaly_sensitivity` <0.5 the child must additionally be a LOLBIN name. `high` severity, reports integrity level and parent.
- **Static (not calibratable):** `integrity_anomaly_sensitivity` = 0.7
- **False positives:** Legitimate installers and deployment agents running elevated from non-allowlisted parents.
- **Baseline phase:** runs

### 18. registry_abuse
- **Function:** `registry_abuse` (`detection.py` §14)
- **Logs:** endpoint
- **Catches:** Persistence and defense-evasion via high-value registry keys — Run/RunOnce, IFEO debugger injection, WINEVT channel config, service registration.
- **How:** Only registry mutation events (`registry_set`, `setvalue`, `deletevalue`, `createkey`, `deletekey`, …) are considered. A hit requires the target to match `CRITICAL_REGISTRY_PATTERNS` (`CurrentVersion\Run`, `RunOnce`, `Policies`, `Image File Execution Options`, `WINEVT\Channels`, `Services\`, `CurrentControlSet\Services`) **or** — at sensitivity ≥0.5 — the writing process to live in a suspicious/shallow path. Processes under `LEGITIMATE_PATHS` are skipped unless sensitivity ≥0.9; at <0.5 only critical keys count. Severity `high` for critical keys, else `medium`. Default **0.7**, RL range 0.3–1.0.
- **Static (not calibratable):** `registry_abuse_sensitivity` = 0.7
- **False positives:** Software installers and GPO/endpoint agents legitimately writing Run keys and service entries.
- **Baseline phase:** runs

### 19. network_anomaly
- **Function:** `network_anomaly` (`detection.py` §15)
- **Logs:** endpoint (only `action == "network_connect"` events)
- **Catches:** Outbound connections from processes that should never talk to the network — LOLBIN C2/download channels — or from binaries dropped in staging paths.
- **How:** Process stem checked against `NETWORK_LOLBIN_PROCS` (certutil, mshta, wscript, cscript, regsvr32, rundll32, bitsadmin, cmstp, installutil, msbuild, msiexec, presentationhost) → `high`. Otherwise, a process in a suspicious or shallow path → `medium` (dropped entirely at sensitivity <0.5). Processes in `LEGITIMATE_PATHS` are skipped unless they are on the LOLBIN list. `network_anomaly_sensitivity` default **0.7**, RL range 0.3–1.0.
- **Static (not calibratable):** `network_anomaly_sensitivity` = 0.7
- **False positives:** Software updaters and license checks that legitimately phone home from temp/ProgramData paths.
- **Baseline phase:** runs

### 20. ewma_cusum
- **Function:** `ewma` → type `ewma_drift`, and `cusum` → types `cusum_shift` / `cusum_drop` (`detection.py` §20–21)
- **Logs:** all (binned per user)
- **Catches:** Gradual ramp-ups and sustained shifts in event rate that point z-scores miss — e.g. failed logins climbing 2→5→12 per interval, or a compromised account quietly generating ~15% more events.
- **How:** Events are binned per user into **5-minute** bins; a user needs ≥3 bins. EWMA: λ = 0.3 (0.1 if `ewma_sensitivity` <0.7); flags a bin whose count exceeds running EWMA + 2.0σ (3.0σ if <0.7); one alert per user, `high`. CUSUM: mean/σ taken from the first half of bins as reference, k = 0.5σ slack, decision limit h = 4.0 (5.0 if <0.7, ARL₀ ≈ 370–465); S⁺ > h → `cusum_shift` `high`, S⁻ > h → `cusum_drop` `medium`; one alert per user per direction. Both default **0.7**, RL range 0.3–1.0.
- **Static (not calibratable):** `ewma_sensitivity` = 0.7, `cusum_sensitivity` = 0.7
- **False positives:** Legitimate step changes — business-hours start, cron bursts, migration jobs — read as sustained shifts.
- **Baseline phase:** suppressed

## Entity-Specific (per-user / per-host baselines from `nabla/baselines.py`)

*These fire only when `entity_profiles` is supplied and `warm_up_complete()` for the entity; each replaces its batch-level counterpart above.*

### 21. entity_z
- **Function:** `entity_z_score` → type `entity_event_count_spike` (`detection.py` §2)
- **Logs:** all; needs user profile with `observation_count` ≥ 3
- **Catches:** A user producing far more events **than they usually do**.
- **How:** z-score of the run's event count against the profile's `typical_event_count` EWMA/std; flags when z > `entity_event_count_sigma` (default **2.0**, RL range 1.0–4.0 step 0.25); `high` if z > threshold + 1.0. When it fires, the batch z-score check is skipped.
- **Calibratable (label-driven):** `entity_event_count_sigma` = 2.0
- **False positives:** Rare but legitimate busy days for a normally quiet user.
- **Baseline phase:** suppressed

### 22. entity_auth_failure
- **Function:** `entity_auth_failure` → type `entity_auth_failure_spike` (`detection.py` §3)
- **Logs:** auth; needs profile auth-failure-ratio variance > 0
- **Catches:** A user whose failure rate jumped relative to their own norm (e.g. normally 5%, now 60%) even if below the global 50% bar.
- **How:** z-score of the current failure ratio against the profile's ratio EWMA; flags when z > `entity_auth_failure_sigma` (default **2.0**, RL range 1.0–4.0 step 0.25) at `high`. Supersedes the global ratio check when it fires.
- **Calibratable (label-driven):** `entity_auth_failure_sigma` = 2.0
- **False positives:** A single bad password cache flush after a credential rotation looks like a spike against a clean history.
- **Baseline phase:** suppressed

### 23. entity_off_hours
- **Function:** `entity_off_hours` → type `entity_off_hours_activity` (`detection.py` §4)
- **Logs:** all; needs profile `typical_hours` populated
- **Catches:** Activity at hours this specific user never works — night-shift workers are no longer flagged.
- **How:** Counts run events whose hour is absent from the user's `typical_hours`; flags when ≥ `off_hours_count` (shared with #4, default **3**, RL range 2–8) at `medium`, reporting usual vs. unusual hour sets.
- **Calibratable (label-driven):** `off_hours_count` = 3
- **False positives:** Schedule changes (new shift, travel) before the profile adapts.
- **Baseline phase:** suppressed

### 24. entity_new_ip
- **Function:** `entity_new_ip` → type `entity_new_ip` (`detection.py` §5)
- **Logs:** auth/network/dns; needs profile `typical_ips` populated
- **Catches:** An account surfacing from addresses it has never used — hijacked credentials or a new foothold.
- **How:** `new_ips = current routable IPs − profile.typical_ips`; flags when count ≥ `entity_new_ip_threshold` (default **2**, RL range 1–5); severity `high` at ≥3 new IPs, else `medium`. Replaces the fixed multi-IP count check.
- **Calibratable (label-driven):** `entity_new_ip_threshold` = 2
- **False positives:** VPN range changes, DHCP churn, and travel — anything that rotates the user's address pool.
- **Baseline phase:** suppressed

### 25. entity_activity
- **Function:** `entity_activity_spike` (`detection.py` §6)
- **Logs:** all; needs profile `typical_event_count.value` > 0
- **Catches:** A user suddenly several times busier than their own norm.
- **How:** Flags when run event count > profile EWMA × `spike_multiplier` (shared with #6, default **3.0**, RL range 2.0–6.0) at `high`; `new_accounts` skipped. Replaces the batch-mean comparison.
- **Calibratable (label-driven):** `spike_multiplier` = 3.0
- **False positives:** Periodic heavy workflows (month-end close) for a normally light user.
- **Baseline phase:** suppressed

### 26. entity_new_process
- **Function:** `entity_new_process` (`detection.py` §10)
- **Logs:** endpoint; needs warm host profile with `typical_processes`
- **Catches:** A host suddenly running a batch of process names it has never run before.
- **How:** Diff of run's process names against the host profile's `typical_processes` (excluding `COMMON_PROCESSES` at sensitivity ≥0.5; at <0.5 only LOLBIN-named processes are counted). Flags when new count ≥ `entity_new_process_threshold` (default **3**, RL range 1–10); `high` at ≥2× the threshold, else `medium`.
- **Static (not calibratable):** `entity_new_process_threshold` = 3, `unusual_process_sensitivity` = 0.5
- **False positives:** Patch Tuesday, software rollouts, and ephemeral tooling that legitimately introduces many new names.
- **Baseline phase:** suppressed

### 27. entity_unusual_process
- **Function:** `entity_unusual_process` → type `unusual_process_per_host` (`detection.py` §10)
- **Logs:** endpoint; nested inside #26's diff
- **Catches:** A single new process on a host that is specifically a LOLBIN or known attack tool — high-signal subset of #26.
- **How:** Iterates #26's `new_procs` list and emits one `high`-severity alert per process whose name matches a LOLBIN signature or the ATT&CK `attack_tool_index`, even when the bulk count threshold (#26) wouldn't fire on its own. Subject to the same `unusual_process_sensitivity` filtering as #26.
- **Static (not calibratable):** `unusual_process_sensitivity` = 0.5 (and `entity_new_process_threshold` gates the parent diff)
- **False positives:** Security tooling or admin utilities newly deployed that happen to share a name with a LOLBIN.
- **Baseline phase:** suppressed

### 28. entity_behavior_composite
- **Function:** `entity_behavior_composite` (`detection.py` §22a)
- **Logs:** all; needs warm user profile
- **Catches:** Subtle account compromise where several indicators drift at once but none individually breaches its threshold.
- **How:** Scores 4 signals — event-count z > 1.5, ≥1 new IP, ≥1 atypical hour, auth-failure z > 1.5 — as the fraction triggered. Flags when score ≥ `entity_behavior_composite_threshold` **and** at least 2 signals fired; `high` at score ≥0.75, else `medium`. Signal z-cutoffs are hardcoded at 1.5 (deliberately lower than the single-detector bars). Threshold default **0.6**, RL range 0.1–1.0.
- **Calibratable (label-driven):** `entity_behavior_composite_threshold` = 0.6
- **False positives:** Any two mild deviations coinciding (new VPN IP + travel hours) cross the bar; 2 of 4 signals at 0.5 is enough.
- **Baseline phase:** suppressed

### 29. entity_host_composite
- **Function:** `entity_host_composite` (`detection.py` §22b)
- **Logs:** all (host-scoped); needs warm host profile
- **Catches:** A server drifting on multiple fronts at once — new software plus new logins plus failing auths.
- **How:** Scores 3 signals — ≥1 new process name (excluding `COMMON_PROCESSES`), ≥ `entity_new_user_threshold` new users (default **1**, RL range 1–5), host auth-failure-ratio z > 1.5. Same scoring rule as #28: score ≥ `entity_behavior_composite_threshold` and ≥2 signals; `high` at ≥0.75.
- **Static (not calibratable):** `entity_behavior_composite_threshold` = 0.6, `entity_new_user_threshold` = 1
- **False positives:** Server maintenance windows and onboarding spikes produce simultaneous new-process + new-user signals.
- **Baseline phase:** suppressed

---

## Exfiltration module (`nabla/exfiltration.py` — 4 sub-detectors, all `type: data_exfiltration`)

**exfil_volume** (`_detect_volume_anomaly`, T1048 Exfiltration Over Alternative Protocol) — counts network events per user and z-scores the count against the user's entity-profile `typical_event_count` EWMA, requiring ≥3 profile observations; flags z > sigma at `high` if z > 1.5× sigma, else `medium`, with confidence `min(0.95, 0.5 + z/10)`. The sigma comes from Settings (`NABLA_EXFIL_VOLUME_SIGMA`, default **3.0**) — not in `THRESHOLDS`, so label calibration never moves it; it is operator-tuned only. Legitimate big transfers (backups, large uploads) that dwarf a user's normal network volume are the main false positive.

**exfil_destination** (`_detect_destination_anomaly`, T1567 Exfiltration Over Web Service / T1048) — inspects each user's outbound connections and flags two things: destinations matching known cloud-storage/upload endpoints (`drive.google.com`, `docs.google.com`, Dropbox, OneDrive/SharePoint/1drv, Box, WeTransfer, transfer.sh, file.io, Mega, `s3.amazonaws.com` …) and ports outside the common set {80, 443, 53, 22, 3389, 8080, 8443, 25, 587, 993, 143}. Cloud-storage hits are `high` with confidence 0.7 and T1567; unusual ports alone are `medium` with confidence 0.5 and T1048. Peer-group/typical-destination comparison is scaffolded but inert (user profiles have no `typical_destinations` yet). Fixed rules, no tunable thresholds. Normal use of Google Drive/Dropbox/SharePoint at work and any legitimate service on an uncommon port will fire.

**dns_tunneling** (`_detect_dns_tunneling`, T1071 Application Layer Protocol for long/entropy hits; T1041 Exfiltration Over C2 Channel for TXT) — groups DNS queries per user and calls a domain suspicious if any dot-separated label exceeds **40 characters** or the full-domain Shannon entropy exceeds **3.5 bits**; any such query yields a `high` alert (T1071) with confidence scaling `0.5 + 0.1×` suspicious queries up to 0.9. Separately, more than **5** TXT queries per user in the batch yields a `medium` alert (T1041, confidence 0.6) as a potential DNS C2 channel. The entropy bar is Settings-tunable (`NABLA_EXFIL_DNS_ENTROPY_THRESHOLD`, default 3.5); label calibration never moves it. Long machine-generated domains (CDNs, cookie-sync, cloud tenant names) and heavy legitimate TXT use (SPF/DKIM checks, some MDM agents) are the main false positives.

**exfil_staging** (`_detect_staging_pattern`, T1048 + T1567) — sorts a user's events by timestamp and looks for the sequence file creation → archival → network transfer inside one window. Creates are actions `create/write/file_create/file_written`; archives are `archive/compress` actions or targets ending `.zip/.tar/.gz/.7z/.rar/.bz2/.xz/.tgz`; transfers are `network_connect`/network-type events. The full archive+transfer pattern within the window is `critical` (confidence 0.85, T1048+T1567); create→transfer without archival is `high` (confidence 0.6, T1048). Window comes from `thresholds.get("exfil_staging_window_minutes", 30)` — also **not** in `THRESHOLDS`, so effectively a static **30 minutes**. Any user who downloads a file and uploads another within half an hour (extremely common) trips the create→transfer branch.

## Provenance communities (`nabla/provenance.py`, `detection_method: provenance_community`)

Builds a graph from all entries with 7 node types (process, file, ip, user, host, registry, domain) and 8 edge types (parent_of, executed_on, created, read, wrote, connected_to, logged_in_as, queried), tagging nodes already flagged by earlier detectors. Well-known benign processes (explorer, svchost, lsass, systemd, sshd, …) are pruned unless they have anomalous neighbors, then a from-scratch Louvain modularity pass finds communities. A community is flagged when it has ≥ `provenance_min_community_size` (default **3**, RL range 2–10) members and either anomaly density ≥ `provenance_anomaly_density` (default **0.3**, RL range 0.1–0.5) or type diversity ≥ 3 with density ≥ threshold/3; severity is `high` at density ≥0.5. Requires ≥3 entries; not phase-gated. Benign-but-large clusters (file shares, print servers) can cross the density bar when a few real anomalies land in them.

## Temporal chains (`nabla/temporal.py`, `detection_method: temporal_chain`)

Correlates the anomalies already emitted by every other detector: two anomalies link if they share at least one entity (source IP, user, or host) and their timestamps are within `temporal_chain_window_minutes` (default **30**, RL range 5–120) of each other; Union-Find merges linked pairs into maximal chains of ≥2 events. Each chain is mapped to the 10 MITRE ATT&CK kill-chain phases via per-anomaly-type and log-type/action tables, then scored `0.4 × phase_coverage + 0.3 × tightness + 0.3 × entity_overlap` (tightness is the inverse-normalized average inter-event gap; entity_overlap is the fraction of events sharing an entity with another event). A chain is flagged when it has ≥ `temporal_min_chain_length` (default **3**, RL range 2–6) events and either phase coverage ≥0.2 or ≥3 distinct phases. Not phase-gated, but produces nothing until other detectors emit ≥2 shareable anomalies. Routine multi-step admin work (login → run script → logoff) forms chains that look like short kill chains.

## Blind spot: machine-account classification

Accounts classified as machine accounts (service-prefix match on `svc-`, `service-`, etc., plus the `NABLA_MACHINE_ACCOUNTS` operator list) are excluded from behavioral baselining, off-hours detection, peer groups, and **behavioral risk scoring** — and the same exclusion that keeps CI noise out of your alerts also hides an attacker who does their work *through* a service account.

**What is and is not excluded (S1, round 5).** Machine accounts lose only the *behavioral* risk methods: z-scores, activity spikes, off-hours, multi-IP/new-IP, EWMA/CUSUM drift, auth-failure sigma, behavior composites (the `BEHAVIORAL_METHODS` set in `nabla/risk.py`). **Signature and exfiltration detections score at full weight**: LOLBin abuse, attack scripts, renamed tools, registry persistence, suspicious paths, integrity anomalies, network anomalies, enumeration, DNS tunneling, exfiltration — an `attack_script` run as `root` carries exactly the risk it would under any user. `failed_login_ratio` also scores for machine accounts (brute force *against* a service account is attack signal, not noise; the accepted background-brute-force risk is bounded and measured by the harness). Interactive use of a machine-classified account (console logins, off-hours GUI sessions) remains a real attacker pattern that per-account behavioral baselining cannot see, because the account has no baseline to deviate from. Mitigations: watch for machine accounts appearing in *other* entities' anomalies (impossible travel source IPs, critical-host access), and use `NABLA_HUMAN_ACCOUNTS` to force a misclassified account back into baselining. A stricter machine-account model (interactive-session detection, classification confidence) is on the roadmap — this release ships reachability (`NABLA_MACHINE_ACCOUNTS`/`NABLA_HUMAN_ACCOUNTS` are Settings fields, forwarded in compose, documented in `.env.example`) and this documented trade-off.

## Threshold reference (generated — do not edit by hand)

Regenerated by `tests/test_n13_docs_thresholds.py`; a mismatch fails the suite.

<!-- threshold-table-start -->
| key | default | range | calibratable |
|---|---|---|---|
| `action_sequence_window_minutes` | 30 | 5–120 (step 5) | no |
| `brute_force_ratio` | 0.5 | 0.3–0.8 (step 0.1) | yes |
| `critical_host_sensitivity` | 0.7 | 0.3–1.0 (step 0.1) | no |
| `cusum_sensitivity` | 0.7 | 0.3–1.0 (step 0.1) | no |
| `entity_auth_failure_sigma` | 2.0 | 1.0–4.0 (step 0.25) | yes |
| `entity_behavior_composite_threshold` | 0.6 | 0.1–1.0 (step 0.1) | yes |
| `entity_event_count_sigma` | 2.0 | 1.0–4.0 (step 0.25) | yes |
| `entity_new_ip_threshold` | 2 | 1–5 (step 1) | yes |
| `entity_new_process_threshold` | 3 | 1–10 (step 1) | yes |
| `entity_new_user_threshold` | 1 | 1–5 (step 1) | no |
| `enumeration_sensitivity` | 0.7 | 0.3–1.0 (step 0.1) | no |
| `ewma_sensitivity` | 0.7 | 0.3–1.0 (step 0.1) | no |
| `gcn_lof_alpha` | 0.5 | 0.3–0.7 (step 0.1) | no |
| `gcn_lof_threshold` | 0.75 | 0.5–0.95 (step 0.05) | no |
| `integrity_anomaly_sensitivity` | 0.7 | 0.3–1.0 (step 0.1) | no |
| `lolbin_sensitivity` | 0.7 | 0.3–1.0 (step 0.1) | no |
| `multi_ip_count` | 3 | 2–6 (step 1) | yes |
| `network_anomaly_sensitivity` | 0.7 | 0.3–1.0 (step 0.1) | no |
| `off_hours_count` | 3 | 2–8 (step 1) | yes |
| `parent_child_sensitivity` | 0.7 | 0.3–1.0 (step 0.1) | no |
| `provenance_anomaly_density` | 0.3 | 0.1–0.5 (step 0.05) | no |
| `provenance_min_community_size` | 3 | 2–10 (step 1) | no |
| `registry_abuse_sensitivity` | 0.7 | 0.3–1.0 (step 0.1) | no |
| `risk_score_investigation_cutoff` | 50.0 | 20.0–80.0 (step 5.0) | no |
| `spike_multiplier` | 3.0 | 2.0–6.0 (step 0.5) | yes |
| `suspicious_path_sensitivity` | 0.7 | 0.3–1.0 (step 0.1) | no |
| `temporal_chain_window_minutes` | 30 | 5–120 (step 5) | no |
| `temporal_min_chain_length` | 3 | 2–6 (step 1) | no |
| `unusual_process_sensitivity` | 0.5 | 0.3–1.0 (step 0.1) | no |
| `z_score_sigma` | 2.0 | 2.0–4.0 (step 0.25) | yes |
<!-- threshold-table-end -->
