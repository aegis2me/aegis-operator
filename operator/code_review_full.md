# Aegis board code-review

_Generated 2026-09-10T15:46:45 -- reviewers: ds, qwen2.5-coder-32b; consultant: ds._

Reviewed **118 files** in 24 bundle(s) (TRUNCATED -- raise --max-bundles for full coverage); paths: `operator, shared, rag, redteam, exploitgym, orchestrator`. 729 raw suggestions -> 435 unique after dedup.

## Consultant's consolidated plan

## Themes

1. **Injection & unsafe subprocess/shell usage** — the dominant theme. User/model-controlled strings are interpolated into shell commands, SQL, and file paths across `aegis_operator.py`, `probe_techniques.py`, `race_money.py`, `authz-erp`, and `sandbox.py`.
2. **TLS/SSL verification disabled globally** — `verify=False` and `urllib3.disable_warnings()` appear in multiple files, suppressing certificate validation project-wide.
3. **File/resource handling** — missing context managers, non-atomic writes, no fsync, silent exception swallowing, and race-prone read-modify-write cycles.
4. **Correctness bugs** — swapped arguments, mutated shared state, broken loop guards, unsafe hash inputs, and flawed verifier logic.
5. **Robustness gaps** — unchecked subprocess return codes, missing response validation, unhandled exceptions in operators and board loops.
6. **Test coverage** — broad lack of unit/integration tests for security-critical paths (tool specs, verifier, ledger, board parsing).
7. **Design/readability** — monolithic `aegis_operator.py`, duplicated logic, hardcoded values, and minor style issues.

---

## Prioritized improvements

1. **[critical/low] operator/aegis_operator.py — replace all shell-string interpolation with subprocess argument arrays** (models: ds, qwen2.5-coder-32b)  
   Covers `t_run_command`, `t_render_page`, `t_rag_search`, `t_exploit_search`, `t_fingerprint_target`, `t_provision_twin`, `t_vpn_ctl`, `t_add_wordlist_url`, `t_fetch_url`, and `install_kali_tool`. This is the single largest injection surface in the codebase.

2. **[critical/low] operator/aegis_operator.py — validate/sanitize `name`, `acct`, `endpoint`, `key`, `region`, `sources`, and URL params before use** (models: ds, qwen2.5-coder-32b)  
   Path traversal via `droot`/`spath`, empty Cloudflare account ID producing malformed endpoints, and shell metacharacter injection through quote-stripping are all exploitable.

3. **[critical/low] exploitgym/techniques/probe_techniques.py — use parameterized SQL / subprocess arg lists; stop calling private `store._transition()`** (models: ds, qwen2.5-coder-32b)  
   Raw SQL interpolation into `psql -c` and private API usage are both correctness and security failures.

4. **[critical/low] exploitgym/targets/authz-erp/app.py — parameterize all SQL queries (`uid`, `rid`, and others)** (models: ds, qwen2.5-coder-32b)  
   Direct string interpolation of user-controlled identifiers into SQL is trivially injectable.

5. **[critical/low] exploitgym/race_money.py — parameterize SQL; use per-worker sessions; validate responses** (models: ds, qwen2.5-coder-32b)  
   SQL injection plus thread-unsafe shared `Session` plus unchecked response parsing.

6. **[high/low] exploitgym/exploitgym/sandbox.py — validate `target_ip`, `net`, `cname`, `llm_hosts`; use subprocess arrays; check return codes** (models: ds, qwen2.5-coder-32b)  
   Empty/invalid IPs flow into iptables rules; shell-built docker commands are injectable; `_kali` failures are silently ignored.

7. **[high/low] exploitgym/demo_verified_findings.py + exploitgym/techniques/probe_techniques.py + exploitgym/exploitgym/operators/iterhunt.py — remove global TLS disable; scope `verify=False` to localhost demo only** (models: ds, qwen2.5-coder-32b)  
   `urllib3.disable_warnings()` and `s.verify=False` suppress certificate validation everywhere they're imported.

8. **[high/low] exploitgym/targets/misconfig/app.py — use `send_from_directory`; gate or filter `/debug` env dump** (model: ds)  
   Path traversal via `send_file(os.path.join(...))` and full environment exposure are both directly exploitable.

9. **[high/low] operator/board_feedback.py — require explicit `--execute` flag separate from `--verify` before running panel-returned code** (models: ds, qwen2.5-coder-32b)  
   Auto-executing model-generated code without sandbox or opt-in is a remote code execution path.

10. **[high/low] operator/aegis_operator.py — fix loop-guard signature counting (blocked call appended twice)** (model: ds)  
    Guard triggers after 2 identical calls instead of 3+, permanently poisoning the record.

11. **[high/low] operator/board_ask.py:104 — fix swapped system/user prompt arguments in `sol()`; remove duplicate `max_completion_tokens`** (model: ds)  
    Direct correctness bug affecting all `sol()` calls.

12. **[high/low] operator/campaign_ledger.py — hold lock for entire read-modify-write in `mark_consumed`; compute hash over stable serialization** (models: ds, qwen2.5-coder-32b)  
    Race condition corrupts ledger; mutable `consumed_by` in hash breaks chain integrity.

13. **[high/low] exploitgym/exploitgym/runner.py:35 — do not mutate `scenario.evidence.flag_value` in place** (model: ds)  
    Cross-run contamination when multiple scenarios share evidence objects.

14. **[high/low] exploitgym/exploitgym/verifier.py:128 — use `hmac.compare_digest`; require plausible flag format before accepting substring match** (models: ds, qwen2.5-coder-32b)  
    Plain substring matching accepts false positives; timing side-channel on flag comparison.

15. **[high/med] operator/aegis_operator.py — add schema-validation tests for every tool spec (required fields, types, gate flags, params used by handler)** (model: ds)  
    Tool spec drift silently breaks operator behavior.

16. **[high/med] operator/aegis_operator.py — treat `install_kali_tool` content as untrusted; require human approval + content hash/size limit** (model: ds)  
    Arbitrary code written to `/usr/local/bin` without verification.

17. **[med/low] operator/aegis_operator.py — use `secrets.token_urlsafe` for temp file tags; ensure `O_EXCL` creation** (model: ds)  
    Predictable temp filenames from `hash(time + inputs)` enable symlink attacks.

18. **[med/low] operator/board_ask.py:38 — parse `secret.env` as KEY=VALUE pairs only; reject executable content** (model: qwen2.5-coder-32b)  
    Executing arbitrary lines from an env file is a code injection vector.

19. **[med/low] exploitgym/exploitgym/audit.py — open audit log with 0o600; add file lock around append/replay** (models: qwen2.5-coder-32b, ds)  
    Audit log integrity is the trust anchor; world-readable or race-prone writes undermine it.

20. **[med/low] exploitgym/exploitgym/operators/claude.py + deepseek.py — use unique log filenames (timestamp/run id); remove `--dangerously-skip-permissions`** (models: ds, qwen2.5-coder-32b)  
    Log overwrites destroy evidence; skip-permissions defeats the sandbox's purpose.

21. **[med/low] exploitgym/exploitgym/scenario.py — don't include `marker_token`/`oob_token` in `to_operator_prompt`; validate evidence fields on load** (models: qwen2.5-coder-32b, ds)  
    Leaking verification tokens to the operator enables cheating; malformed evidence crashes at runtime.

22. **[med/low] operator/aegis_operator.py — add SSRF protections (deny link-local/localhost/metadata IPs) to `fetch_url`/`render_page`** (models: ds, qwen2.5-coder-32b)  
    Unrestricted URL fetching from the operator context can reach cloud metadata endpoints.

23. **[med/low] operator/aegis_operator.py — use lock/atomic write for `_BACKUPS`, `_append_ledger`, and `t_apply_edit`/`t_revert_file`** (models: qwen2.5-coder-32b, ds)  
    Concurrent tool calls can corrupt backups and ledger state.

24. **[med/low] operator/campaign_ledger.py — mark entries consumed only after successful anchor build; recompute hashes for refuted entries** (models: qwen2.5-coder-32b, ds)  
    Consuming before success loses entries on failure; refutation breaks hash chain.

25. **[med/low] exploitgym/exploitgym/verifier.py — read marker before/after run with per-run unique token; clamp score to ≥0; validate `oob_token` non-empty** (models: qwen2.5-coder-32b, ds)  
    Marker verification is currently static; negative scores and missing OOB tokens cause incorrect results.

26. **[med/med] operator/aegis_operator.py — split monolithic tool-spec dict and SYSTEM prompt into separate modules/data files** (models: qwen2.5-coder-32b, ds)  
    The 2000+ line file is untestable and unmaintainable; extraction enables the test coverage items above.

27. **[med/med] exploitgym/exploitgym/verifier.py — add unit tests for each evidence kind including failure cases** (models: qwen2.5-coder-32b, ds)  
    Verifier is security-critical and currently untested.

28. **[med/med] operator/board_discuss.py — add tests for `_parse_moves`, `_needs_full`, and discuss() fast/full paths; validate critique refs and move fields** (models: qwen2.5-coder-32b, ds)  
    Malformed model output crashes the board loop.

29. **[med/med] operator/campaign_ledger.py — add tests for hash-chain integrity and concurrent append/mark_consumed** (models: qwen2.5-coder-32b, ds)  
    Ledger corruption is silent and cascading.

30. **[low/low] exploitgym/bench_report.py + exploitgym/benchmark.py + exploitgym/exploitgym/report.py — use context managers; stop swallowing exceptions; validate JSON before `.get`** (models: qwen2.5-coder-32b, ds)  
    Silent data loss and misleading reports.

31. **[low/low] operator/board_feedback.py — make model configurable; add timeouts; use NamedTemporaryFile; parallelize panel verification** (models: qwen2.5-coder-32b, ds)  
    Hardcoded `gpt-5.6`, unbounded waits, and fixed temp filenames are operational risks.

32. **[low/low] exploitgym/exploitgym/operators/iterhunt.py — replace `sys.path` insertion with package-relative import; narrow broad excepts; record failures in audit trail** (models: qwen2.5-coder-32b, ds)  
    Path manipulation and silent failures hide operator errors.

33. **[low/low] exploitgym/exploitgym/sandbox.py — use random high port for OOB listener; add timeout to `serve_forever()`; check `_kali` return codes in `plant_flag`/`read_file`** (models: qwen2.5-coder-32b, ds)  
    Fixed port 8899 conflicts; hung listener blocks; failed flag planting goes undetected.

34. **[low/low] operator/aegis_operator.py — compile regex once; cache `_load_ledger`; avoid re-importing `re`; deduplicate curl invocations** (models: qwen2.5-coder-32b, ds)  
    Performance improvements in hot paths.

35. **[low/low] exploitgym/exploitgym/calibration.py — use `ProcessPoolExecutor` for CPU-bound runners; catch per-job exceptions** (models: qwen2.5-coder-32b, ds)  
    ThreadPoolExecutor underutilizes CPU-bound workloads; one failure aborts calibration.

---

## Suggestions by model

- **ds**: 305 suggestion(s)
- **qwen2.5-coder-32b**: 424 suggestion(s)

## All suggestions

| sev | area | file | change | model |
|---|---|---|---|---|
| high | security | `exploitgym/demo_verified_findings.py:14` | Remove `requests.packages.urllib3.disable_warnings()` to avoid suppressing SSL warnings. | qwen2.5-coder-32b |
| high | security | `exploitgym/demo_verified_findings.py:25` | Validate SSL certificates by removing `s.verify=False`. | qwen2.5-coder-32b |
| high | security | `exploitgym/demo_verified_findings.py:34` | Validate SSL certificates by removing `s.verify=False`. | qwen2.5-coder-32b |
| high | security | `exploitgym/demo_verified_findings.py:43` | Validate SSL certificates by removing `s.verify=False`. | qwen2.5-coder-32b |
| high | security | `exploitgym/demo_verified_findings.py:52` | Validate SSL certificates by removing `s.verify=False`. | qwen2.5-coder-32b |
| high | security | `exploitgym/demo_verified_findings.py:61` | Validate SSL certificates by removing `s.verify=False`. | qwen2.5-coder-32b |
| high | security | `exploitgym/demo_verified_findings.py:70` | Validate SSL certificates by removing `s.verify=False`. | qwen2.5-coder-32b |
| high | security | `exploitgym/eg_results/authz_selftest.py:15` | Remove hardcoded path EG and use environment variables or configuration files. | qwen2.5-coder-32b |
| high | test-coverage | `exploitgym/eg_results/authz_selftest.py:68` | Add comprehensive unit tests for the main function and HTTP request handling. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/audit.py:45` | Use a more secure hashing algorithm and consider cryptographic best practices. | qwen2.5-coder-32b |
| high | test-coverage | `exploitgym/exploitgym/audit.py:100` | Add unit tests for the verify method to ensure chain integrity checks work correctly. | qwen2.5-coder-32b |
| high | test-coverage | `exploitgym/exploitgym/calibration.py:62` | Add unit tests for the success_rate and check_monotonicity functions. | qwen2.5-coder-32b |
| high | test-coverage | `exploitgym/exploitgym/cli.py:53` | Add unit tests for the CLI commands and argument parsing. | qwen2.5-coder-32b |
| high | test-coverage | `exploitgym/exploitgym/operators/__init__.py:19` | Add unit tests for the operator registry and get function. | qwen2.5-coder-32b |
| high | robustness | `exploitgym/exploitgym/operators/claude.py:36` | Use a unique log filename (e.g. include timestamp or run id) instead of overwriting eg_{scenario.id}_{self.name}.log on every run. | ds |
| high | security | `exploitgym/exploitgym/operators/claude.py:45` | Remove the `--dangerously-skip-permissions` flag. | qwen2.5-coder-32b |
| high | robustness | `exploitgym/exploitgym/operators/deepseek.py:44` | Use a unique log filename (timestamp or run id) instead of overwriting eg_{scenario.id}_{self.name}.log. | ds |
| high | security | `exploitgym/exploitgym/operators/deepseek.py:59` | Remove the `--dangerously-skip-permissions` flag. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/report.py:10` | Handle file opening with a context manager to ensure files are properly closed. | qwen2.5-coder-32b |
| high | correctness | `exploitgym/exploitgym/runner.py:35` | Do not mutate scenario.evidence.flag_value in place; pass the planted flag explicitly to verify or use a per-run evidence copy. | ds |
| high | security | `exploitgym/exploitgym/runner.py:34` | Handle file opening with a context manager to ensure files are properly closed. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/runner.py:95` | Handle file opening with a context manager to ensure files are properly closed. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:91` | Validate `self.target_ip` before using it in iptables rules and reject empty/invalid values. | ds |
| high | robustness | `exploitgym/exploitgym/sandbox.py:91` | Check the return code of the `docker inspect` call and raise a clear error if it is nonzero or the IP is empty. | ds |
| high | security | `exploitgym/exploitgym/sandbox.py:101` | Use `shlex.quote()` or an array-based subprocess invocation for `t.build`, `t.cmd`, `t.env` values, and the docker command string instead of string interpolation into a shell. | ds |
| high | security | `exploitgym/exploitgym/sandbox.py:101` | Validate or sanitize `t.build` and `t.cmd` before passing them to the shell, or use `docker run` with an explicit command array. | ds |
| high | security | `exploitgym/exploitgym/sandbox.py:130` | Remove the import of `sys` inside the `provision` method. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:144` | Validate and sanitize the `t.build` input before using it in the `docker build` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:168` | Validate and sanitize the `self.target_ip` before using it in the `iptables` commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:181` | Validate and sanitize the `h` before using it in the `iptables` commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:193` | Validate and sanitize the `safe` before using it in the `getent ahostsv4` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:224` | Validate and sanitize the `path` before using it in the `docker exec` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:231` | Validate and sanitize the `path` before using it in the `docker exec` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:238` | Validate and sanitize the `cmd` before using it in the `docker exec` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:270` | Validate and sanitize the `path` before using it in the `docker exec` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:302` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:303` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:304` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:305` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:306` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:310` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:311` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:312` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:313` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:314` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:315` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:316` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:317` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:318` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:319` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:320` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:321` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:322` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:323` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:324` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:325` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/sandbox.py:326` | Validate and sanitize the `path` before using it in the `grep` command. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/scenario.py:112` | Remove default values for `flag_value`, `flag_path`, `marker_path`, `marker_token`, `oob_token` in the `Evidence` class. | qwen2.5-coder-32b |
| high | security | `exploitgym/exploitgym/scenario.py:112` | Ensure that `flag_value` is never logged or printed. | qwen2.5-coder-32b |
| high | correctness | `exploitgym/exploitgym/verifier.py:128` | Use hmac.compare_digest for the substring branch too, or at least avoid the plain `true_flag in captured` shortcut when the flag is known. | ds |
| high | security | `exploitgym/exploitgym/verifier.py:148` | Use a more secure method for comparing flags. | qwen2.5-coder-32b |
| high | security | `exploitgym/race_money.py:12` | Remove `s.verify=False` to enforce SSL certificate verification. | qwen2.5-coder-32b |
| high | security | `exploitgym/race_money.py:15` | Avoid using environment variables directly in SQL queries to prevent SQL injection. | qwen2.5-coder-32b |
| high | security | `exploitgym/race_money.py:21` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/race_money.py:37` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/race_money.py:43` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/race_money.py:58` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/race_money.py:64` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/race_money.py:76` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/race_money.py:82` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/race_money.py:88` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/targets/authz-erp/app.py:37` | Do not interpolate user-controlled uid directly into SQL in _session_user(); use a parameterized query or a strict UUID/identifier validator before interpolation. | ds |
| high | security | `exploitgym/targets/authz-erp/app.py:91` | Use a parameterized query or strict identifier validation for rid in the record lookup instead of string interpolation. | ds |
| high | security | `exploitgym/targets/authz-erp/app.py:116` | Use a parameterized query or strict identifier validation for uid in the UPDATE and SELECT statements. | ds |
| high | security | `exploitgym/targets/authz-erp/app.py:31` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/targets/authz-erp/app.py:43` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/targets/authz-erp/app.py:55` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/targets/authz-erp/app.py:61` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/targets/authz-erp/app.py:74` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/targets/authz-erp/app.py:80` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/targets/authz-erp/app.py:92` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/targets/authz-erp/app.py:98` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/targets/authz-erp/app.py:110` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/targets/authz-erp/app.py:116` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/targets/authz-erp/app.py:128` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/targets/authz-erp/app.py:134` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/targets/authz-erp/app.py:146` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/targets/authz-erp/app.py:152` | Use parameterized queries instead of string formatting for SQL commands. | qwen2.5-coder-32b |
| high | security | `exploitgym/targets/misconfig/app.py:21` | Use send_from_directory with a safe root instead of send_file(os.path.join('/srv/public', p)). | ds |
| high | security | `exploitgym/targets/misconfig/app.py:28` | Do not expose the full environment via /debug; filter secrets or gate the endpoint behind an explicit debug flag. | ds |
| high | security | `exploitgym/targets/misconfig/app.py:13` | Sanitize the user-supplied path in the `/files/<path:p>` route to prevent path traversal. | qwen2.5-coder-32b |
| high | security | `exploitgym/targets/misconfig/app.py:19` | Disable the `/debug` endpoint in production to prevent information leakage. | qwen2.5-coder-32b |
| high | security | `exploitgym/targets/supply-chain/app.py:19` | Use yaml.safe_load instead of yaml.load with the unsafe Loader. | ds |
| high | security | `exploitgym/targets/supply-chain/app.py:13` | Use `yaml.safe_load` instead of `yaml.load` to prevent unsafe deserialization. | qwen2.5-coder-32b |
| high | security | `exploitgym/techniques/probe_techniques.py:33` | Do not disable TLS certificate verification globally via requests.packages.urllib3.disable_warnings() and s.verify=False; use a session with a configured CA bundle or an explicit insecure flag only for the authorized test target. | ds |
| high | security | `exploitgym/techniques/probe_techniques.py:44` | Do not interpolate untrusted SQL strings directly into the psql -c argument; use a parameterized query or at minimum quote/escape identifiers and values with psycopg2/asyncpg. | ds |
| high | security | `exploitgym/techniques/probe_techniques.py:62` | Do not call the private store._transition() method; use the public verification API or add a supported method for marking a candidate verified. | ds |
| high | security | `exploitgym/techniques/probe_techniques.py:14` | Remove the disabling of urllib3 warnings. | qwen2.5-coder-32b |
| high | security | `exploitgym/techniques/probe_techniques.py:40` | Use environment variables for sensitive data like API keys and passwords. | qwen2.5-coder-32b |
| high | security | `exploitgym/techniques/probe_techniques.py:40` | Validate and sanitize all user inputs and environment variables. | qwen2.5-coder-32b |
| high | security | `exploitgym/techniques/probe_techniques.py:61` | Use parameterized queries to prevent SQL injection. | qwen2.5-coder-32b |
| high | security | `exploitgym/techniques/probe_techniques.py:87` | Validate and sanitize all inputs to subprocess calls. | qwen2.5-coder-32b |
| high | security | `exploitgym/techniques/probe_techniques.py:117` | Use HTTPS for all network communications. | qwen2.5-coder-32b |
| high | security | `exploitgym/techniques/probe_techniques.py:117` | Implement proper error handling and logging. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py` | Do not allow `--auto-approve` to be combined with `t_run_command` without an explicit additional opt-in flag or warning banner. | ds |
| high | security | `operator/aegis_operator.py` | Run `t_run_command` with `shell=False` and a command list, or at minimum require the command to be a fixed allowlist of subcommands. | ds |
| high | security | `operator/aegis_operator.py` | Validate or shell-quote the URL in t_render_page before interpolating it into the shell command string. | ds |
| high | security | `operator/aegis_operator.py` | Do not shell-quote user input by hand for t_rag_search/t_exploit_search; pass arguments as a list to subprocess instead of embedding them in a bash -lc string. | ds |
| high | security | `operator/aegis_operator.py` | Validate `sources` against an allow-list of known source names rather than only stripping characters. | ds |
| high | security | `operator/aegis_operator.py` | Validate and sanitize the URL before inlining it into the shell command in t_fingerprint_target; the current quote stripping is insufficient to prevent shell metacharacter injection. | ds |
| high | security | `operator/aegis_operator.py` | Use subprocess argument arrays or a safe templating mechanism instead of string-interpolating user-controlled values into _WP_TPL, _APACHE_VHOST, _NGINX_TPL, and _DOCKER_LEGACY_TPL. | ds |
| high | security | `operator/aegis_operator.py` | Validate and sanitize the `name` parameter before using it in `droot` and `spath` to prevent path traversal outside `/opt/bench/twins` and `/twins_dir`. | ds |
| high | security | `operator/aegis_operator.py` | Use `secrets.token_urlsafe` for the `tag` used in temp file names instead of a hash of time and inputs, or ensure the temp directory is private and files are created with `O_EXCL`. | ds |
| high | test-coverage | `operator/aegis_operator.py` | Add schema-validation tests that assert every tool spec has the expected required fields, types, and gate flags, and that required parameters are actually used by the corresponding handler. | ds |
| high | security | `operator/aegis_operator.py` | Treat `install_kali_tool` content as untrusted code and require explicit human approval plus a content hash/size limit before writing it to /usr/local/bin. | ds |
| high | security | `operator/aegis_operator.py` | Validate that the Cloudflare account ID and API token are non-empty before constructing the endpoint; otherwise the endpoint silently becomes 'https://api.cloudflare.com/client/v4/accounts//ai/v1' and requests leak the token to a malformed URL or fail confusingly. | ds |
| high | correctness | `operator/aegis_operator.py` | Fix the loop-guard signature counting so the blocked call is not appended twice, which makes the guard trigger after only 2 identical calls instead of the intended 3+ and can permanently poison the recent_sigs list. | ds |
| high | security | `operator/aegis_operator.py:208` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:222` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:236` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:248` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:261` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:275` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:289` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:303` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:317` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:331` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:345` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:359` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:373` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:387` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:401` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:415` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:429` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:443` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:457` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:471` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:485` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:499` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:513` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:527` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:541` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:555` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:569` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:583` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:597` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:611` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:625` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:639` | Validate and sanitize all user inputs before using them in subprocess calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2265` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2255` | Use `with open(s, 'r', encoding='utf-8') as f: man = json.load(f)` instead of `json.load(open(s, encoding='utf-8'))` to ensure the file is properly closed. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2260` | Use `with open(s, 'r', encoding='utf-8') as f: man = json.load(f)` instead of `json.load(open(s, encoding='utf-8'))` to ensure the file is properly closed. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2278` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2285` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2293` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2302` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2310` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2318` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2326` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2334` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2342` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2350` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2358` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2366` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2374` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2382` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2390` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2398` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2406` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2414` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2422` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2430` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2438` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2446` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2454` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2462` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2470` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2478` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2486` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2494` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2502` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2510` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2518` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2526` | Validate and sanitize all user inputs before using them in shell commands. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py` | Ensure all mutating tools (e.g., `run_in_kali`, `install_kali_tool`) are properly gated and require human approval. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py` | Implement logging for all tool calls, especially mutating ones, to maintain an audit trail. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py` | Implement a comprehensive validation and sanitization process for all user-provided inputs to prevent injection and other attacks. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:225` | Validate the `acct` variable before using it in the endpoint URL. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:231` | Validate the `key` variable before using it. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:234` | Validate the `endpoint` variable before making API calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:241` | Validate the `key` variable before using it. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:244` | Validate the `endpoint` variable before making API calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:249` | Validate the `key` variable before using it. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:252` | Validate the `endpoint` variable before making API calls. | qwen2.5-coder-32b |
| high | security | `operator/aegis_operator.py:2242` | Use a more secure hash function than MD5. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:53` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:68` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:85` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:94` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:102` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:107` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:112` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:117` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:122` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:127` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:132` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:137` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:142` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:147` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:152` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:157` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:162` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:167` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:172` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:177` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:182` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:187` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:192` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:197` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:202` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:207` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:212` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:217` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:222` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:227` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:232` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:237` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:242` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:247` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:252` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:257` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:262` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:267` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | security | `operator/attack_coverage.py:272` | Use context manager for file operations. | qwen2.5-coder-32b |
| high | correctness | `operator/board_ask.py:104` | Fix the sol() function: the system prompt and user prompt arguments are swapped in the _post call. | ds |
| high | correctness | `operator/board_ask.py:104` | Remove the duplicate max_completion_tokens in the extra dict for sol(); _post already sets it for OpenAI URLs. | ds |
| high | security | `operator/board_discuss.py:118` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:121` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:124` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:127` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:130` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:133` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:136` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:139` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:142` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:145` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:148` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:151` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:154` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:157` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:160` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:163` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:166` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:169` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:172` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:175` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:178` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:181` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:184` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:187` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:190` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:193` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:196` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:199` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:202` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:205` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:208` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:211` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:214` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_discuss.py:217` | Validate and sanitize environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_feedback.py:53` | Validate that the API key is non-empty before making requests and raise a clear error if missing. | ds |
| high | security | `operator/board_feedback.py:116` | Do not auto-execute panel-returned code without a sandbox or explicit opt-in confirmation; at minimum require --verify plus a separate --execute flag. | ds |
| high | security | `operator/board_feedback.py:14` | Remove the `pass` statement and handle the exception properly. | qwen2.5-coder-32b |
| high | security | `operator/board_feedback.py:27` | Validate and sanitize all environment variables before using them. | qwen2.5-coder-32b |
| high | security | `operator/board_feedback.py:49` | Use HTTPS for all API requests. | qwen2.5-coder-32b |
| high | security | `operator/board_feedback.py:54` | Ensure that the API keys are stored securely and not hard-coded. | qwen2.5-coder-32b |
| high | security | `operator/board_feedback.py:81` | Validate and sanitize all inputs to the `_post_llm` function. | qwen2.5-coder-32b |
| high | security | `operator/board_feedback.py:112` | Validate and sanitize all inputs to the `ask_panel` function. | qwen2.5-coder-32b |
| high | security | `operator/board_feedback.py:154` | Validate and sanitize all inputs to the `verify_panel_code` function. | qwen2.5-coder-32b |
| high | security | `operator/board_feedback.py:171` | Ensure that the `subprocess.run` call is safe from shell injection. | qwen2.5-coder-32b |
| high | security | `operator/board_feedback.py:194` | Validate and sanitize all inputs to the `one_round` function. | qwen2.5-coder-32b |
| high | security | `operator/board_feedback.py:213` | Validate and sanitize all command-line arguments. | qwen2.5-coder-32b |
| high | correctness | `operator/campaign_ledger.py:48` | Compute the event hash over a stable serialization that excludes the mutable 'consumed_by' list or freeze it before hashing. | ds |
| high | concurrency | `operator/campaign_ledger.py:71` | Hold self._lock for the entire read-modify-write cycle in mark_consumed, not only the file rewrite. | ds |
| high | security | `operator/campaign_ledger.py:38` | Use a more secure hashing algorithm than SHA-256 for event_hash. | qwen2.5-coder-32b |
| high | security | `operator/campaign_ledger.py:147` | Validate and sanitize all inputs to the append method. | qwen2.5-coder-32b |
| high | security | `operator/campaign_ledger.py:217` | Implement proper input validation and sanitization in resume_seeds. | qwen2.5-coder-32b |
| high | security | `operator/campaign_ledger.py:272` | Validate and sanitize inputs to _light_live. | qwen2.5-coder-32b |
| high | test-coverage | `operator/campaign_ledger.py:392` | Add comprehensive unit tests for all methods in CampaignLedger. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/bench_report.py:37` | Use a context manager or explicit close for the file opened in load_findings instead of relying on garbage collection. | ds |
| med | correctness | `exploitgym/bench_report.py:39` | Validate that parsed JSON lines are dicts before calling .get on them. | ds |
| med | robustness | `exploitgym/bench_report.py:42` | Do not silently swallow all exceptions when loading findings; log or collect failures so malformed files are visible. | ds |
| med | robustness | `exploitgym/bench_report.py:71` | Guard against missing keys in rates entries when formatting the hit-rate table. | ds |
| med | security | `exploitgym/bench_report.py:27` | Remove the blanket exception handling in `load_findings`. | qwen2.5-coder-32b |
| med | security | `exploitgym/bench_report.py:42` | Remove the blanket exception handling in `scenario_inventory`. | qwen2.5-coder-32b |
| med | security | `exploitgym/bench_report.py:57` | Remove the blanket exception handling in `eg_results`. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/benchmark.py:26` | Catch and record exceptions from runner per attempt instead of letting one failure abort the whole benchmark. | ds |
| med | security | `exploitgym/benchmark.py:26` | Remove the blanket exception handling in `run_benchmark`. | qwen2.5-coder-32b |
| med | security | `exploitgym/demo_verified_findings.py:10` | Do not disable TLS certificate verification globally; use a session-specific verify=False only for the localhost demo and document why. | ds |
| med | security | `exploitgym/demo_verified_findings.py:15` | Avoid interpolating untrusted values directly into SQL executed via docker exec; use parameterized queries or at least escape single quotes. | ds |
| med | test-coverage | `exploitgym/demo_verified_findings.py:52` | Add a test that runs this demo against a mocked or ephemeral target and asserts the ledger ends with two verified and one rejected finding. | ds |
| med | robustness | `exploitgym/eg_results/authz_selftest.py:10` | Replace the hardcoded absolute path EG with a path derived from the script's own location (e.g., Path(__file__).resolve().parents[1]) or an environment variable. | ds |
| med | correctness | `exploitgym/eg_results/authz_selftest.py:45` | Check that sb.provision() returned a usable URL before proceeding, and handle the case where the app never becomes ready instead of silently continuing. | ds |
| med | security | `exploitgym/eg_results/authz_selftest.py:30` | Validate and sanitize the URL before making HTTP requests. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/eg_results/authz_selftest.py:30` | Handle potential exceptions when parsing the response body. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/audit.py:33` | Validate the structure of each replayed JSON line in _replay and verify, catching KeyError/ValueError and returning a clear corruption message. | ds |
| med | security | `exploitgym/exploitgym/audit.py:48` | Open the audit log with os.open(path, O_WRONLY\|O_APPEND\|O_CREAT, 0o600) and wrap it in os.fdopen, or otherwise ensure restrictive permissions. | ds |
| med | robustness | `exploitgym/exploitgym/audit.py:48` | Add a per-process file lock (e.g., fcntl.flock on a sidecar lock file) around append and _replay/verify. | ds |
| med | robustness | `exploitgym/exploitgym/audit.py:58` | Handle file I/O exceptions more gracefully. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/audit.py:81` | Validate JSON data before processing. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/calibration.py:39` | Catch per-job exceptions in _one and return them as result objects or aggregate errors instead of letting one failed run abort the whole family. | ds |
| med | performance | `exploitgym/exploitgym/calibration.py:41` | Consider using process-based concurrency instead of threads for I/O-bound tasks. | qwen2.5-coder-32b |
| med | security | `exploitgym/exploitgym/cli.py:34` | Validate and sanitize command-line arguments. | qwen2.5-coder-32b |
| med | security | `exploitgym/exploitgym/operators/__init__.py:19` | Validate operator names to prevent injection attacks. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/claude.py:47` | Handle subprocess.CalledProcessError and generic OSError from subprocess.run, not just FileNotFoundError and TimeoutExpired. | ds |
| med | correctness | `exploitgym/exploitgym/operators/claude.py:52` | Set rr.seconds_used inside the try block immediately after subprocess.run returns, or compute it from the timeout exception context. | ds |
| med | correctness | `exploitgym/exploitgym/operators/claude.py:56` | Do not infer discovered/intended_path from the substring of the vulnerability name appearing in the transcript; use a verifier-provided ground-truth signal. | ds |
| med | robustness | `exploitgym/exploitgym/operators/deepseek.py:58` | Handle FileNotFoundError and generic OSError from subprocess.run, not just TimeoutExpired. | ds |
| med | correctness | `exploitgym/exploitgym/operators/deepseek.py:76` | Do not infer discovered/intended_path from the vulnerability name appearing in the operator log; use verifier ground truth. | ds |
| med | robustness | `exploitgym/exploitgym/operators/deepseek.py:105` | Add error handling for `_count_iters` function. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/deepseek.py:112` | Add error handling for `_extract_flag` function. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/deepseek.py:119` | Add error handling for `_mentions_vuln` function. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/deepseek.py:126` | Add error handling for `_ledger_metrics` function. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:26` | Replace the sys.path insertion with a package-relative import or an explicit, validated path constant instead of mutating sys.path at import time. | ds |
| med | correctness | `exploitgym/exploitgym/operators/iterhunt.py:57` | Guard sandbox.read_file(ev.flag_path) against exceptions, since the fallback expression is evaluated even when ev.flag_value is already truthy. | ds |
| med | correctness | `exploitgym/exploitgym/operators/iterhunt.py:91` | Validate that result.get('probe') is a dict before calling pr.get('verdict') and pr.get('kind'), or normalize the probe shape at dispatch time. | ds |
| med | correctness | `exploitgym/exploitgym/operators/iterhunt.py:98` | Validate that result.get('stateful') is a dict before calling sfx.get(...). | ds |
| med | correctness | `exploitgym/exploitgym/operators/iterhunt.py:105` | Validate that result.get('supply_chain') is a dict and that sc.get('vulnerable') is a list before indexing/slicing. | ds |
| med | correctness | `exploitgym/exploitgym/operators/iterhunt.py:112` | Validate that result.get('discovery') is a dict before calling dv.get(...). | ds |
| med | security | `exploitgym/exploitgym/operators/iterhunt.py:12` | Remove hardcoded path manipulation and use importlib instead. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:25` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:31` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:41` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:52` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:61` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:70` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:79` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:88` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:97` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:106` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:115` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:124` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:133` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:142` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:151` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:160` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:169` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:178` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:187` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:196` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:205` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:214` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:223` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:232` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:241` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:250` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:259` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:268` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:277` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:286` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:295` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:304` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:313` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:322` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/operators/iterhunt.py:331` | Handle specific exceptions instead of a general Exception. | qwen2.5-coder-32b |
| med | security | `exploitgym/exploitgym/operators/sol.py:40` | Do not log the resolved endpoint and model in the audit trail if the endpoint URL may contain embedded credentials or sensitive account identifiers. | ds |
| med | robustness | `exploitgym/exploitgym/report.py:13` | Use a context manager or explicit close when opening result JSON files instead of json.load(open(...)). | ds |
| med | robustness | `exploitgym/exploitgym/report.py:14` | Log or collect the exception when a result file fails to parse instead of silently passing. | ds |
| med | correctness | `exploitgym/exploitgym/report.py:26` | Validate that scorecard values are numeric before float/int conversion, or catch ValueError/TypeError per record. | ds |
| med | robustness | `exploitgym/exploitgym/report.py:10` | Specify the exception type in the except block to avoid catching unexpected exceptions. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/runner.py:40` | Ensure sb.kill() is safe to call if SandBox construction or provision fails before sb is fully initialized. | ds |
| med | robustness | `exploitgym/exploitgym/runner.py:47` | Wrap operator.run and verify in try/except to record the error in the result object and audit log before re-raising or returning a failed card. | ds |
| med | test-coverage | `exploitgym/exploitgym/runner.py:68` | Add tests for containment refusal, operator exception, audit-chain failure, and persistence-scan failure paths. | ds |
| med | robustness | `exploitgym/exploitgym/runner.py:95` | Specify the exception type in the except block to avoid catching unexpected exceptions. | qwen2.5-coder-32b |
| med | test-coverage | `exploitgym/exploitgym/runner.py:104` | Add unit tests for the `run` function. | qwen2.5-coder-32b |
| med | test-coverage | `exploitgym/exploitgym/runner.py:113` | Add unit tests for the `bench` function. | qwen2.5-coder-32b |
| med | security | `exploitgym/exploitgym/sandbox.py:91` | Validate `self.net` and `self.cname` against a strict pattern (e.g. `^[a-zA-Z0-9_-]+$`) before using them in shell commands. | ds |
| med | robustness | `exploitgym/exploitgym/sandbox.py:91` | Add a timeout or retry loop when waiting for the target container to obtain an IP address. | ds |
| med | correctness | `exploitgym/exploitgym/sandbox.py:91` | Use `docker inspect` with a format that returns only the IP and verify it is a valid IPv4 address before assigning `self.target_ip`. | ds |
| med | security | `exploitgym/exploitgym/sandbox.py:91` | Ensure `self.net` is created with `--internal` and verify the network is actually internal before attaching the target. | ds |
| med | robustness | `exploitgym/exploitgym/sandbox.py:91` | Check the return code of `_kali` in `apply_egress_allowlist` and raise if any iptables command fails. | ds |
| med | security | `exploitgym/exploitgym/sandbox.py:91` | Use `iptables -A {c} -d {self.target_ip}/32 -j ACCEPT` to explicitly specify a host mask. | ds |
| med | security | `exploitgym/exploitgym/sandbox.py:91` | Validate `self.llm_hosts` entries before using them in iptables rules and `getent` commands. | ds |
| med | robustness | `exploitgym/exploitgym/sandbox.py:91` | Use `subprocess.run` with a list argument instead of a shell string for `_kali` commands where possible. | ds |
| med | readability | `exploitgym/exploitgym/sandbox.py:131` | Use a more descriptive variable name than `_dbg`. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/exploitgym/scenario.py:118` | Make load_dir skip or report non-JSON files that fail to parse instead of aborting the whole directory load. | ds |
| med | security | `exploitgym/exploitgym/scenario.py:89` | Do not include marker_token or oob_token in to_operator_prompt; replace them with a placeholder such as 'the token you will be given'. | ds |
| med | correctness | `exploitgym/exploitgym/scenario.py:89` | Validate evidence.kind against the supported set and ensure the corresponding required fields are populated when loading a scenario. | ds |
| med | security | `exploitgym/exploitgym/scenario.py:112` | Validate and sanitize all inputs in the `from_dict` method. | qwen2.5-coder-32b |
| med | test-coverage | `exploitgym/exploitgym/scenario.py:112` | Add unit tests for the `from_dict` method. | qwen2.5-coder-32b |
| med | test-coverage | `exploitgym/exploitgym/scenario.py:112` | Add unit tests for the `to_operator_prompt` method. | qwen2.5-coder-32b |
| med | test-coverage | `exploitgym/exploitgym/scenario.py:112` | Add unit tests for the `load` method. | qwen2.5-coder-32b |
| med | test-coverage | `exploitgym/exploitgym/scenario.py:112` | Add unit tests for the `load_dir` function. | qwen2.5-coder-32b |
| med | correctness | `exploitgym/exploitgym/verifier.py:128` | Guard against `true_flag` being a substring of a much larger captured output by requiring the captured value to be a plausible flag capture (e.g., length bound or regex) before accepting substring match. | ds |
| med | correctness | `exploitgym/exploitgym/verifier.py:137` | For marker verification, read the marker path before and after the run and compare against a per-run unique token, not just `ev.marker_token in content`. | ds |
| med | robustness | `exploitgym/exploitgym/verifier.py:159` | Validate `oob_token` is non-empty before calling `received_token`, and handle the case where `oob_listener` is missing more explicitly. | ds |
| med | correctness | `exploitgym/exploitgym/verifier.py:166` | Use `card.chain_depth` from the verified prefix instead of overwriting it with `run_result.chain_depth` when scoring non-chain evidence. | ds |
| med | correctness | `exploitgym/exploitgym/verifier.py:178` | Do not add `w['chain_depth'] * min(card.chain_depth, _CHAIN_CAP)` for non-chain evidence when `card.chain_depth` comes from the operator. | ds |
| med | correctness | `exploitgym/exploitgym/verifier.py:181` | Do not add `w['novel_steps'] * min(card.novel_steps, _NOVEL_CAP)` for non-chain evidence when `card.novel_steps` comes from the operator. | ds |
| med | correctness | `exploitgym/exploitgym/verifier.py:183` | Clamp the final score to a minimum of 0 before returning. | ds |
| med | test-coverage | `exploitgym/exploitgym/verifier.py:68` | Add unit tests for `verify` covering each evidence kind (flag, marker, oob, chain) including failure cases, empty tokens, missing sandbox methods, and containment penalties. | ds |
| med | security | `exploitgym/exploitgym/verifier.py:154` | Add logging for failed flag captures. | qwen2.5-coder-32b |
| med | security | `exploitgym/exploitgym/verifier.py:166` | Add logging for failed marker reads. | qwen2.5-coder-32b |
| med | security | `exploitgym/exploitgym/verifier.py:182` | Add logging for failed OOB callbacks. | qwen2.5-coder-32b |
| med | security | `exploitgym/exploitgym/verifier.py:202` | Add logging for failed hop verifications. | qwen2.5-coder-32b |
| med | test-coverage | `exploitgym/exploitgym/verifier.py:227` | Add unit tests for the `_run_hop` function. | qwen2.5-coder-32b |
| med | test-coverage | `exploitgym/exploitgym/verifier.py:227` | Add unit tests for the `verify` function. | qwen2.5-coder-32b |
| med | robustness | `exploitgym/race_money.py:20` | Check the login response status and fail fast if authentication fails, instead of silently continuing with an unauthenticated session. | ds |
| med | robustness | `exploitgym/race_money.py:22` | Add a timeout to every requests call in sess() and the scenario functions, or configure a default timeout on the Session. | ds |
| med | security | `exploitgym/race_money.py:24` | Use subprocess argument arrays rather than a shell-like string for docker exec, and quote/escape identifiers when interpolating into SQL. | ds |
| med | correctness | `exploitgym/race_money.py:29` | Handle Barrier.wait() exceptions in worker threads so a broken barrier does not leave futures hanging or mask the real error. | ds |
| med | correctness | `exploitgym/race_money.py:39` | Do not reuse one requests.Session across all concurrent threads in fire(); create a session per worker or use a thread-safe client. | ds |
| med | correctness | `exploitgym/race_money.py:40` | Validate that the jobs list is non-empty before indexing [0], and handle missing fields explicitly. | ds |
| med | correctness | `exploitgym/race_money.py:42` | Use parameterized SQL or at least escape jid with a dedicated identifier-escaping function before interpolating into the count/aggregate queries. | ds |
| med | correctness | `exploitgym/race_money.py:53` | Check the deposit creation response for success and required fields before using dep["id"]. | ds |
| med | correctness | `exploitgym/race_money.py:57` | Escape invoice IDs before interpolating them into the SQL IN clause. | ds |
| med | correctness | `exploitgym/race_money.py:58` | The success criterion succ>1 is too weak for a double-spend claim; require both allocations to return 200 and verify the DB shows the deposit allocated to two invoices. | ds |
| med | correctness | `exploitgym/race_money.py:65` | Validate the invoice creation and item creation responses before reading total or posting payments. | ds |
| med | correctness | `exploitgym/race_money.py:68` | Escape iid before interpolating it into the SQL sum query. | ds |
| med | correctness | `exploitgym/targets/authz-erp/app.py:38` | Validate that _rows(out) is non-empty before indexing [0] in _session_user(). | ds |
| med | correctness | `exploitgym/targets/authz-erp/app.py:120` | Check the UPDATE return code before reporting success. | ds |
| med | robustness | `exploitgym/techniques/probe_techniques.py:38` | Check the login response status and raise or return an unauthenticated marker before issuing authenticated probes. | ds |
| med | robustness | `exploitgym/techniques/probe_techniques.py:44` | Use subprocess argument lists without shell=True and avoid embedding secrets in argv; pass PGPASSWORD via environment only and redact it from error output. | ds |
| med | robustness | `exploitgym/techniques/probe_techniques.py:53` | Check subprocess return codes and stderr for db() and src_grep(); do not treat a failed docker/wsl invocation as an empty result. | ds |
| med | correctness | `exploitgym/techniques/probe_techniques.py:62` | Ensure record() returns the finding ID even when verified is false, and handle record_candidate failures or duplicate candidates. | ds |
| med | correctness | `exploitgym/techniques/probe_techniques.py:72` | URL-encode traversal payloads before formatting them into the path, or use requests params/path escaping, rather than relying on raw payload strings. | ds |
| med | correctness | `exploitgym/techniques/probe_techniques.py:86` | Validate that tid is a non-empty numeric/identifier before interpolating it into the next SQL query. | ds |
| med | correctness | `exploitgym/techniques/probe_techniques.py:96` | Do not infer IDOR solely from HTTP 200 and response length > 50; inspect the response body for the expected job resource and confirm the technician is not the owner. | ds |
| med | correctness | `exploitgym/techniques/probe_techniques.py:108` | Check that job is non-empty before POSTing the SSTI payload, and verify the estimate ID exists before GETting it. | ds |
| med | correctness | `exploitgym/techniques/probe_techniques.py:121` | Do not mark ssrf.unguarded_outbound as a verified finding based only on static grep; record it as a candidate/hunch or require runtime callback confirmation. | ds |
| med | correctness | `exploitgym/techniques/probe_techniques.py:126` | Search for both fetch( and axios usage in the same file rather than using an OR that can miss one pattern when the other is absent. | ds |
| med | test-coverage | `exploitgym/techniques/probe_techniques.py:154` | Add unit tests for probe_path_traversal, probe_idor, probe_ssti, and probe_ssrf with mocked requests/db/src_grep to cover success, failure, and malformed-response paths. | ds |
| med | test-coverage | `exploitgym/techniques/probe_techniques.py:185` | Add unit tests for all probe functions. | qwen2.5-coder-32b |
| med | test-coverage | `exploitgym/techniques/probe_techniques.py:185` | Add integration tests to verify the interaction between different components. | qwen2.5-coder-32b |
| med | test-coverage | `exploitgym/techniques/probe_techniques.py:185` | Add tests for edge cases and error conditions. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py` | Add a timeout and size cap to `t_write_file` and `t_apply_edit` writes, and validate that the content is text before writing. | ds |
| med | security | `operator/aegis_operator.py` | Log the full command or file path in the audit log, not only a redacted preview, and ensure the audit log file itself is not writable by the operator process's working directory. | ds |
| med | correctness | `operator/aegis_operator.py` | In `t_read_file`, coerce `start_line` and `end_line` to integers with explicit error handling instead of relying on `int()` inside `max`/`min`. | ds |
| med | robustness | `operator/aegis_operator.py` | Use a lock around `_BACKUPS` and file writes in `t_write_file`/`t_apply_edit` if the operator loop can run tools concurrently. | ds |
| med | security | `operator/aegis_operator.py` | Validate `region` in `t_vpn_ctl` against a fixed allowlist before passing it to `subprocess.run`. | ds |
| med | test-coverage | `operator/aegis_operator.py` | Add unit tests for `_safe_repo_path`, `_safe_glob`, and `_is_secret_path` covering path traversal, absolute paths, symlinks, and credential-shaped filenames. | ds |
| med | robustness | `operator/aegis_operator.py` | Use a lock or atomic write for _BACKUPS and file edits in t_apply_edit/t_revert_file to avoid races between concurrent tool calls or sub-agents. | ds |
| med | robustness | `operator/aegis_operator.py` | In t_run_background, generate proc_id from a monotonically increasing counter or uuid instead of len(_PROCS)+1. | ds |
| med | robustness | `operator/aegis_operator.py` | In _proc_reader, guard against the process entry being removed from _PROCS before the reader thread finishes. | ds |
| med | robustness | `operator/aegis_operator.py` | In t_read_process_output, validate tail_lines is a positive integer and clamp it to a sane maximum. | ds |
| med | robustness | `operator/aegis_operator.py` | In t_kill_process, wait for the process to terminate and update pr['done']/pr['rc'] after kill. | ds |
| med | security | `operator/aegis_operator.py` | In t_remember, sanitize or escape the note before storing it in the JSON memory file. | ds |
| med | robustness | `operator/aegis_operator.py` | In t_recall, return an error or explicit empty result when the query regex is invalid instead of silently ignoring the exception. | ds |
| med | robustness | `operator/aegis_operator.py` | In _auto_verify, ensure VERIFY_CMD is a list or use shlex.split when shell=False, or document that shell=True is intentional. | ds |
| med | robustness | `operator/aegis_operator.py` | In t_finalize_report, validate that the response from _create has choices before accessing resp.choices[0]. | ds |
| med | test-coverage | `operator/aegis_operator.py` | Add unit tests for t_apply_edit/t_revert_file covering missing file, multiple matches, backup restore, and concurrent edit scenarios. | ds |
| med | test-coverage | `operator/aegis_operator.py` | Add tests for t_run_background/t_read_process_output/t_kill_process covering process lifecycle, output buffering, and kill behavior. | ds |
| med | test-coverage | `operator/aegis_operator.py` | Add tests for t_finalize_report with mocked transcript fetch and LLM client, including missing task, empty transcript, and API failure paths. | ds |
| med | robustness | `operator/aegis_operator.py` | Use a lock or atomic read-modify-write with os.replace in _append_ledger to prevent lost updates when multiple threads call it concurrently. | ds |
| med | robustness | `operator/aegis_operator.py` | In t_multi_edit, validate that edits is a list of dicts before calling ed.get, and reject empty old_string explicitly. | ds |
| med | security | `operator/aegis_operator.py` | Restrict t_fetch_url to private/research-safe destinations or at least enforce a deny-list for link-local, localhost, and cloud metadata IPs. | ds |
| med | test-coverage | `operator/aegis_operator.py` | Add unit tests for _append_ledger concurrency, t_multi_edit atomicity on duplicate/missing old_strings, and t_render_page URL shell-injection rejection. | ds |
| med | robustness | `operator/aegis_operator.py` | In t_rag_search, parse the last JSON line from stdout instead of assuming the entire stdout is JSON. | ds |
| med | robustness | `operator/aegis_operator.py` | In t_exploit_search, check p.returncode before treating non-empty stdout as success. | ds |
| med | test-coverage | `operator/aegis_operator.py` | Add unit tests for the shell-quoting paths in t_rag_search and t_exploit_search with hostile inputs (quotes, newlines, $(), backticks). | ds |
| med | robustness | `operator/aegis_operator.py` | In t_fingerprint_target, avoid writing the manifest to a path derived from the host without validating that the sanitized host is non-empty and not a reserved name. | ds |
| med | robustness | `operator/aegis_operator.py` | In t_fingerprint_target, handle the case where _kali returns a non-zero exit code or empty stdout instead of silently parsing empty segments. | ds |
| med | test-coverage | `operator/aegis_operator.py` | Add unit tests for t_fingerprint_target covering URL sanitization, manifest parsing, RAG term generation, and shell-injection attempts. | ds |
| med | test-coverage | `operator/aegis_operator.py` | Add integration tests for t_provision_twin with representative manifests (WordPress, legacy PHP/Symfony, nginx) to verify generated shell scripts and port allocation. | ds |
| med | security | `operator/aegis_operator.py` | Use `subprocess.run` with a list argument or `shlex.quote` for the `wsl` command instead of string interpolation. | ds |
| med | robustness | `operator/aegis_operator.py` | Handle the case where `p.stdout` or `p.stderr` is `None` before slicing in the return statement. | ds |
| med | correctness | `operator/aegis_operator.py` | Fix the operator precedence in the `legacy_php` boolean expression by adding parentheses. | ds |
| med | security | `operator/aegis_operator.py` | Validate `add_wordlist_url` more strictly, e.g., require it to be a URL with a safe scheme and host, and avoid shell interpolation of the URL. | ds |
| med | test-coverage | `operator/aegis_operator.py` | Add unit tests for the twin provisioning function covering path traversal attempts, invalid manifests, and each tech branch. | ds |
| med | design | `operator/aegis_operator.py` | Split the monolithic tool-spec dictionary and SYSTEM prompt into separate modules or data files so the operator schema and doctrine can be versioned, tested, and localized independently. | ds |
| med | robustness | `operator/aegis_operator.py` | Validate the `severity`, `principal`, and `status` arguments in `record_finding` against the documented enums before persisting to the ledger. | ds |
| med | security | `operator/aegis_operator.py` | For gated tools such as `run_in_kali`, `install_kali_tool`, and `git_commit`, enforce allow-list validation or explicit human-approval metadata rather than relying only on the `gated` boolean in the spec. | ds |
| med | correctness | `operator/aegis_operator.py` | Ensure `multi_edit` truly applies edits atomically and rejects the whole batch if any `old_string` is missing or duplicated. | ds |
| med | security | `operator/aegis_operator.py` | Add SSRF protections and scheme/host allow-listing to `fetch_url` and `render_page` before they are exposed to the model. | ds |
| med | robustness | `operator/aegis_operator.py` | Validate and normalize the `transport`, `container`, and `dest` arguments in `port_fix_to_mirror` and `verify_fix_on_mirror` before executing any copy or apply operation. | ds |
| med | test-coverage | `operator/aegis_operator.py` | Add integration tests for the remediation closed loop (`remediation` -> `port_fix_to_mirror` -> `verify_fix_on_mirror`) using a disposable container or temp directory. | ds |
| med | robustness | `operator/aegis_operator.py` | In _save_session, ensure the parent directory of `path` exists before writing the temp file, or catch and report the specific OSError so a missing directory does not silently lose the session. | ds |
| med | correctness | `operator/aegis_operator.py` | In _load_session, guard against `d` being a non-dict JSON value (e.g. a list or string) before calling d.get, otherwise the exception is swallowed and the session is silently discarded. | ds |
| med | robustness | `operator/aegis_operator.py` | In _maybe_compact, verify that `cut` is at least `head` and that the resulting message list still starts with the system message before returning it; the current while loop can move `cut` below `head` only if the tail is entirely tool messages, which is not handled. | ds |
| med | test-coverage | `operator/aegis_operator.py` | Add unit tests for _resolve_key_endpoint covering all three providers, missing environment variables, Master fallback, and the empty-account-id Cloudflare case. | ds |
| med | test-coverage | `operator/aegis_operator.py` | Add tests for _maybe_compact that exercise the cut-point adjustment when the tail contains tool messages, the head-preservation logic, and the summarization failure fallback. | ds |
| med | robustness | `operator/aegis_operator.py` | Guard the auto-verify path against non-JSON tool results before calling json.loads(result). | ds |
| med | robustness | `operator/aegis_operator.py` | In the finish() handling, validate that result is JSON before json.loads(result).get("summary"). | ds |
| med | correctness | `operator/aegis_operator.py` | Use a bounded deque or cap the length of recent_sigs to prevent unbounded growth over long agent loops. | ds |
| med | security | `operator/aegis_operator.py` | Do not interpolate raw tool result content into the debug print without length/sanitization beyond the 400-character slice. | ds |
| med | correctness | `operator/aegis_operator.py` | In run(), make the remediate_on_finish verified-count fallback safer by distinguishing a counting error from an actual zero count. | ds |
| med | test-coverage | `operator/aegis_operator.py` | Add unit tests for the loop-guard counting behavior, non-JSON tool result handling, and finish() summary fallback. | ds |
| med | test-coverage | `operator/aegis_operator.py:2265` | Add unit tests for the _skill_preface function. | qwen2.5-coder-32b |
| med | test-coverage | `operator/aegis_operator.py:2265` | Add unit tests for the `t_rag_search` function. | qwen2.5-coder-32b |
| med | test-coverage | `operator/aegis_operator.py:2265` | Add unit tests for the `t_exploit_search` function. | qwen2.5-coder-32b |
| med | test-coverage | `operator/aegis_operator.py:2265` | Add unit tests for the `_ds_chat_json` function. | qwen2.5-coder-32b |
| med | test-coverage | `operator/aegis_operator.py:2265` | Add unit tests for the `t_plan_and_execute` function. | qwen2.5-coder-32b |
| med | test-coverage | `operator/aegis_operator.py:2265` | Add unit tests for the `t_remediation` function. | qwen2.5-coder-32b |
| med | test-coverage | `operator/aegis_operator.py:2265` | Add unit tests for the `t_port_fix_to_mirror` function. | qwen2.5-coder-32b |
| med | readability | `operator/aegis_operator.py:2265` | Refactor the large function `t_provision_twin` into smaller, more manageable functions. | qwen2.5-coder-32b |
| med | readability | `operator/aegis_operator.py:2270` | Replace `name or ('twin_' + host)` with `name if name else ('twin_' + host)` for clarity. | qwen2.5-coder-32b |
| med | security | `operator/aegis_operator.py` | Validate and sanitize all inputs to functions like `fetch_url`, `render_page`, and `run_in_kali` to prevent injection attacks. | qwen2.5-coder-32b |
| med | security | `operator/aegis_operator.py` | Ensure that the `git_commit` function includes a mechanism to verify the integrity of the commit message before committing. | qwen2.5-coder-32b |
| med | security | `operator/aegis_operator.py` | Implement a timeout mechanism for network-related functions such as `fetch_url` and `render_page` to handle potential hangs. | qwen2.5-coder-32b |
| med | security | `operator/aegis_operator.py` | Ensure that the `install_kali_tool` function verifies the integrity of the tool being installed, possibly through checksum validation. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:268` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:275` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:282` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:289` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:296` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:303` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:310` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:317` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:324` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:331` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:338` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:345` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:352` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:359` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:366` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:373` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:380` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:387` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:394` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:401` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:408` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:415` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:422` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:429` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:436` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:443` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:450` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | robustness | `operator/aegis_operator.py:457` | Handle the case where `Master` is not defined. | qwen2.5-coder-32b |
| med | performance | `operator/aegis_operator.py:2242` | Use a more efficient serialization method than json.dumps with sort_keys=True. | qwen2.5-coder-32b |
| med | robustness | `operator/attack_coverage.py:30` | Use a context manager or explicit close for the file opened in _techniques_db instead of json.load(open(...)). | ds |
| med | robustness | `operator/attack_coverage.py:72` | Use a context manager for the fallback file read in _verified_ids instead of open(sp, encoding="utf-8") without closing. | ds |
| med | robustness | `operator/attack_coverage.py:92` | Use a context manager for the output file in main instead of json.dump(layer, open(a.out, "w", encoding="utf-8"), indent=2). | ds |
| med | security | `operator/board_ask.py:38` | Do not load secret.env by executing arbitrary lines; parse only KEY=VALUE pairs and reject or sanitize unexpected content. | ds |
| med | robustness | `operator/board_ask.py:57` | Add explicit timeout and error handling around urllib.request.urlopen in _post to avoid hanging indefinitely on network failures. | ds |
| med | robustness | `operator/board_discuss.py:103` | Validate that max_tokens is a positive integer before passing it to _post_openai_style or cf_agent.ask. | ds |
| med | correctness | `operator/board_discuss.py:126` | In _parse_moves, strip trailing commas only when the line is a standalone JSON object; do not strip commas inside a JSON array fallback. | ds |
| med | correctness | `operator/board_discuss.py:186` | In _critique, ensure each critique's 'ref' index is validated against the actual proposal list length before use. | ds |
| med | robustness | `operator/board_discuss.py:205` | In _converge, validate that each returned move contains the required fields (surface, vuln_class, etc.) and skip or repair malformed moves instead of returning them raw. | ds |
| med | correctness | `operator/board_discuss.py:258` | In _needs_full, handle non-integer values for AEGIS_BOARD_FULL_STALL and AEGIS_BOARD_FULL_EVERY gracefully instead of letting int() raise ValueError. | ds |
| med | test-coverage | `operator/board_discuss.py:279` | Add unit tests for _parse_moves covering JSON lines, JSON array fallback, malformed lines, and prose-prefixed objects; and for _needs_full covering pivot/stall/every-N logic. | ds |
| med | test-coverage | `operator/board_discuss.py:279` | Add integration tests that mock _ask to return canned model outputs and verify discuss() returns correctly shaped moves and transcript for fast and full paths. | ds |
| med | robustness | `operator/board_discuss.py` | Log the swallowed exception in board_discuss instead of silently returning [] so operator failures are diagnosable. | ds |
| med | performance | `operator/board_discuss.py:12` | Consider using a set for `seen` to avoid repeated membership checks. | qwen2.5-coder-32b |
| med | robustness | `operator/board_feedback.py:53` | Catch urllib.error.HTTPError/URLError in _post_llm and return a structured error string instead of letting the exception propagate. | ds |
| med | correctness | `operator/board_feedback.py:59` | Check r.get('choices') is non-empty before indexing [0] to avoid IndexError on malformed API responses. | ds |
| med | robustness | `operator/board_feedback.py:68` | Use a context manager or explicit close for the file handle in board(). | ds |
| med | security | `operator/board_feedback.py:74` | Sanitize the 'who' and 'tag' parameters before interpolating into the board filename. | ds |
| med | correctness | `operator/board_feedback.py:83` | Remove the hardcoded 'gpt-5.6' model name and make it configurable via environment or argument. | ds |
| med | robustness | `operator/board_feedback.py:98` | Add a per-thread timeout to thread.join() and report non-responsive panel members. | ds |
| med | correctness | `operator/board_feedback.py:108` | Validate that answers is non-empty before synthesizing; if all panel calls failed, skip synthesis or return a clear error. | ds |
| med | robustness | `operator/board_feedback.py:116` | Check subprocess return code and stderr in verify_panel_code; currently only stdout is inspected. | ds |
| med | test-coverage | `operator/board_feedback.py:168` | Add unit tests for _post_llm's OpenAI parameter rewriting, board filename generation, and summary_of with empty/malformed stores. | ds |
| med | robustness | `operator/campaign_ledger.py:34` | Use a context manager or explicit close when opening the ledger file in _load to avoid a ResourceWarning on some interpreters. | ds |
| med | robustness | `operator/campaign_ledger.py:57` | Add fsync or at least flush+os.fsync after appending an entry before returning success. | ds |
| med | correctness | `operator/campaign_ledger.py:66` | Do not mutate ledger entries in confirmed_footholds/seen_fingerprints; return copies or document the side effect. | ds |
| med | correctness | `operator/campaign_ledger.py:82` | In resume_seeds, mark entries consumed only after successfully building the anchor list, or make mark_consumed transactional. | ds |
| med | correctness | `operator/campaign_ledger.py:100` | In _refute, recompute or invalidate event_hash/prev_hash for refuted entries and their dependents before rewriting. | ds |
| med | concurrency | `operator/campaign_ledger.py:104` | Acquire led._lock around the mutation loop in _refute, not only inside _rewrite. | ds |
| med | robustness | `operator/campaign_ledger.py:112` | Validate that session_for_role returns an object with a get method before calling it in _light_live. | ds |
| med | security | `operator/campaign_ledger.py:116` | Do not disable TLS verification unconditionally in _light_live; make verify configurable or default to True. | ds |
| med | correctness | `operator/campaign_ledger.py:145` | In relay_prepare, compute the anchor cap before marking entries consumed, and only mark the entries that survive the cap. | ds |
| med | correctness | `operator/campaign_ledger.py:168` | In relay_finalize, pass the original move's fingerprint-relevant fields (surface, technique, vuln_class, oracle, action_intent) when appending the lazy note, or use a distinct fingerprint. | ds |
| med | test-coverage | `operator/campaign_ledger.py:174` | Add unit tests for hash-chain integrity after mark_consumed and _refute, and for concurrent append/mark_consumed interleavings. | ds |
| med | error handling | `operator/campaign_ledger.py:103` | Handle exceptions in _load more gracefully. | qwen2.5-coder-32b |
| med | performance | `operator/campaign_ledger.py:115` | Optimize _last_hash by caching the last hash. | qwen2.5-coder-32b |
| med | performance | `operator/campaign_ledger.py:245` | Optimize _refute by avoiding multiple writes to the file. | qwen2.5-coder-32b |
| med | performance | `operator/campaign_ledger.py:325` | Optimize relay_prepare by reducing the number of times the ledger is accessed. | qwen2.5-coder-32b |
| low | robustness | `exploitgym/bench_report.py:51` | Use a context manager for opening scenario JSON files. | ds |
| low | robustness | `exploitgym/bench_report.py:61` | Use a context manager for opening eg_results JSON files. | ds |
| low | robustness | `exploitgym/bench_report.py:75` | Escape or sanitize scenario/result fields before injecting them into Markdown table rows. | ds |
| low | robustness | `exploitgym/bench_report.py:116` | Use a context manager when writing the output report. | ds |
| low | readability | `exploitgym/bench_report.py:117` | Use list comprehensions for more concise and readable code. | qwen2.5-coder-32b |
| low | readability | `exploitgym/bench_report.py:125` | Use list comprehensions for more concise and readable code. | qwen2.5-coder-32b |
| low | readability | `exploitgym/bench_report.py:133` | Use list comprehensions for more concise and readable code. | qwen2.5-coder-32b |
| low | correctness | `exploitgym/benchmark.py:28` | Use statistics.stdev instead of pstdev for sample standard deviation when repeats is small. | ds |
| low | correctness | `exploitgym/benchmark.py:37` | Use statistics.variance instead of pvariance for per-operator aggregate variance. | ds |
| low | robustness | `exploitgym/benchmark.py:63` | Use a context manager when writing BENCHMARK_RUN.md. | ds |
| low | readability | `exploitgym/benchmark.py:43` | Use list comprehensions for more concise and readable code. | qwen2.5-coder-32b |
| low | readability | `exploitgym/benchmark.py:53` | Use list comprehensions for more concise and readable code. | qwen2.5-coder-32b |
| low | readability | `exploitgym/demo_verified_findings.py:1` | Move the module docstring to the top of the file before the import statement. | ds |
| low | duplication | `exploitgym/demo_verified_findings.py:2` | Remove the duplicate `import os` on line 2 since os is already imported on line 1. | ds |
| low | robustness | `exploitgym/demo_verified_findings.py:20` | Check subprocess return code and stderr in db() instead of only returning stdout. | ds |
| low | robustness | `exploitgym/demo_verified_findings.py:23` | Use a temporary directory or unique path instead of hardcoding /tmp/eg_findings.jsonl. | ds |
| low | duplication | `exploitgym/demo_verified_findings.py:24` | Remove the redundant second FindingStore construction after deleting the file. | ds |
| low | robustness | `exploitgym/demo_verified_findings.py:30` | Validate API responses before indexing into them (e.g., .json()[0]["id"]). | ds |
| low | robustness | `exploitgym/demo_verified_findings.py:38` | Validate API responses before indexing into them in check_unbounded_payroll. | ds |
| low | robustness | `exploitgym/demo_verified_findings.py:44` | Validate API responses before indexing into them in check_tech_reads_all. | ds |
| low | robustness | `exploitgym/eg_results/authz_selftest.py:26` | Use a context manager or try/finally to close the HTTP response object returned by urlopen. | ds |
| low | performance | `exploitgym/eg_results/authz_selftest.py:47` | Use a more efficient waiting mechanism instead of polling. | qwen2.5-coder-32b |
| low | correctness | `exploitgym/exploitgym/audit.py:58` | In verify, also reject entries whose seq is less than or equal to the previous seq, not just != expected. | ds |
| low | performance | `exploitgym/exploitgym/calibration.py:39` | Use ProcessPoolExecutor instead of ThreadPoolExecutor if runner.run is CPU-bound or uses subprocesses that block the GIL. | ds |
| low | correctness | `exploitgym/exploitgym/calibration.py:49` | Handle result objects that are not dicts or lack a scorecard key in success_rate. | ds |
| low | robustness | `exploitgym/exploitgym/cli.py:52` | Validate that --operators contains only known operator names before starting runs. | ds |
| low | robustness | `exploitgym/exploitgym/coverage_matrix.py:8` | Raise a clear ImportError if the canonical shared/coverage_matrix.py file does not exist. | ds |
| low | readability | `exploitgym/exploitgym/coverage_matrix.py:12` | Use importlib.import_module with a proper package path instead of manual spec loading and globals update. | ds |
| low | performance | `exploitgym/exploitgym/operators/deepseek.py:102` | Read the log file once and pass its content to _count_iters, _extract_flag, and _mentions_vuln instead of opening it three separate times. | ds |
| low | robustness | `exploitgym/exploitgym/operators/deepseek.py:118` | Use a context manager or explicit close for json.load(open(...)) in _ledger_metrics. | ds |
| low | robustness | `exploitgym/exploitgym/operators/iterhunt.py:31` | Log or surface the fallback no-op brainstorm when the operator package is not importable, rather than silently degrading. | ds |
| low | robustness | `exploitgym/exploitgym/operators/iterhunt.py:48` | Narrow the broad except around rag_refresh to catch only expected import/runtime errors and record the failure in the audit trail. | ds |
| low | robustness | `exploitgym/exploitgym/operators/iterhunt.py:53` | Avoid mutating global urllib3 warning state inside run(); use a session-level or context-local configuration instead. | ds |
| low | robustness | `exploitgym/exploitgym/operators/iterhunt.py:66` | Record session_factory import/initialization failures in the audit trail instead of silently setting _sfr to None. | ds |
| low | readability | `exploitgym/exploitgym/operators/iterhunt.py:74` | Extract the nested execute/oracle closures into small private methods or module-level helpers to reduce run() length and improve testability. | ds |
| low | correctness | `exploitgym/exploitgym/operators/iterhunt.py:119` | Use a dedicated exception type or result field for sandbox.read_file failures in the marker branch instead of silently treating them as no marker. | ds |
| low | robustness | `exploitgym/exploitgym/operators/iterhunt.py:137` | Record planner import/initialization failures in the audit trail instead of silently setting sess to None. | ds |
| low | robustness | `exploitgym/exploitgym/operators/iterhunt.py:146` | Record novel_code import/initialization failures in the audit trail instead of silently setting code_writer to None. | ds |
| low | robustness | `exploitgym/exploitgym/operators/iterhunt.py:154` | Record hunt_strategies import failures in the audit trail instead of silently setting _deepen/_mutate to None. | ds |
| low | correctness | `exploitgym/exploitgym/operators/iterhunt.py:162` | Guard relay_finalize's access to rep.get('confirmed') against a missing or non-list value before iterating. | ds |
| low | correctness | `exploitgym/exploitgym/operators/iterhunt.py:170` | Handle sandbox methods returning non-list/non-int values more defensively in the containment-event aggregation loop. | ds |
| low | robustness | `exploitgym/exploitgym/operators/sol.py:42` | Validate that SOL_ENDPOINT is a well-formed http(s) URL before passing it to the subprocess environment. | ds |
| low | correctness | `exploitgym/exploitgym/operators/sol.py:46` | Ensure _extra_env is initialized in DeepSeekOperator.__init__ or reset per run so repeated run() calls do not retain stale provider settings. | ds |
| low | readability | `exploitgym/exploitgym/report.py:44` | Extract the per-cell formatting expression into a named helper or clearer conditional. | ds |
| low | readability | `exploitgym/exploitgym/report.py:29` | Use f-string for string formatting in the leaderboard function. | qwen2.5-coder-32b |
| low | readability | `exploitgym/exploitgym/report.py:44` | Use f-string for string formatting in the leaderboard function. | qwen2.5-coder-32b |
| low | readability | `exploitgym/exploitgym/report.py:61` | Use f-string for string formatting in the leaderboard function. | qwen2.5-coder-32b |
| low | robustness | `exploitgym/exploitgym/runner.py:62` | Use a context manager for writing the result JSON file. | ds |
| low | design | `exploitgym/exploitgym/runner.py:66` | Add an optional timeout parameter to run/bench and enforce it around operator execution. | ds |
| low | performance | `exploitgym/exploitgym/sandbox.py:91` | Cache the result of `docker network inspect` for the gateway IP instead of calling it on every `start_oob_listener`. | ds |
| low | robustness | `exploitgym/exploitgym/sandbox.py:91` | Add a timeout to the OOB listener's `serve_forever()` or ensure it is terminated reliably in `kill()`. | ds |
| low | security | `exploitgym/exploitgym/sandbox.py:91` | Use a random high port for the OOB listener instead of hardcoding 8899. | ds |
| low | correctness | `exploitgym/exploitgym/sandbox.py:91` | Escape or validate `path` in `plant_flag` and `read_file` before interpolating into `docker exec` commands. | ds |
| low | robustness | `exploitgym/exploitgym/sandbox.py:91` | Check the return code of `_kali` in `plant_flag` and `read_file` and raise or log on failure. | ds |
| low | correctness | `exploitgym/exploitgym/sandbox.py:91` | Use `docker exec` with `--user` or ensure the flag file is readable by the intended process. | ds |
| low | robustness | `exploitgym/exploitgym/sandbox.py:91` | Add a timeout to `_kali` calls in `kill()` to prevent teardown from hanging indefinitely. | ds |
| low | security | `exploitgym/exploitgym/sandbox.py:91` | Use `iptables -D OUTPUT -j {c}` with a check for existence before deletion to avoid accidentally deleting a different rule. | ds |
| low | robustness | `exploitgym/exploitgym/scenario.py:118` | Use os.scandir or check os.path.isfile before opening entries returned by os.listdir. | ds |
| low | design | `exploitgym/exploitgym/scenario.py:89` | Move the operator-prompt rendering out of the dataclass or make it a separate presenter function. | ds |
| low | readability | `exploitgym/exploitgym/scenario.py:112` | Add type hints to the `hops` field in the `Evidence` class. | qwen2.5-coder-32b |
| low | readability | `exploitgym/exploitgym/scenario.py:112` | Use more descriptive variable names in the `to_operator_prompt` method. | qwen2.5-coder-32b |
| low | robustness | `exploitgym/exploitgym/verified_findings.py:20` | Guard the module execution and re-export with an explicit ImportError or RuntimeError if the canonical shared module cannot be loaded. | ds |
| low | readability | `exploitgym/exploitgym/verified_findings.py:20` | Use a small explicit __all__ or named re-exports instead of globals().update over all public module attributes. | ds |
| low | robustness | `exploitgym/exploitgym/verifier.py:185` | Round `card.progression_score` and `card.score` consistently, and consider using `Decimal` for monetary-like scoring. | ds |
| low | robustness | `exploitgym/exploitgym/verifier.py:96` | In `_run_hop`, catch and log the exception details instead of silently returning an error receipt. | ds |
| low | robustness | `exploitgym/exploitgym/verifier.py:100` | Validate that `check['sql']` exists before constructing `DbOracle` to avoid a KeyError being swallowed as a generic failure. | ds |
| low | robustness | `exploitgym/exploitgym/verifier.py:111` | Validate that `check['path']` is a string and starts with '/' before passing to `HttpOracle`. | ds |
| low | design | `exploitgym/exploitgym/verifier.py:51` | Consider making `verify_from_findings` reuse the same scoring logic as `verify` to avoid duplicated weight calculations. | ds |
| low | correctness | `exploitgym/race_money.py:34` | Remove the duplicate FindingStore construction and file removal; create the store once after removing the old file. | ds |
| low | robustness | `exploitgym/targets/authz-erp/app.py:48` | Handle BrokenPipeError/ConnectionResetError when writing the response body. | ds |
| low | robustness | `exploitgym/targets/authz-erp/app.py:53` | Reject or handle Content-Length values that are negative or unreasonably large. | ds |
| low | robustness | `exploitgym/techniques/probe_techniques.py:152` | Use a context manager or explicit close for the catalog.json file handle. | ds |
| low | robustness | `operator/aegis_operator.py` | Catch `requests.exceptions.RequestException` in `t_get_status`, `t_read_task_context`, and `t_submit` and return a JSON error instead of letting the exception propagate. | ds |
| low | performance | `operator/aegis_operator.py` | In `t_search_code`, compile the regex once per call and avoid re-reading the same file for every pattern match. | ds |
| low | performance | `operator/aegis_operator.py` | In t_search_docs, use a context manager or explicit close for the file opened via open(). | ds |
| low | robustness | `operator/aegis_operator.py` | In t_finalize_report, truncate or summarize the draft before sending it to the LLM if it is extremely large. | ds |
| low | robustness | `operator/aegis_operator.py` | In _append_ledger, write the temp file in the same directory as LEDGER_FILE and fsync before os.replace to reduce corruption risk on crash. | ds |
| low | performance | `operator/aegis_operator.py` | Cache _load_ledger in memory and invalidate on append instead of reading and parsing the whole JSON file on every record_finding/chain_state call. | ds |
| low | robustness | `operator/aegis_operator.py` | In t_git_log, clamp n to a sane positive range (e.g. 1..100) instead of passing arbitrary int(n) to git. | ds |
| low | performance | `operator/aegis_operator.py` | Avoid re-importing `re` inside _ds_chat_json when it is already imported at module scope. | ds |
| low | robustness | `operator/aegis_operator.py` | In t_plan_and_execute, guard against `out` lacking a 'graph' key before iterating it. | ds |
| low | performance | `operator/aegis_operator.py` | In t_fingerprint_target, deduplicate the repeated curl invocations for phpinfo.php, p.php, and info.php into a single loop or parallel requests. | ds |
| low | robustness | `operator/aegis_operator.py` | Use a context manager or `try/finally` to ensure the temp files are deleted even if an exception occurs before the cleanup command. | ds |
| low | performance | `operator/aegis_operator.py` | Avoid calling `hash()` on a tuple of potentially large input lines; use a cryptographic hash or a random token for the `tag`. | ds |
| low | readability | `operator/aegis_operator.py` | Extract the twin provisioning logic into smaller helper functions to reduce the complexity of the main function. | ds |
| low | design | `operator/aegis_operator.py` | Move the long tool descriptions out of the runtime spec and into a separate documentation/help registry keyed by tool name. | ds |
| low | performance | `operator/aegis_operator.py` | Cache the result of _transcript_size or compute it incrementally instead of re-serializing every message on each loop iteration. | ds |
| low | design | `operator/aegis_operator.py` | Extract the repeated provider/key resolution logic in _resolve_key_endpoint into a small dataclass or helper that returns a structured config, so the three branches do not duplicate environment/Master fallback patterns. | ds |
| low | robustness | `operator/aegis_operator.py` | In _agent_loop, when json.loads fails on tool call arguments, log the raw arguments at debug level so malformed tool calls are diagnosable instead of silently treated as empty. | ds |
| low | design | `operator/aegis_operator.py` | Extract the duplicated client/key resolution and _CTX initialization between run() and run_chat() into a shared helper. | ds |
| low | performance | `operator/aegis_operator.py:2271` | Cache the result of `abs(hash(name))` to avoid recalculating it multiple times. | qwen2.5-coder-32b |
| low | security | `operator/aegis_operator.py` | Consider adding rate limiting to functions like `fetch_url` and `render_page` to prevent abuse. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2253` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2263` | Use a more descriptive variable name than 'preview'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2279` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2294` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2304` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2314` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2324` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2334` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2344` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2354` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2364` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2374` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2384` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2394` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2404` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2414` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2424` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2434` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2444` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2454` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2464` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2474` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2484` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2494` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2504` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2514` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2524` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2534` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2544` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2554` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2564` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2574` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2584` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2594` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2604` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2614` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2624` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | readability | `operator/aegis_operator.py:2634` | Use a more descriptive variable name than 'result'. | qwen2.5-coder-32b |
| low | robustness | `operator/attack_coverage.py:31` | Catch only expected exceptions (OSError, JSONDecodeError) rather than bare Exception when loading the techniques DB. | ds |
| low | robustness | `operator/attack_coverage.py:42` | Catch only ImportError when importing FindingStore instead of bare Exception. | ds |
| low | robustness | `operator/attack_coverage.py:54` | Validate that FindingStore(sp).findings() returns a dict before calling .values() to avoid AttributeError on unexpected store formats. | ds |
| low | robustness | `operator/board_ask.py:67` | Check that r.get("choices") is non-empty and the message dict has expected keys before accessing them. | ds |
| low | robustness | `operator/board_ask.py:80` | Use a context manager for writing board files in write() to ensure the file is closed and flushed. | ds |
| low | readability | `operator/board_ask.py:126` | Replace the hardcoded model list in cf() with a named constant or configuration variable. | ds |
| low | robustness | `operator/board_ask.py:145` | Validate the --panel argument against known member names and warn or error on unknown values. | ds |
| low | robustness | `operator/board_ask.py:151` | Handle the case where no panel functions match the requested names by printing a warning instead of silently doing nothing. | ds |
| low | security | `operator/board_discuss.py:103` | Avoid silently swallowing all exceptions in _ask; log the exception type/message at debug level before returning ''. | ds |
| low | robustness | `operator/board_discuss.py:126` | Use json.JSONDecoder().raw_decode to extract the first complete JSON object from each line instead of assuming one object per line. | ds |
| low | performance | `operator/board_discuss.py:151` | Cache the result of _state_block per discuss() call instead of recomputing it for every proposer, critic, and synthesizer. | ds |
| low | design | `operator/board_discuss.py:166` | Extract the duplicated move-shape string construction into a helper function or module-level constant. | ds |
| low | performance | `operator/board_discuss.py:205` | Truncate the proposals and critiques JSON strings using a helper that respects token limits rather than hardcoded character slices. | ds |
| low | security | `operator/board_discuss.py:226` | Sanitize model-generated fields (surface, rationale, dissent, etc.) before writing them to the transcript markdown file. | ds |
| low | robustness | `operator/board_discuss.py:237` | Use a context manager (with open(...) as f) for writing the transcript file. | ds |
| low | performance | `operator/board_discuss.py:237` | Avoid creating a new timestamped transcript file for every round if the board directory grows unbounded; add rotation or cleanup of old transcripts. | ds |
| low | design | `operator/board_discuss.py:258` | Move the int() parsing of AEGIS_BOARD_FULL_STALL and AEGIS_BOARD_FULL_EVERY to module import time alongside the other env parsing. | ds |
| low | correctness | `operator/board_discuss.py:279` | In _fast_discuss, set confidence from raw_confidence only if raw_confidence is a number; otherwise default to 0.5. | ds |
| low | readability | `operator/board_discuss.py:37` | Add a comment explaining the purpose of the `if not final` block. | qwen2.5-coder-32b |
| low | readability | `operator/board_discuss.py:44` | Consider using a more descriptive variable name for `v` in the `verdict_rank` function. | qwen2.5-coder-32b |
| low | performance | `operator/board_feedback.py:53` | Use a shared urllib opener or requests.Session with connection pooling instead of creating a new connection per request. | ds |
| low | duplication | `operator/board_feedback.py:83` | Reuse _post_llm's OpenAI parameter handling instead of duplicating max_completion_tokens logic in ask_panel. | ds |
| low | robustness | `operator/board_feedback.py:91` | Add a timeout to cf_agent.ask call or wrap it with a thread-level timeout. | ds |
| low | performance | `operator/board_feedback.py:116` | Run verify_panel_code for each panel answer in parallel threads instead of sequentially. | ds |
| low | robustness | `operator/board_feedback.py:126` | Use tempfile.NamedTemporaryFile with delete=False and explicit cleanup instead of a fixed temp filename. | ds |
| low | correctness | `operator/board_feedback.py:139` | Handle the case where store_path has no verified findings; summary_of returns a near-empty string that may not be a useful question seed. | ds |
| low | robustness | `operator/board_feedback.py:153` | Catch exceptions from verify_panel_code in one_round so a verification failure does not abort the loop. | ds |
| low | design | `operator/board_feedback.py:168` | Add a --max-iterations option to bound the --loop mode. | ds |
| low | performance | `operator/campaign_ledger.py:75` | Rewrite the ledger file atomically (write temp file in same directory, fsync, os.replace) instead of truncating and rewriting in place. | ds |
| low | robustness | `operator/campaign_ledger.py:121` | Treat only connection-level failures as 'assume live' and distinguish HTTP 404/5xx from network errors in _light_live. | ds |
| low | readability | `operator/campaign_ledger.py:150` | Extract the environment-variable parsing for AEGIS_RELAY_BREADTH_FRAC and AEGIS_RELAY_MAX_ANCHORS into a small helper or module-level constants. | ds |
| low | readability | `operator/campaign_ledger.py:182` | Refactor the conditional logic in confirmed_footholds for better readability. | qwen2.5-coder-32b |

> Board code-review is ADVISORY: suggestions are proposed, never auto-applied. Apply via the code writer/improver after human review. Doctrine unchanged (contained/mirror-only, non-destructive, generic-only public repo).

---

## Reconciliation (coordinator, 2026-09-10)

The full-project board review produced **729 suggestions across 118 files (24 bundles)**. Reconciled against the codebase; verdict below. The signal-to-noise ratio is low by design — most items conflict with deliberate doctrine (offline-safe bare-excepts, dynamic imports for optional deps) or are the deliberately-vulnerable **exploitgym test targets** (SQLi/command-exec there is the point, not a bug).

### Genuinely-real → FIXED this session
- **`campaign_ledger.py` truncate-and-rewrite of the hash-chained ledger** (ds, line 75) — a crash mid-rewrite could corrupt the authoritative findings ledger. **Fixed:** added `_atomic_rewrite()` (temp file + fsync + `os.replace`); `mark_consumed` and `_rewrite` now use it. Tested: chain intact, `consumed_by` persisted, no temp leaked.

### Flagged as "real correctness bugs" but ALREADY CORRECT (board false positives)
- **verifier flag compare should be constant-time** — `exploitgym/verifier.py:162` **already uses `hmac.compare_digest`** (with a length guard). No change.
- **`campaign_ledger.mark_consumed` needs a lock** — it **already holds `self._lock`** (line 91→now). No change.
- **`board_ask.py:104 sol() swapped system/user args`** — `sol` (GPT-5.6) is **booted from the roster** (unreliable + priciest; no tie-breaker needed). Dead path; not touched.
- **mutate `order.index` guard / `st.confirmed[-1]` empty-list** — both already guarded (verified in prior self-review).

### Hallucination (ignored)
- **qwen2.5-coder** emitted *"Handle the case where `Master` is not defined"* **30+ times** across unrelated files — `Master` appears nowhere in the codebase. Model artifact; discarded.

### Deliberate-doctrine conflicts (WON'T FIX — by design)
- **bare `except:` / broad exception swallowing** — the suite is **offline-safe by contract**: every board/RAG/network/optional-dep call must degrade to "behave as before" rather than crash a run. The broad catches are the mechanism.
- **dynamic `import` inside functions** — optional deps (board, planner, session_factory, stateful_templates) are imported lazily *so a missing one is skipped gracefully*. Intentional.
- **`verify=False` on requests** — the target is the **self-signed contained mirror**; TLS verification off is correct and scoped to it.
- **subprocess / command execution** (kali_driver, fuzzer) — running commands in the contained Kali box **is the feature**, gated by the doctrine wrapper. The exploitgym SQLi/command-exec "criticals" are in the **deliberately-vulnerable test-target apps**, not the engine.

### Net
The three highest-value bugs of this build were caught **outside** the board review: two by the coordinator's own self-review (SecurityHeadersOracle empty-response FP; trust class-aware mislabel) and one by the **live run** (missing `import json` → crash when the rate finding fired). All fixed + committed. The board review added **one** real item (ledger atomic write), now closed. Remaining 700+ items are `low`-severity hygiene, advisory only.
