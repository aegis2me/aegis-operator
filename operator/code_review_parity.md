# Aegis board code-review

_Generated 2026-09-10T15:38:51 -- reviewers: ds, qwen2.5-coder-32b, kimi-k2.7-code; consultant: ds._

Reviewed **9 files** in 8 bundle(s) (TRUNCATED -- raise --max-bundles for full coverage); paths: `shared/verified_findings.py, operator/vectors.py, operator/trust.py, operator/coverage.py, operator/run_monitor.py, operator/canary.py, operator/crawler.py, operator/hunt_strategies.py, operator/iterative_hunt.py`. 207 raw suggestions -> 98 unique after dedup.

## Consultant's consolidated plan

## Themes

1. **Exception hygiene & logging** — pervasive bare `except Exception` / `except: pass` swallowing errors across `canary.py`, `iterative_hunt.py`, `hunt_strategies.py`, `crawler.py`. Replace with specific exception types and debug logging.
2. **Correctness of hunt state machine** — guards around `st.confirmed`, `st.real_attempts`, novelty mean division, window slicing, and move metadata normalization in `iterative_hunt.py`.
3. **Security hardening** — dynamic imports, env-var parsing, URL/token sanitization, and surface validation.
4. **Canary lifecycle robustness** — port binding, listener verification, thread shutdown, and URL/port consistency.
5. **Crawler resilience** — Playwright availability signaling, cookie domain derivation, cleanup, timeouts, and dedup.
6. **Readability / maintainability** — magic constants, long parameter lists, nested conditionals, duplicated expressions, and helper extraction.

---

## Prioritized improvements

1. **[high/security] operator/iterative_hunt.py:1243,1251,1257,1264,1270 — Remove dynamic imports of `coverage`, `board_discuss`, `remediation_board`, `json`, `t0_bandit`** (models: 1)  
   Move to module-level imports; dynamic imports inside functions are a code-injection surface and obscure dependencies.

2. **[high/security] operator/canary.py:36,44 — Remove bare `except Exception` clauses** (models: 1)  
   Catch specific exceptions (`OSError`, `socket.error`, `ValueError`) and log; bare excepts hide real failures.

3. **[high/correctness] operator/iterative_hunt.py:1279 — Guard `st.confirmed[-1]["move"]` in GATE 1 against empty `st.confirmed`** (models: 1)  
   Indexing an empty list raises `IndexError`; add an explicit emptiness check before access.

4. **[med/security] operator/canary.py:63,75,85,92,100 — Validate and sanitize `AEGIS_CANARY_URL`** (models: 1)  
   Parse with `urllib.parse.urlparse`, enforce scheme/host allowlist, and reject path traversal or embedded credentials.

5. **[med/security] operator/iterative_hunt.py:14,30,50,78,127 — Avoid bare `except` clauses; catch specific exceptions** (models: 1)  
   Replace with `except (TypeError, ValueError, KeyError)` as appropriate and log at debug level.

6. **[med/security] operator/iterative_hunt.py:164,171,178,185,192 — Use a more secure method to parse environment variables** (models: 1)  
   Replace direct `os.environ.get` with a typed helper (`_env_bool`, `_env_int`, `_env_float`) that validates and logs malformed values.

7. **[med/robustness] operator/canary.py:56 — Verify existing listener is an Aegis canary before reusing a busy port** (models: 1)  
   Probe the existing listener with a canary-specific health check; if it's not ours, raise instead of silently reusing.

8. **[med/correctness] operator/canary.py:56 — Don't return `_PORT` as success when `ThreadingHTTPServer` construction fails for non-EADDRINUSE reasons** (models: 1)  
   Only treat `EADDRINUSE` as "already running"; propagate other `OSError`s.

9. **[med/correctness] operator/canary.py:80 — Make `base_url()` return the actual bound port** (models: 1)  
   Track the bound port from the server instance (`server.server_address[1]`) rather than assuming `_PORT` or the env var.

10. **[med/correctness] operator/coverage.py:58 — Fix fallback class mapping for generic 'web' actions** (models: 1)  
    Current expression wrongly returns `'authz'` for `'web'` and `'fact'`; use an explicit mapping dict or if/elif chain.

11. **[med/robustness] operator/crawler.py:44 — Don't silently return `{}` when Playwright is unavailable** (models: 1)  
    Log a warning and return a distinct sentinel or raise a typed exception so callers can distinguish "no browser" from "no findings".

12. **[med/correctness] operator/crawler.py:48 — Derive cookie domain from actual base URL hostname** (models: 1)  
    Use `urllib.parse.urlparse(base_url).hostname` instead of stripping port from a string.

13. **[med/correctness] operator/hunt_strategies.py:91 — Guard `order.index(cur)` against `ValueError`** (models: 1)  
    Unknown methods should fall back to a default index rather than crashing.

14. **[med/correctness] operator/hunt_strategies.py:104 — Normalize `move.get("transport", "http").lower()` before comparing** (models: 1)  
    `"HTTPS"` should match `"http"`; lowercase before the comparison.

15. **[med/robustness] operator/hunt_strategies.py:164 — Catch `ImportError` specifically around lazy import** (models: 1)  
    Narrow the except clause so other errors aren't swallowed.

16. **[med/robustness] operator/iterative_hunt.py — Replace broad `except Exception` fallbacks in `direction_of`, `intent_of`, `_is_reach_bridge` with debug logging** (models: 1)  
    Log exception type and message at debug level instead of silently returning defaults.

17. **[med/correctness] operator/iterative_hunt.py — Normalize parameter names case-insensitively and sort after lowercasing in `_norm_surface`** (models: 1)  
    Current sorting is case-sensitive, causing inconsistent surface keys.

18. **[med/correctness] operator/iterative_hunt.py — Handle non-dict oracle entries in `_oracle_type`** (models: 1)  
    Skip or coerce non-dict entries with a debug log instead of silently dropping them.

19. **[med/robustness] operator/iterative_hunt.py — Replace bare `except Exception` around env-var parsing with `except (TypeError, ValueError)`** (models: 1)  
    Narrow the catch and log malformed values.

20. **[med/correctness] operator/iterative_hunt.py — In `_pick`, validate move metadata at enqueue time or make `_dirkey` exception-safe** (models: 1)  
    Malformed move metadata should not crash the pick loop.

21. **[med/robustness] operator/iterative_hunt.py — Guard `_dir_pref` against `_LAYERS` not having exactly two directions** (models: 1)  
    Add an assertion or fallback when `_LAYERS` is malformed.

22. **[med/correctness] operator/iterative_hunt.py — Fix window slicing in `_maybe_stop_direction` when `len(hist)` is between `2*W` and `3*W`** (models: 1)  
    The current slice bounds are off-by-one for that range; compute indices explicitly.

23. **[med/robustness] operator/iterative_hunt.py:1279 — Wrap `coverage` import and `_cov.class_of(move)` in narrower try/except with logging** (models: 1)  
    Catch only `ImportError` and `KeyError`; log the move that failed.

24. **[med/correctness] operator/iterative_hunt.py:1279 — Ensure `st.real_attempts` increments exactly once per real attempt** (models: 1)  
    Move the increment to a single code path covering hang/abandon cases.

25. **[med/robustness] operator/iterative_hunt.py:1279 — Guard novelty mean division against empty `novelty_hist`** (models: 1)  
    Add an explicit `if novelty_hist:` check before dividing.

26. **[med/robustness] operator/iterative_hunt.py:1279 — Replace bare `except Exception: pass` around `_tb.learn_from_context`, `_ts.synthesize`, `board_fn(context)`, `bandit.save()` with logging** (models: 1)  
    Log exception type and message at debug level so failures are observable.

27. **[med/correctness] operator/iterative_hunt.py:1279 — Guard `bandit._board_served_at = n_conf` against missing attribute** (models: 1)  
    Initialize `_board_served_at` in `_get_bandit()` or use `setattr` with a default.

28. **[med/readability] operator/iterative_hunt.py:1279 — Refactor long constructor parameter list into a configuration dictionary** (models: 1)  
    Improves readability and makes future parameters non-breaking.

29. **[med/security] operator/iterative_hunt.py:1253 — Avoid `import` inside a function** (models: 1)  
    Move to module level; see item 1.

30. **[med/security] operator/iterative_hunt.py:1254 — Avoid `os.environ.get` directly for sensitive data** (models: 1)  
    Use the typed env helper from item 6.

31. **[med/readability] operator/iterative_hunt.py:1279 — Refactor long string concatenation into a single f-string** (models: 1)  
    Improves readability and avoids implicit concatenation bugs.

32. **[med/security] operator/iterative_hunt.py:11 — Avoid importing `os` as `_os`; use original `os` import** (models: 1)  
    The alias obscures the standard library module and serves no purpose.

33. **[low/robustness] operator/canary.py:59 — Set `daemon_threads=True` or track server thread for deterministic shutdown** (models: 1)  
    Prevents hangs on interpreter exit.

34. **[low/correctness] operator/canary.py:63 — Use `uuid.uuid4().hex` directly instead of prefixing and slicing** (models: 1)  
    Simpler and avoids off-by-one token length bugs.

35. **[low/robustness] operator/canary.py:68 — Close UDP socket in `finally` or use context manager in `_local_ip`** (models: 1)  
    Prevents socket leak.

36. **[low/robustness] operator/canary.py:84 — Validate/sanitize `tok` in `url_for` to prevent path traversal or URL injection** (models: 1)  
    Reject tokens containing `/`, `..`, or URL metacharacters.

37. **[low/performance] operator/canary.py:88 — Use `threading.Event` instead of polling with `time.sleep` in `hits()`** (models: 1)  
    Reduces latency and CPU usage.

38. **[low/readability] operator/coverage.py:58 — Replace nested conditional expression in `class_of` with if/elif chain or lookup table** (models: 1)  
    See item 10; same fix.

39. **[low/robustness] operator/crawler.py:55 — Add timeout or try/finally around browser/context cleanup** (models: 1)  
    Ensures cleanup runs even on exceptions.

40. **[low/performance] operator/crawler.py:66 — Filter captured request URLs to target host before adding to `found`** (models: 1)  
    Reduces noise from third-party requests.

41. **[low/correctness] operator/crawler.py:70 — Track visited selectors/elements to avoid duplicate clicks** (models: 1)  
    Prevents infinite loops and redundant work.

42. **[low/robustness] operator/crawler.py:78 — Handle Playwright timeout in `pg.goto()` and continue with captured requests** (models: 1)  
    A timeout shouldn't discard already-captured requests.

43. **[low/readability] operator/hunt_strategies.py:91 — Compute `cur` and fallback before conditional expression or use dict lookup** (models: 1)  
    See item 13; same fix.

44. **[low/performance] operator/hunt_strategies.py:121 — Compute budget components once and reuse** (models: 1)  
    Avoids redundant computation in the budget split.

45. **[low/correctness] operator/hunt_strategies.py:121 — Ensure budget components sum exactly to `remaining`** (models: 1)  
    Use integer division with explicit remainder distribution.

46. **[low/readability] operator/hunt_strategies.py:170 — Extract `_APP_ACTIONS` gate and surface-normalization into helper functions** (models: 1)  
    Reduces nesting and improves testability.

47. **[low/design] operator/hunt_strategies.py:170 — Make `_APP_ACTIONS` configurable or documented as deliberate policy** (models: 1)  
    Add a comment or config option explaining the allowlist.

48. **[low/correctness] operator/hunt_strategies.py:190,198 — Use `move.get("method", "GET").upper()` when constructing moves** (models: 1)  
    Ensures consistent method casing downstream.

49. **[low/security] operator/hunt_strateg

---

## Suggestions by model

- **ds**: 64 suggestion(s)
- **qwen2.5-coder-32b**: 143 suggestion(s)
- **kimi-k2.7-code**: 0 suggestion(s)

## All suggestions

| sev | area | file | change | model |
|---|---|---|---|---|
| high | security | `operator/canary.py:36` | Remove the bare `except Exception` clauses. | qwen2.5-coder-32b |
| high | security | `operator/canary.py:44` | Remove the bare `except Exception` clauses. | qwen2.5-coder-32b |
| high | correctness | `operator/iterative_hunt.py:1279` | Add a guard before `st.confirmed[-1]["move"]` in GATE 1 to ensure `st.confirmed` is non-empty, or restructure the condition to short-circuit on `not st.confirmed`. | ds |
| high | security | `operator/iterative_hunt.py:1243` | Remove the dynamic import of `coverage` module. | qwen2.5-coder-32b |
| high | security | `operator/iterative_hunt.py:1251` | Remove the dynamic import of `board_discuss` module. | qwen2.5-coder-32b |
| high | security | `operator/iterative_hunt.py:1257` | Remove the dynamic import of `remediation_board` module. | qwen2.5-coder-32b |
| high | security | `operator/iterative_hunt.py:1264` | Remove the dynamic import of `json` module. | qwen2.5-coder-32b |
| high | security | `operator/iterative_hunt.py:1270` | Remove the dynamic import of `t0_bandit` module. | qwen2.5-coder-32b |
| med | robustness | `operator/canary.py:56` | When the bind fails because the port is busy, verify that the existing listener is actually an Aegis canary before reusing the port. | ds |
| med | correctness | `operator/canary.py:56` | Do not return _PORT as if the canary started successfully when ThreadingHTTPServer construction raises for reasons other than EADDRINUSE (e.g. permission denied, invalid address). | ds |
| med | correctness | `operator/canary.py:80` | Make base_url() return the same port that start() actually bound, including when AEGIS_CANARY_URL is set but start() was called with a different explicit port. | ds |
| med | security | `operator/canary.py:63` | Validate and sanitize the environment variable `AEGIS_CANARY_URL`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:75` | Validate and sanitize the environment variable `AEGIS_CANARY_PORT`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:85` | Validate and sanitize the environment variable `AEGIS_CANARY_URL`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:92` | Validate and sanitize the environment variable `AEGIS_CANARY_PORT`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:100` | Validate and sanitize the environment variable `AEGIS_CANARY_URL`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:107` | Validate and sanitize the environment variable `AEGIS_CANARY_PORT`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:115` | Validate and sanitize the environment variable `AEGIS_CANARY_URL`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:122` | Validate and sanitize the environment variable `AEGIS_CANARY_PORT`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:130` | Validate and sanitize the environment variable `AEGIS_CANARY_URL`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:137` | Validate and sanitize the environment variable `AEGIS_CANARY_PORT`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:145` | Validate and sanitize the environment variable `AEGIS_CANARY_URL`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:152` | Validate and sanitize the environment variable `AEGIS_CANARY_PORT`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:160` | Validate and sanitize the environment variable `AEGIS_CANARY_URL`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:167` | Validate and sanitize the environment variable `AEGIS_CANARY_PORT`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:175` | Validate and sanitize the environment variable `AEGIS_CANARY_URL`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:182` | Validate and sanitize the environment variable `AEGIS_CANARY_PORT`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:190` | Validate and sanitize the environment variable `AEGIS_CANARY_URL`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:197` | Validate and sanitize the environment variable `AEGIS_CANARY_PORT`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:205` | Validate and sanitize the environment variable `AEGIS_CANARY_URL`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:212` | Validate and sanitize the environment variable `AEGIS_CANARY_PORT`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:220` | Validate and sanitize the environment variable `AEGIS_CANARY_URL`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:227` | Validate and sanitize the environment variable `AEGIS_CANARY_PORT`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:235` | Validate and sanitize the environment variable `AEGIS_CANARY_URL`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:242` | Validate and sanitize the environment variable `AEGIS_CANARY_PORT`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:250` | Validate and sanitize the environment variable `AEGIS_CANARY_URL`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:257` | Validate and sanitize the environment variable `AEGIS_CANARY_PORT`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:265` | Validate and sanitize the environment variable `AEGIS_CANARY_URL`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:272` | Validate and sanitize the environment variable `AEGIS_CANARY_PORT`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:280` | Validate and sanitize the environment variable `AEGIS_CANARY_URL`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:287` | Validate and sanitize the environment variable `AEGIS_CANARY_PORT`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:295` | Validate and sanitize the environment variable `AEGIS_CANARY_URL`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:302` | Validate and sanitize the environment variable `AEGIS_CANARY_PORT`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:310` | Validate and sanitize the environment variable `AEGIS_CANARY_URL`. | qwen2.5-coder-32b |
| med | security | `operator/canary.py:317` | Validate and sanitize the environment variable `AEGIS_CANARY_PORT`. | qwen2.5-coder-32b |
| med | correctness | `operator/coverage.py:58` | Fix the fallback class mapping for generic 'web' actions: the current expression returns 'authz' for 'web', 'fact', 'authz', and 'money', which is likely wrong for 'web' and 'fact'. | ds |
| med | robustness | `operator/crawler.py:44` | Do not silently return {} when Playwright is unavailable; log or expose a distinct signal that crawling was skipped. | ds |
| med | correctness | `operator/crawler.py:48` | Derive the cookie domain from the actual base URL hostname rather than stripping the port and assuming the bare host works for all cookie domains. | ds |
| med | correctness | `operator/hunt_strategies.py:91` | Guard `order.index(cur)` against a `ValueError` when `cur` is not in `order` (e.g., method `DELETE` or lowercase). | ds |
| med | correctness | `operator/hunt_strategies.py:104` | Use `move.get("transport", "http").lower()` before comparing to `"http"`. | ds |
| med | robustness | `operator/hunt_strategies.py:164` | Catch `ImportError` specifically (or check availability) instead of a bare `except Exception` around the lazy import. | ds |
| med | test-coverage | `operator/hunt_strategies.py:164` | Add unit tests for `deepen_on_clean` covering the lazy-import failure path, the `_APP_ACTIONS` gate, non-HTTP surfaces, and the invariant-template break behavior. | ds |
| med | readability | `operator/hunt_strategies.py:111` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:136` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:165` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:182` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:237` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:265` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:290` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:314` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:344` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:369` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:394` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:424` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:454` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:484` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:514` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:544` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:574` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:604` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:634` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:664` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:694` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:724` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:754` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:784` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:814` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:844` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:874` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:904` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:934` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:964` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:994` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:1024` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:1054` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:1084` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:1114` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:1144` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:1174` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:1204` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | readability | `operator/hunt_strategies.py:1234` | Use a more descriptive variable name than `m`. | qwen2.5-coder-32b |
| med | robustness | `operator/iterative_hunt.py` | Replace the broad `except Exception` fallbacks in `direction_of`, `intent_of`, and `_is_reach_bridge` with logging at debug level so reach-module failures are observable instead of silently degrading. | ds |
| med | correctness | `operator/iterative_hunt.py` | In `_norm_surface`, normalize parameter names case-insensitively and sort them after lowercasing, not before, so `User` and `user` are treated as the same parameter. | ds |
| med | correctness | `operator/iterative_hunt.py` | In `_oracle_type`, handle oracle entries that are non-dict values (e.g. strings) instead of silently dropping them, or document that only dict oracles contribute to identity. | ds |
| med | test-coverage | `operator/iterative_hunt.py` | Add unit tests for `_norm_surface` covering query strings, fragments, numeric IDs, hex IDs, UUID-like segments, parameter-name case, and list vs scalar params. | ds |
| med | test-coverage | `operator/iterative_hunt.py` | Add tests for `angle_of` covering each `_TECH_FAMILIES` keyword, `_NON_WEB` actions, fallback `web:<angle>`, and empty moves. | ds |
| med | robustness | `operator/iterative_hunt.py` | Replace bare `except Exception` clauses around environment-variable parsing with `except (TypeError, ValueError)` (or a small helper) so programming errors and unexpected exceptions are not silently swallowed. | ds |
| med | test-coverage | `operator/iterative_hunt.py` | Add unit tests for the interaction between `direction_floor`, `breadth_floor`, coverage gate, and epsilon pick, especially when the queue is empty, all moves are saturated, or `cov_idx` excludes every queued move. | ds |
| med | correctness | `operator/iterative_hunt.py` | In `_pick`, when `cov_idx` is non-empty but `_dirkey` raises for a candidate (e.g. missing angle/direction metadata), the exception is not caught; validate move metadata at enqueue time or make `_dirkey` defensive. | ds |
| med | robustness | `operator/iterative_hunt.py` | Guard `_dir_pref` against `_LAYERS` containing fewer or more than two directions instead of assuming exactly two entries. | ds |
| med | correctness | `operator/iterative_hunt.py` | In `_maybe_stop_direction`, use a fixed window size or validate `len(hist)` before slicing `hist[-2*W:-W]` when `len(hist)` is between `2*W` and `3*W`. | ds |
| med | test-coverage | `operator/iterative_hunt.py` | Add unit tests for `_maybe_stop_direction` covering the boundary where `len(hist)` is between `2*W` and `3*W`, and for `_dir_pref` with zero-count directions and tie scores. | ds |
| med | robustness | `operator/iterative_hunt.py:1279` | Wrap the `coverage` import and `_cov.class_of(move)` call in a narrower try/except that logs or records the failure, rather than silently passing. | ds |
| med | test-coverage | `operator/iterative_hunt.py:1279` | Add unit tests for the watchdog/hang path where `run_attempt` returns `_hung=True`, asserting that `result` is set to the abandoned status and `attempts_hung` is incremented. | ds |
| med | correctness | `operator/iterative_hunt.py:1279` | Ensure `st.real_attempts` is incremented exactly once per real attempt, including when `gain > 0` but the attempt later hangs or is abandoned. | ds |
| med | robustness | `operator/iterative_hunt.py:1279` | Guard the division in the novelty mean against an empty novelty_hist before computing sum/len. | ds |
| med | robustness | `operator/iterative_hunt.py:1279` | Replace the bare `except Exception: pass` blocks around `_tb.learn_from_context`, `_ts.synthesize`, `board_fn(context)`, and `bandit.save()` with logging at debug/warning level so silent failures are diagnosable. | ds |
| med | correctness | `operator/iterative_hunt.py:1279` | Guard `bandit._board_served_at = n_conf` against `bandit` being a mock or object lacking the attribute, or initialize `_board_served_at` in `_get_bandit()` instead of relying on `getattr`. | ds |
| med | test-coverage | `operator/iterative_hunt.py:1279` | Add unit tests for the tiered brainstorm gating logic: cold start (no confirms), thin T1 (< M distinct), quota due, stall phase, and dedup of board vs synth moves. | ds |
| med | readability | `operator/iterative_hunt.py:1279` | Refactor the long parameter list in the IterativeHunt constructor into a configuration dictionary. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:164` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:171` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:178` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:185` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:192` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:200` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:208` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:216` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:224` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:232` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:240` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:248` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:256` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:264` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:272` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:280` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:288` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:296` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:304` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:312` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:320` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:328` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:336` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:344` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:352` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:360` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:368` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:376` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:384` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:392` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:400` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:408` | Use a more secure method to parse environment variables. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:1253` | Avoid using `import` inside a function. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:1254` | Avoid using `os.environ.get` directly for sensitive data. | qwen2.5-coder-32b |
| med | readability | `operator/iterative_hunt.py:1279` | Refactor the long string concatenation into a single f-string for better readability. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:11` | Avoid importing `os` as `_os` and using it; use the original `os` import. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:14` | Avoid using a bare `except` clause; catch specific exceptions. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:30` | Avoid using a bare `except` clause; catch specific exceptions. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:50` | Avoid using a bare `except` clause; catch specific exceptions. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:78` | Avoid using a bare `except` clause; catch specific exceptions. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:127` | Avoid using a bare `except` clause; catch specific exceptions. | qwen2.5-coder-32b |
| med | security | `operator/iterative_hunt.py:170` | Avoid using a bare `except` clause; catch specific exceptions. | qwen2.5-coder-32b |
| low | robustness | `operator/canary.py:59` | Set daemon_threads=True on ThreadingHTTPServer or explicitly track the server thread so shutdown/restart behavior is deterministic. | ds |
| low | correctness | `operator/canary.py:63` | Use uuid.uuid4().hex directly instead of prefixing with 'aegis' and slicing to 12 hex chars. | ds |
| low | robustness | `operator/canary.py:68` | Close the UDP socket in a finally block or use a context manager in _local_ip. | ds |
| low | robustness | `operator/canary.py:84` | Validate or sanitize tok in url_for to prevent path traversal or URL injection if callers ever pass untrusted token values. | ds |
| low | performance | `operator/canary.py:88` | Use a threading.Event or condition variable instead of polling with time.sleep in hits(). | ds |
| low | readability | `operator/coverage.py:58` | Replace the nested conditional expression in class_of with a small if/elif chain or lookup table. | ds |
| low | test-coverage | `operator/coverage.py:60` | Add unit tests for class_of covering generic 'web' actions, unknown actions, and keyword fallback precedence. | ds |
| low | robustness | `operator/crawler.py:55` | Add a timeout or try/finally around browser and context cleanup so a crash in one role does not leak the browser process. | ds |
| low | performance | `operator/crawler.py:66` | Filter captured request URLs to the target host before adding them to found, rather than only filtering later in _norm_path. | ds |
| low | correctness | `operator/crawler.py:70` | Use a set of visited selectors/elements or track clicked elements to avoid clicking the same link/button multiple times. | ds |
| low | robustness | `operator/crawler.py:78` | Handle the case where pg.goto() times out or the page never reaches networkidle by catching the specific Playwright timeout and continuing with whatever requests were captured. | ds |
| low | readability | `operator/hunt_strategies.py:91` | Compute `cur` and the fallback before the conditional expression, or use a dict lookup for the next verb. | ds |
| low | performance | `operator/hunt_strategies.py:121` | Compute `int(0.6 * remaining)` and `int(0.3 * remaining)` once and reuse them in the returned dict. | ds |
| low | correctness | `operator/hunt_strategies.py:121` | Ensure the three budget components sum exactly to `remaining` by assigning the last component as `remaining - deepen - novel_same`. | ds |
| low | readability | `operator/hunt_strategies.py:170` | Extract the `_APP_ACTIONS` gate and the surface-normalization logic into small helper functions. | ds |
| low | design | `operator/hunt_strategies.py:170` | Consider making `_APP_ACTIONS` configurable or documented as a deliberate policy constant rather than a hard-coded set. | ds |
| low | correctness | `operator/hunt_strategies.py:190` | Use `move.get("method", "GET").upper()` when constructing the artifact-check move to avoid propagating a lowercase method. | ds |
| low | security | `operator/hunt_strategies.py:190` | Validate or sanitize `surface` before embedding it in `why_novel` and move construction. | ds |
| low | correctness | `operator/hunt_strategies.py:198` | Use `move.get("method", "GET").upper()` for the concurrency differential move as well. | ds |
| low | performance | `operator/hunt_strategies.py:206` | Avoid scanning all templates when `inv` is already known and the surface matches no template keywords; short-circuit with a precomputed keyword index if template count grows. | ds |
| low | readability | `operator/iterative_hunt.py` | Extract the duplicated `str(move.get("vuln_class") or move.get("class") or "").lower().strip() or _norm_tech(move)` expression into a helper such as `_vuln_class(move)` and reuse it in `_hypo_identity` and `_combo`. | ds |
| low | robustness | `operator/iterative_hunt.py` | Guard `_hypo_identity` against non-string values in move fields by coercing with `str()` before calling `.lower()`/`.strip()` on every field, not just the ones currently wrapped. | ds |
| low | performance | `operator/iterative_hunt.py` | Cache `_hypo_identity` results keyed by a stable move representation if moves are reused, or memoize `_sig` for repeated identical moves. | ds |
| low | design | `operator/iterative_hunt.py` | Document the precedence order when both `move["oracles"]` and `move["oracle"]` are present in `_oracle_type`, since the current code silently ignores the singular `oracle` if `oracles` is non-empty. | ds |
| low | readability | `operator/iterative_hunt.py` | Extract the repeated environment kill-switch parsing (`str(os.environ.get(...)).lower() not in (...)` and numeric env parsing) into small module-level helpers. | ds |
| low | performance | `operator/iterative_hunt.py` | Cache `_angle_cap()` per state or compute it once per pick instead of calling it inside `_saturated` for every angle. | ds |
| low | design | `operator/iterative_hunt.py` | Consider making `_epsilon_pick`'s RNG stream deterministic and injectable rather than relying on `AEGIS_SEED` and wave arithmetic. | ds |
| low | robustness | `operator/iterative_hunt.py` | In `_maybe_write_code`, log the exception type/message when `self.code_writer` raises instead of silently swallowing it. | ds |
| low | correctness | `operator/iterative_hunt.py` | In `_info_gain`, normalize `status` to a string before membership testing in `_INFORMATIVE_STATUS`. | ds |
| low | performance | `operator/iterative_hunt.py` | Cache `_angle_cap()` and `_under_probed_direction()` results per state update instead of recomputing them on every `_context` call. | ds |
| low | design | `operator/iterative_hunt.py` | Extract the epsilon-greedy stratum selection block into a named helper method. | ds |
| low | performance | `operator/iterative_hunt.py:1279` | Cache `_cvm.PARITY_CLASSES` length outside the per-attempt monitor beat instead of recomputing `len(_cvm.PARITY_CLASSES)` on every leg. | ds |
| low | design | `operator/iterative_hunt.py:1279` | Extract the inline coverage-parity computation into a small helper method to reduce duplication and improve readability. | ds |
| low | correctness | `operator/iterative_hunt.py:1279` | Use `str(m.get("surface"))` consistently in the dedup `seen` set and the final list comprehension; currently `seen` uses `str(m.get("surface"))` for t1 but the comprehension uses `str(m.get("surface"))` for bmoves, which is fine, but normalize `None` to a sentinel like `""` to avoid `"None"` collisions. | ds |
| low | performance | `operator/iterative_hunt.py:1279` | Compute `closed` set once and reuse it, and avoid re-importing `os` as `_os` when `os` is already imported at module top. | ds |
| low | readability | `operator/iterative_hunt.py:1304` | Use a constant for the default cost value. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:1315` | Use a constant for the default impact weight. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:1348` | Use a constant for the default cost floor. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:1351` | Use a constant for the default per-directory floor. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:1356` | Use a constant for the default window size. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:1361` | Use a constant for the default tau multiplier. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:1406` | Use a constant for the default direction adaptation setting. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:1411` | Use a constant for the default direction cap. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:1435` | Use a constant for the default novel code cap. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:1474` | Use a constant for the default informative statuses. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:1526` | Use a constant for the default angle cap. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:1535` | Use a constant for the default hypothesis template. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:142` | Use a more descriptive variable name for `M` and `K`. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:143` | Use a more descriptive variable name for `M` and `K`. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:147` | Use a more descriptive variable name for `last_served`. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:150` | Use a more descriptive variable name for `quota_due`. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:151` | Use a more descriptive variable name for `thin`. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:152` | Use a more descriptive variable name for `stall`. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:156` | Use a more descriptive variable name for `bmoves`. | qwen2.5-coder-32b |
| low | readability | `operator/iterative_hunt.py:165` | Use a more descriptive variable name for `seen`. | qwen2.5-coder-32b |

## Reviewer skips / errors

- {"model": "kimi-k2.7-code", "bundle": 1, "why": "[raw reasoning, no final content] We need review source bundle 1/8. Need output JSONL per schema. We must be concrete, c"}
- {"model": "kimi-k2.7-code", "bundle": 2, "why": "[raw reasoning, no final content] We need review source file operator/hunt_strategies.py. Need output JSONL per suggesti"}
- {"model": "kimi-k2.7-code", "bundle": 3, "why": "[raw reasoning, no final content] The user wants me to review source code bundle 3/8 and emit JSONL suggestions per the "}
- {"model": "kimi-k2.7-code", "bundle": 4, "why": "[raw reasoning, no final content] We need review source file operator/iterative_hunt.py part 2, 1279 lines total. We nee"}
- {"model": "kimi-k2.7-code", "bundle": 5, "why": "[raw reasoning, no final content] The user wants me to review source code from a file called `operator/iterative_hunt.py"}
- {"model": "kimi-k2.7-code", "bundle": 6, "why": "[raw reasoning, no final content] We need review source file operator/iterative_hunt.py part 4. Need emit JSONL suggesti"}
- {"model": "kimi-k2.7-code", "bundle": 7, "why": "[raw reasoning, no final content] We need review source bundle 7/8, file operator/iterative_hunt.py (part 5, 1279 lines "}
- {"model": "kimi-k2.7-code", "bundle": 8, "why": "[raw reasoning, no final content] We need review source file operator/iterative_hunt.py part 6. Need emit JSONL suggesti"}

> Board code-review is ADVISORY: suggestions are proposed, never auto-applied. Apply via the code writer/improver after human review. Doctrine unchanged (contained/mirror-only, non-destructive, generic-only public repo).
