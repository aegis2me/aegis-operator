"""Stateful-probe TEMPLATE library -- the Planner instantiates these against the target so the engine
AUTO-SEEDS stateful moves (no hand-seeding). Each template is a StatefulMove (see vectors.stateful) with
an `applies` keyword set the Planner matches against the fingerprint (surfaces/stack/objective terms).
Templates are self-validating at runtime: if the target lacks the endpoint, setup capture fails and the
oracle rejects -- never a crash. Two directions: CODE (replay/idempotency/invariant) + SCAFFOLD (resource
persistence). Budget-capped + dataflow-scoped by the Planner (see planner.stateful_seeds)."""
import os, random

_API_CONTAINER = os.environ.get("AEGIS_MIRROR_API_CONTAINER", "fixflow-mirror-api-1")


def _london(n):
    return [{"lat": round(51.50 + random.uniform(-0.05, 0.05), 6),
             "lng": round(-0.12 + random.uniform(-0.05, 0.05), 6)} for _ in range(n)]


def templates(base=None, roles=None):
    """Return the StatefulMove templates. `base` unused here (paths are relative; the leg prepends base)."""
    return [
        # ---- CODE direction: credit-note over-credit via replay (InvariantOracle) -- PROVEN ----
        {
            "action": "stateful", "technique": "stateful.replay_mutation",
            "vuln_class": "idempotency/business-logic", "role": "finance", "layer": "code",
            "surface": "/api/credit-notes", "severity": "high", "seed": "planner",
            "why_novel": "Credit-note create is not idempotent and enforces no sum(credits)<=invoice.total "
                         "invariant: replaying POST /api/credit-notes over-credits the invoice.",
            "setup": [
                # F3: pick a job with NO invoice yet (not $[0], which L1 may have already invoiced -> 409).
                {"method": "GET", "path": "/api/jobs", "pick": {"where_empty": "invoices"},
                 "capture": {"jobId": "$.id"}},
                {"method": "POST", "path": "/api/invoices", "body": {"jobId": "{{jobId}}"},
                 "capture": {"invoiceId": "$.id", "invoice_total": "$.total"}},
            ],
            "measure": {"method": "GET", "path": "/api/credit-notes",
                        "filter": {"field": "invoiceId", "eq_var": "invoiceId"}, "reduce": "sum", "field": "total"},
            "bound": {"var": "invoice_total"},
            "action_step": {"method": "POST", "path": "/api/credit-notes", "body": {"invoiceId": "{{invoiceId}}"}},
            "repeat": 2, "oracle": "invariant", "invariant": "sum(issued credit notes) <= invoice.total",
            "applies": ["credit", "invoice", "money", "refund", "finance", "accounting", "payment"],
        },
        # ---- CODE direction: deposit/payment replay (IdempotencyOracle, count-based) ----
        {
            "action": "stateful", "technique": "stateful.replay_mutation",
            "vuln_class": "idempotency", "role": "finance", "layer": "code",
            "surface": "/api/payments/deposit", "severity": "medium", "seed": "planner",
            "why_novel": "Deposit intake may not be idempotent: replaying POST /api/payments/deposit could "
                         "book duplicate held funds for one intended payment.",
            "setup": [{"method": "GET", "path": "/api/customers", "capture": {"customerId": "$[0].id"}}],
            "measure": {"method": "GET", "path": "/api/payments",
                        "filter": {"field": "customerId", "eq_var": "customerId"}, "reduce": "count"},
            "action_step": {"method": "POST", "path": "/api/payments/deposit",
                            "body": {"customerId": "{{customerId}}", "amount": 50, "method": "CARD"}},
            "repeat": 2, "oracle": "idempotency", "unit": 1.0, "metric": "deposit-count",
            "applies": ["payment", "deposit", "money", "finance", "accounting"],
        },
        # ---- SCAFFOLD direction: auth/session state -- token not invalidated on logout (AuthStateOracle) ----
        {
            "action": "stateful", "technique": "stateful.session_not_invalidated",
            "vuln_class": "broken-auth/session", "role": "owner", "layer": "scaffold",
            "surface": "/api/auth/logout", "severity": "high", "seed": "planner",
            "why_novel": "Server-side session may not be invalidated on logout: reusing the same session "
                         "cookie after POST /api/auth/logout could still reach protected resources.",
            "probe_step": {"method": "GET", "path": "/api/settings/details"},
            "logout_step": {"method": "POST", "path": "/api/auth/logout"},
            "oracle": "auth_state", "metric": "session-invalidation",
            "applies": ["auth", "session", "login", "logout", "token", "account", "identity"],
        },
        # ---- SCAFFOLD direction: routing-stack resource persistence (ResourcePersistenceOracle) ----
        {
            "action": "stateful", "technique": "stateful.resource_exhaustion_persistence",
            "vuln_class": "resource-exhaustion", "role": "owner", "layer": "scaffold",
            "surface": "/api/dispatch/route-geometry", "severity": "high", "seed": "planner",
            "why_novel": "Unbounded stops[] on POST /api/dispatch/route-geometry: repeated heavy requests may "
                         "leave the routing stack's memory elevated (leak/exhaustion) vs a benign control run.",
            "action_step": {"method": "POST", "path": "/api/dispatch/route-geometry", "body": {"stops": _london(150)}},
            "control_step": {"method": "POST", "path": "/api/dispatch/route-geometry", "body": {"stops": _london(2)}},
            "oracle": "resource_persistence", "container": _API_CONTAINER,
            "warmup": 1, "cooldown": 3, "repeat": 5, "floor": 40 * 1024 * 1024, "factor": 2.0,
            "applies": ["route", "optimize", "geometry", "dispatch", "schedul", "report", "export"],
        },
    ]
