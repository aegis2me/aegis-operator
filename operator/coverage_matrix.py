"""Vendored shim -- the SINGLE SOURCE OF TRUTH is shared/coverage_matrix.py.

No logic here: it loads the canonical module once (cached in sys.modules so every import site shares
one instance) and re-exports its public names, so the vendored copies can never drift.
"""
import os as _os, sys as _sys, importlib.util as _il

_NAME = "aegis_shared_coverage_matrix"
_mod = _sys.modules.get(_NAME)
if _mod is None:
    _path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "shared", "coverage_matrix.py")
    _spec = _il.spec_from_file_location(_NAME, _path)
    _mod = _il.module_from_spec(_spec)
    _sys.modules[_NAME] = _mod
    _spec.loader.exec_module(_mod)

globals().update({_k: _v for _k, _v in vars(_mod).items() if not _k.startswith("__")})
