"""Vendored shim -- the SINGLE SOURCE OF TRUTH is shared/verified_findings.py.

This file deliberately contains NO logic. It loads the canonical module once (cached in sys.modules
under a private name, so operator/ and exploitgym/ resolve to the SAME instance -> isinstance stays
valid across components) and re-exports its public names. Because there is no logic here, the three
import sites can no longer drift out of sync.
"""
import os as _os, sys as _sys, importlib.util as _il

_NAME = "aegis_shared_verified_findings"
_mod = _sys.modules.get(_NAME)
if _mod is None:
    _path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "shared", "verified_findings.py")
    _spec = _il.spec_from_file_location(_NAME, _path)
    _mod = _il.module_from_spec(_spec)
    _sys.modules[_NAME] = _mod
    _spec.loader.exec_module(_mod)

globals().update({_k: _v for _k, _v in vars(_mod).items() if not _k.startswith("__")})
