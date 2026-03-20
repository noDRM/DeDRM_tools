
#@@CALIBRE_COMPAT_CODE_START@@
import sys, os

# Explicitly allow importing everything ...
if os.path.dirname(os.path.dirname(os.path.abspath(__file__))) not in sys.path:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if os.path.dirname(os.path.abspath(__file__)) not in sys.path:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Bugfix for Calibre < 5:
if "calibre" in sys.modules and sys.version_info[0] == 2:
    from calibre.utils.config import config_dir
    if os.path.join(config_dir, "plugins", "DeDRM.zip") not in sys.path:
        sys.path.insert(0, os.path.join(config_dir, "plugins", "DeDRM.zip"))

if "calibre" in sys.modules:
    # Explicitly set the package identifier so we are allowed to import stuff ...
    __package__ = "calibre_plugins.dedrm"
else:
    # Standalone mode: make relative imports (from .utilities import ...) work
    # without Calibre by installing a meta_path hook that maps dedrm.X -> X.
    import types as _types

    _dedrm_pkg_name = "dedrm"

    class _DeDRMFinder:
        """Acts as both finder and loader.
        Intercepts 'import dedrm.X' and redirects it to the flat module 'X',
        so that relative imports (from .utilities import ...) work standalone."""

        def find_spec(self, fullname, path, target=None):
            import importlib.util as _ilu
            if fullname == _dedrm_pkg_name or fullname.startswith(_dedrm_pkg_name + "."):
                return _ilu.spec_from_loader(fullname, loader=self,
                                             is_package=(fullname == _dedrm_pkg_name))
            return None

        def create_module(self, spec):
            if spec.name == _dedrm_pkg_name:
                return sys.modules[_dedrm_pkg_name]
            # For dedrm.X: import X as a top-level module first, then reuse it
            subname = spec.name[len(_dedrm_pkg_name) + 1:]
            if subname not in sys.modules:
                import importlib as _il
                _il.import_module(subname)
            # Return a fresh module; exec_module will copy attrs from top-level
            import types as _t
            return _t.ModuleType(spec.name)

        def exec_module(self, module):
            if module.__name__ == _dedrm_pkg_name:
                return  # stub package — nothing to execute
            subname = module.__name__[len(_dedrm_pkg_name) + 1:]
            if subname in sys.modules:
                _skip = {'__name__', '__spec__', '__loader__',
                         '__package__', '__file__', '__cached__', '__builtins__'}
                for _k, _v in sys.modules[subname].__dict__.items():
                    if _k not in _skip:
                        module.__dict__[_k] = _v

    if _dedrm_pkg_name not in sys.modules:
        _dedrm_pkg = _types.ModuleType(_dedrm_pkg_name)
        _dedrm_pkg.__path__ = []
        _dedrm_pkg.__package__ = _dedrm_pkg_name
        _dedrm_pkg.__spec__ = None
        sys.modules[_dedrm_pkg_name] = _dedrm_pkg

    if not any(type(f).__name__ == "_DeDRMFinder" for f in sys.meta_path):
        sys.meta_path.append(_DeDRMFinder())

    __package__ = _dedrm_pkg_name

#@@CALIBRE_COMPAT_CODE_END@@
