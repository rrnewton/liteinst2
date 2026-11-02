"""Whole old12 domain with complete descriptions of new, refused forms."""
import importlib.util
from pathlib import Path
_s=importlib.util.spec_from_file_location('effects_explicit_source',Path(__file__).with_name('source_decode.py'))
model=importlib.util.module_from_spec(_s);_s.loader.exec_module(model)
need,decode=model.need,model.decode12
