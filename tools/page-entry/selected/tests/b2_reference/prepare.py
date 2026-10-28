"""Add format observation after the exact reviewed callback preparation."""
import importlib.util
from pathlib import Path
def load(path):
    spec=importlib.util.spec_from_file_location('b2_original_prepare',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def prepare(selected,reference_sources,reference,output,pin,boundary):
    here=Path(__file__).resolve().parent
    old=load(pin(here/'callback/prepare.py'))
    result=old.prepare(selected,reference_sources,reference,output,pin,boundary)
    target=Path(output)/'b2_format.inc'
    with target.open('xb')as f:f.write(pin(here/'format.inc').read_bytes())
    pin(target);result.append({'name':target.name,'after':old.fact(target)})
    return result
def recipe(argv,selected,output):
    return load(Path(__file__).resolve().parent/'callback/prepare.py').recipe(argv,selected,output)
