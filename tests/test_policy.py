import importlib.util
from pathlib import Path
p=Path(__file__).resolve().parents[1]/'src'/'multihop.py'
spec=importlib.util.spec_from_file_location('multihop',p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert m.verdict([m.HYBRID]*3)=='SATISFIED'
assert m.verdict([m.HYBRID,None,m.HYBRID])=='UNRESOLVED'
assert m.verdict([m.HYBRID,m.CLASSIC,None])=='VIOLATED'
assert m.verdict([m.CLASSIC]*3)=='VIOLATED'
print('PASS: four policy regression tests')
