"""Generate an additive reference source view; never compile or execute it.

Call prepare(repo, destination) in a private copied checkout. Existing files
are authenticated and remain unchanged; destination paths must not exist.
"""
from pathlib import Path
import hashlib,json

DONORS=('image.rs','model.rs','raw.rs','cases.rs','checks.rs')
DESTINATIONS={
    'b2_dynamic_reference.rs':'crates/liteinst-launch/tests/b2_dynamic_reference.rs',
    'image.rs':'crates/liteinst-launch/tests/support/b2_dynamic_reference/image.rs',
    'record.rs':'crates/liteinst-launch/tests/support/b2_dynamic_reference/record.rs',
}
def digest(b):return hashlib.sha256(b).hexdigest()
def prepare(repo,destination):
    repo=Path(repo).resolve(strict=True);destination=Path(destination).resolve(strict=True)
    if not destination.is_relative_to(repo/'target'):raise ValueError('private target source view required')
    packet=Path(__file__).resolve().parent
    pins=json.loads((packet.parent/'PINS.json').read_text())
    for path,fact in pins.items():
        b=(repo/path).read_bytes()
        if len(b)!=fact['bytes'] or digest(b)!=fact['sha256']:raise ValueError('exact source prerequisite: '+path)
        # A private view must carry the very same old source; no replacement of
        # the original static fixtures/model/strict predicates is permitted.
        if (destination/path).read_bytes()!=b:raise ValueError('private view differs: '+path)
    result={}
    if any((destination/path).exists()for path in DESTINATIONS.values()):raise ValueError('all additive destinations must be absent')
    for source,path in DESTINATIONS.items():
        out=destination/path;out.parent.mkdir(parents=True,exist_ok=True)
        b=(packet/source).read_bytes()
        with out.open('xb')as f:f.write(b)
        result[path]={'bytes':len(b),'sha256':digest(b)}
    return result
if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('repo',type=Path);p.add_argument('private_view',type=Path)
    a=p.parse_args();print(json.dumps(prepare(a.repo,a.private_view),sort_keys=True))
