"""Bounded supplied-data wrapper; calls the complete unchanged historical oracle."""
import sys
sys.dont_write_bytecode=True
import argparse,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
from page_selected_write_footprint import verify

def main():
    p=argparse.ArgumentParser();p.add_argument('raw',type=Path);a=p.parse_args();data=a.raw.read_bytes()
    result=verify(data)
    print(json.dumps(dict(profile='page-selected-write-footprint-v1',status='passed',result=result,
        raw_bytes=len(data),raw_sha256=hashlib.sha256(data).hexdigest()),sort_keys=True))
if __name__=='__main__':main()
