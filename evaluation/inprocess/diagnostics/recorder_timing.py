"""Private per-case timing only; unchanged recorder bodies, population and limits."""
import json, runpy, subprocess, sys, time, unittest
from pathlib import Path
HERE=Path(__file__).resolve(); ROOT=HERE.parents[3]
ORIGINAL=ROOT/'evaluation/admission/recorder_parallel.py'
sys.path.insert(0,str(ORIGINAL.parent))
if '--worker' in sys.argv:
    begin=unittest.TextTestResult.startTest; end=unittest.TextTestResult.stopTest
    def start(self, test):
        if type(self).__name__=='Ledger' and type(self).__module__=='__main__':
            self._li2_diag_wall=time.monotonic_ns(); self._li2_diag_cpu=time.process_time_ns()
        return begin(self,test)
    def stop(self, test):
        out=end(self,test)
        if type(self).__name__=='Ledger' and type(self).__module__=='__main__':
            print('CASE_TIMING '+json.dumps(dict(identity=test.id(),wall_ns=time.monotonic_ns()-self._li2_diag_wall,
                  cpu_ns=time.process_time_ns()-self._li2_diag_cpu),sort_keys=True),flush=True)
        return out
    unittest.TextTestResult.startTest=start;unittest.TextTestResult.stopTest=stop
else:
    launch=subprocess.Popen
    def popen(args,*pos,**kw):
        args=list(args)
        if len(args)>=4 and args[:3]==[sys.executable,'-B',str(ORIGINAL)] and args[3]=='--worker':
            args[2]=str(HERE)
        return launch(args,*pos,**kw)
    subprocess.Popen=popen
sys.argv=[str(ORIGINAL),*sys.argv[1:]]
runpy.run_path(str(ORIGINAL),run_name='__main__')
