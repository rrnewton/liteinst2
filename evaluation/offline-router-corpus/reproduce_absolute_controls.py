"""Finite explicit new producer stage; all earlier reproduction controls remain."""
from pathlib import Path
import tempfile
import unittest
import reproduce_preparation as D


class AbsoluteStage(unittest.TestCase):
    def plan(self, stage):
        values={key:'value' for key in D.FLAGS[stage]}
        values['original-profile']='startup-original-facts-readonly-headerpad-v1'
        if stage=='producer-absolute': values['startup-profile']=D.ABSOLUTE_STARTUP
        return dict(schema='LI2-PREPARATION-COMMAND-1',stage=stage,history=[],
                    arguments=[v for key,value in values.items() for v in ('--'+key,value)])

    def test_old_exact_flags_and_new_fixed_selection(self):
        old=self.plan('producer');new=self.plan('producer-absolute')
        before=D.command(Path('/repo'),Path('/python'),old)
        after=D.command(Path('/repo'),Path('/python'),new)
        self.assertEqual(len(D.FLAGS['producer']),11)
        self.assertEqual(D.FLAGS['producer-absolute'],D.FLAGS['producer']+('startup-profile',))
        self.assertEqual(after,before+['--startup-profile',D.ABSOLUTE_STARTUP])
        self.assertNotIn('observe',after);self.assertNotIn('n01',after)
        with self.assertRaisesRegex(ValueError,'exact unique flags'):
            D.command(Path('/repo'),Path('/python'),dict(old,arguments=new['arguments']))
        for tail in [new['arguments'][:-2],new['arguments']+['--startup-profile',D.ABSOLUTE_STARTUP],
                     new['arguments'][:-2]+['--startup-pro',D.ABSOLUTE_STARTUP],
                     new['arguments'][:-1]+['elf-disassembly-null-jumps-static-exec-router-bootstrap-v1']]:
            with self.assertRaises(ValueError): D.command(Path('/repo'),Path('/python'),dict(new,arguments=tail))

    def test_new_stage_keeps_explicit_history_bounds_and_duplicate_refusal(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve();refs=[]
            for n in range(65):
                path=root/str(n);path.write_bytes(b'FAILED')
                refs.append(dict(path=str(path),sha256=D.sha(b'FAILED')))
            plan=self.plan('producer-absolute')
            for count in (0,1,6,64):
                argv=D.command(root,Path('/python'),dict(plan,history=refs[:count]))
                self.assertEqual(argv.count('--failure-history'),count)
            for history in (refs,refs[:1]*2):
                with self.assertRaises(ValueError): D.command(root,Path('/python'),dict(plan,history=history))


if __name__=='__main__': unittest.main()
