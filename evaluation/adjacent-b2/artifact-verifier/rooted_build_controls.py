#!/usr/bin/env python3
"""Prospective rooted-build controls; no Cargo or producer execution."""
import copy
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import cargo_from_root as launcher
import rooted_build as build
import verify_saved as w


class RootedBuildControls(unittest.TestCase):
    def test_finite_configuration_positive_before_includes_and_build_overrides(self):
        for raw in (b'', b'# empty\n', b'[net]\ngit-fetch-with-cli = true\n',
                    b'[http]\nproxy = "http://localhost:3128"\n',
                    b'[net]\ngit-fetch-with-cli = false\n[http]\nproxy = ""\n'):
            build.check_config(raw)
        for raw in (b'include = ["elsewhere.toml"]\n', b'"include" = []\n',
                    b'[build]\nrustc-wrapper = "other"\n', b'[alias]\nbuild = "other"\n',
                    b'[http]\nproxy = "x"\nproxy = "y"\n', b'[http]\n[http]\n',
                    b'[net]\ngit-fetch-with-cli = 1\n', b'[net]\ninclude = []\n',
                    b'[http]\nproxy = "\\n"\n', b'[http]\nproxy = "x" # outside subset\n',
                    b'x' * (1048576 + 1)):
            with self.subTest(raw=raw[:80]), self.assertRaises((ValueError,UnicodeError)):
                build.check_config(raw)

    def test_root_configuration_scope_complete_then_every_denial_and_grammar_failure(self):
        rows = {'root-config':dict(state='ABSENT'), 'home-config':dict(state='READ',
                identity=dict(path='/config',sha256='pin'))}
        ctx = types.SimpleNamespace(B=types.SimpleNamespace(configuration=mock.Mock(return_value=rows)),
                                    read=mock.Mock(return_value=b'[http]\nproxy=""\n'))
        captured = dict(env={'CARGO_HOME':'/cargo-home'})
        self.assertEqual(build.configurations(ctx,captured),rows)
        ctx.B.configuration.assert_called_once_with(Path('/'),Path('/cargo-home'))
        ctx.read.assert_called_once_with(Path('/config'),rows['home-config']['identity'],1048576)
        for state in ('READ_DENIED','unexpected'):
            ctx.B.configuration.return_value = {'one':dict(state=state)}
            with self.assertRaises(ValueError): build.configurations(ctx,captured)
        ctx.B.configuration.return_value = rows
        ctx.read.return_value = b'include=["outside"]\n'
        with self.assertRaises(ValueError): build.configurations(ctx,captured)

    def test_comment_profile_preserves_values_and_old_strict_refusals(self):
        for raw in (b'[net] # section\ngit-fetch-with-cli=true # transport only\n',
                    b'[http]\nproxy="http://localhost:3128" # transport only\n',
                    b'[http]\nproxy="http://localhost/#fragment" # outside\n',
                    b'[http]\nproxy="quote\\\"#inside" # outside\n',
                    b'[http]\nproxy="backslash\\\\" # outside\n'):
            build.check_commented_config(raw)
            with self.assertRaises(ValueError): build.check_config(raw)
        normalized = b'[http]\nproxy="http://localhost/#fragment" '
        with mock.patch.object(build,'check_config') as strict:
            build.check_commented_config(normalized+b'#outside\n')
            strict.assert_called_once_with(normalized)
        for raw in (b'include=[] # forbidden\n', b'[build] # forbidden\nrustc="x"\n',
                    b'[net]\ngit-fetch-with-cli=1 # not boolean\n',
                    b'[http]\nproxy="x" include=[] # still invalid\n',
                    b'[http]\nproxy="unterminated # still string\n',
                    b'[http]\nproxy="x"\nproxy="y" # duplicate\n',
                    b'[http]\nproxy="\\n" # control character\n',
                    b'#' + b'x' * 1048576):
            with self.subTest(raw=raw[:80]), self.assertRaises(ValueError):
                build.check_commented_config(raw)
        rows={'root':dict(state='ABSENT'), 'home':dict(state='READ',identity=dict(path='/config'))}
        ctx=types.SimpleNamespace(B=types.SimpleNamespace(configuration=mock.Mock(return_value=rows)),
                                 read=mock.Mock(return_value=b'[net]\ngit-fetch-with-cli=true # comment\n'))
        captured=dict(env={'CARGO_HOME':'/cache'})
        with self.assertRaises(ValueError): build.configurations(ctx,captured)
        self.assertEqual(build.configurations(ctx,captured,profile=build.COMMENT_PROFILE),rows)
        with self.assertRaises(ValueError): build.configurations(ctx,captured,profile='unknown')

    def test_launcher_exact_toolchain_manifest_target_and_exec_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); manifest = root/w.CRATE/'Cargo.toml'
            manifest.parent.mkdir(parents=True); manifest.write_text('[package]\n')
            env = {'RUSTC':'/fixed/toolchain/bin/rustc', 'CARGO_HOME':'/fixed/cache',
                   'CARGO_TARGET_DIR':str(root/'target')}
            argv = launcher.command(root,env,'/fixed/toolchain/bin/cargo',str(manifest))
            self.assertEqual(argv,['/fixed/toolchain/bin/cargo','build','--release','--locked',
                '--offline','--manifest-path',str(manifest),'--bin','adjacent-b2-artifact-verifier',
                '--message-format=json'])
            for cargo, path in (('/usr/bin/cargo',str(manifest)),('/fixed/toolchain/bin/cargo',str(root/'Cargo.toml'))):
                with self.assertRaises(AssertionError): launcher.command(root,env,cargo,path)
            for key,value in (('RUSTC','rustc'),('CARGO_HOME','relative'),('CARGO_TARGET_DIR',str(root/'other'))):
                with self.assertRaises(AssertionError):
                    launcher.command(root,dict(env,**{key:value}),'/fixed/toolchain/bin/cargo',str(manifest))
        expected=['/fixed/cargo','build']
        events=[]
        with mock.patch.object(launcher.sys,'argv',['launcher','cargo','manifest']), \
             mock.patch.object(launcher,'command',return_value=expected), \
             mock.patch.object(launcher.os,'chdir',side_effect=lambda p:events.append(('cwd',p))), \
             mock.patch.object(launcher.os,'execve',side_effect=lambda *a:events.append(('exec',a))):
            launcher.main()
        self.assertEqual(events,[('cwd','/'),('exec',(expected[0],expected,dict(os.environ)))])

    def test_schema_two_exact_rooted_build_before_each_identity_scope_and_command_mutant(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); out=root/'build'; out.mkdir()
            captured=dict(env={'CARGO_HOME':'/cargo-home'},
                tools={n:dict(path='/tools/'+n) for n in ('python','helper','timeout','cargo')})
            ctx=types.SimpleNamespace(ROOT=root,load=mock.Mock(),
                closed=mock.Mock(return_value=(0,{'stdout':b'build-json'})))
            a=types.SimpleNamespace(json_value=json.loads,ROUTED=types.SimpleNamespace(builder='b',builder_sha='p'))
            request,command=w.request_and_command(ctx,captured,out,build.invocation(ctx,captured),(120,180,128))
            names=dict(w.VERIFIER_SOURCES,**w.ROOTED_BUILD_SOURCES)
            pins={str(root/w.CRATE/n):dict(sha256=h) for n,h in names.items()}
            binary=root/'target/release/adjacent-b2-artifact-verifier'
            pins.update({str(root/w.CRATE/'Cargo.lock'):dict(sha256='1'*64),str(binary):dict(sha256='2'*64)})
            controls=('request.json','command.json','parent-closed.json','receipt.json','stdout.txt',
                      'stderr.txt','helper.stdout','helper.stderr','planned.json')
            pins.update({str(out/n):dict(sha256='3'*64) for n in controls})
            configs={'root':dict(state='ABSENT'),'home':dict(state='ABSENT')}
            closed=dict(schema='LI2W01-VERIFIER-BUILD-2',cargo_cwd='/',files=pins,
                lock_sha256='1'*64,configuration_complete=True,configurations=configs)
            args=types.SimpleNamespace(verifier_build=out,verifier_lock_sha256='1'*64)
            def check(value,cmd=command):
                raw=json.dumps(value).encode();args.verifier_build_sha256=w.sha(raw)
                ctx.read=lambda p,*a,**k: raw if p==out/'closed.json' else json.dumps(cmd).encode() if p==out/'command.json' else b'bound-input'
                with mock.patch.object(w,'rooted_module',return_value=build), \
                     mock.patch.object(build,'configurations',return_value=configs):
                    return w.verifier_build(ctx,a,args,captured)
            self.assertEqual(check(closed),binary)
            ctx.closed.assert_called_with(out,request)
            self.assertEqual(request['argv'],build.invocation(ctx,captured))
            self.assertEqual(request['cwd'],str(root))
            for mutate in ('cwd','configuration','missing-launcher','launcher-pin','missing-plan','extra'):
                bad=copy.deepcopy(closed)
                if mutate=='cwd':bad['cargo_cwd']=str(root)
                elif mutate=='configuration':bad['configurations']={}
                elif mutate=='missing-launcher':bad['files'].pop(str(root/w.CRATE/'cargo_from_root.py'))
                elif mutate=='launcher-pin':bad['files'][str(root/w.CRATE/'cargo_from_root.py')]['sha256']='0'*64
                elif mutate=='missing-plan':bad['files'].pop(str(out/'planned.json'))
                else:bad['unbound']='extra'
                with self.subTest(mutate=mutate),self.assertRaises(ValueError):check(bad)
            with self.assertRaises(ValueError): check(closed,dict(command,cwd='/'))
            commented=dict(closed,schema='LI2W01-VERIFIER-BUILD-3',configuration_profile=build.COMMENT_PROFILE)
            self.assertEqual(check(commented),binary)
            for mutate in ('missing-profile','wrong-profile','schema-two-with-profile','config-mismatch'):
                bad=copy.deepcopy(commented)
                if mutate=='missing-profile':bad.pop('configuration_profile')
                elif mutate=='wrong-profile':bad['configuration_profile']='unknown'
                elif mutate=='schema-two-with-profile':bad['schema']='LI2W01-VERIFIER-BUILD-2'
                else:bad['configurations']={}
                with self.subTest(mutate=mutate),self.assertRaises(ValueError):check(bad)


if __name__ == '__main__':
    unittest.main()
