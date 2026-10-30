#!/usr/bin/env python3
"""Custody optimization controls. No child, Git, build or native dispatch."""
import copy
import errno
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest import mock

import startup_custody as C
import startup_source_controls as SOURCE


def descriptor():
    ctx = types.SimpleNamespace(ROOT=Path('/repo'))
    pins = types.SimpleNamespace(SOURCE_REVISION='a'*40, SOURCE_PINS={'src/a.rs':'b'*64})
    store = C.Store()
    captured = dict(env={'HOME':'/private'}, tools={'python':{'path':'/python'}})
    configs = {'/private/config':{'state':'ABSENT'}}
    profile = 'rooted-offline-neutral-toml-comments-v1'
    value = C.stability_inputs(ctx,pins,store,captured,configs,profile)
    return ctx,pins,store,captured,configs,profile,value


class DirectoryEdges(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name); path=root/'first/second/value'
        path.parent.mkdir(parents=True); path.write_bytes(b'unchanged')
        store=C.Store(); self.addCleanup(store.close)
        self.assertEqual(store.read(path,32),b'unchanged')
        return root,path,store

    def test_cached_lookup_opens_only_file_but_checks_every_edge(self):
        _,path,store=self.fixture()
        opened=[]; checked=[]; raw_open=os.open; raw_stat=os.stat
        def tracked_open(name,flags,*args,**kw):
            opened.append((str(name),flags));return raw_open(name,flags,*args,**kw)
        def tracked_stat(name,*args,**kw):
            checked.append((str(name),kw));return raw_stat(name,*args,**kw)
        with mock.patch.object(C.os,'open',side_effect=tracked_open), \
             mock.patch.object(C.os,'stat',side_effect=tracked_stat):
            self.assertEqual(store.read(path,32),b'unchanged')
        self.assertEqual(opened,[(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)])
        self.assertIn(('/',{'follow_symlinks':False}),checked)
        for parent in path.parents:
            if parent==Path('/'):continue
            self.assertTrue(any(name==parent.name and 'dir_fd' in kw and kw['follow_symlinks'] is False
                for name,kw in checked),str(parent))

    def test_replaced_ancestor_cannot_hide_behind_held_parent(self):
        root,path,store=self.fixture(); (root/'first').rename(root/'held-first')
        path.parent.mkdir(parents=True);path.write_bytes(b'unchanged')
        with self.assertRaisesRegex(ValueError,'directory identity changed'):store.read(path,32)
        with self.assertRaisesRegex(ValueError,'retained directory replaced'):store.verify()

    def test_symlink_to_same_held_ancestor_still_refuses(self):
        root,path,store=self.fixture(); (root/'first').rename(root/'held-first')
        (root/'first').symlink_to(root/'held-first',target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'directory identity changed'):store.read(path,32)

    def test_cached_ancestor_mode_change_refuses(self):
        _,path,store=self.fixture(); mode=stat.S_IMODE(path.parent.stat().st_mode)
        path.parent.chmod(mode ^ stat.S_IXGRP)
        with self.assertRaisesRegex(ValueError,'directory identity changed'):store.read(path,32)

    def test_cached_file_replacement_and_size_cap_still_refuse(self):
        _,path,store=self.fixture(); replacement=path.with_name('replacement')
        replacement.write_bytes(path.read_bytes());replacement.replace(path)
        with self.assertRaisesRegex(ValueError,'cached file changed'):store.read(path,32)
        with self.assertRaisesRegex(ValueError,'regular file size/type'):store.read(path,1)

    def test_root_identity_is_not_trusted_from_previous_read(self):
        _,path,store=self.fixture(); original=os.stat
        def changed(name,*args,**kw):
            value=original(name,*args,**kw)
            if str(name)=='/':
                return types.SimpleNamespace(st_dev=value.st_dev,st_ino=value.st_ino+1,st_mode=value.st_mode)
            return value
        with mock.patch.object(C.os,'stat',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'retained root replaced'):store.read(path,32)
            with self.assertRaisesRegex(ValueError,'retained root replaced'):store.verify()

    def test_close_releases_all_held_directory_and_root_descriptors(self):
        _,_,store=self.fixture(); fds=[fd for fd,_ in store.directories.values()]+[store.root[0]]
        store.close();self.assertEqual(store.directories,{});self.assertEqual(store.chains,{})
        self.assertIsNone(store.root)
        for fd in fds:
            with self.assertRaises(OSError) as error:os.fstat(fd)
            self.assertEqual(error.exception.errno,errno.EBADF)


class FreshSourceIdentity(unittest.TestCase):
    fixture=SOURCE.SourceSemantics.fixture

    def call(self,pins,ctx,git):
        with mock.patch.object(C.subprocess,'check_output',side_effect=git), \
             mock.patch.object(C,'source_batch'):
            return C.source_profile(ctx,pins,{'TOKEN':'fixed'})

    def test_same_bytes_new_inode_between_boundaries_refuses(self):
        _,pins,ctx,_,_,git=self.fixture();self.call(pins,ctx,git)
        path=ctx.ROOT/'src/a.rs';replacement=path.with_name('replacement')
        replacement.write_bytes(path.read_bytes());replacement.replace(path)
        with self.assertRaisesRegex(ValueError,'source identity drift'):self.call(pins,ctx,git)

    def test_same_bytes_metadata_drift_between_boundaries_refuses(self):
        _,pins,ctx,_,_,git=self.fixture();self.call(pins,ctx,git)
        path=ctx.ROOT/'src/a.rs';info=path.stat()
        os.utime(path,ns=(info.st_atime_ns,info.st_mtime_ns+1000000))
        with self.assertRaisesRegex(ValueError,'source identity drift'):self.call(pins,ctx,git)

    def test_preexisting_ctx_pin_cannot_be_overwritten(self):
        _,pins,ctx,_,_,git=self.fixture();self.call(pins,ctx,git)
        key=str(ctx.ROOT/'src/a.rs');ctx.PINS[key]['stat'][1]+=1
        previous=copy.deepcopy(ctx.PINS[key])
        with self.assertRaisesRegex(ValueError,'source identity drift'):self.call(pins,ctx,git)
        self.assertEqual(ctx.PINS[key],previous)

    def test_success_populates_all_full_pins_and_reads_every_pass(self):
        files,pins,ctx,reads,_,git=self.fixture()
        self.call(pins,ctx,git);old=copy.deepcopy(ctx.PINS);self.call(pins,ctx,git)
        self.assertEqual(ctx.PINS,old);self.assertEqual(reads,sorted(files)*2)
        self.assertEqual(set(old),{str(ctx.ROOT/name) for name in files})
        for name,raw in files.items():
            value=old[str(ctx.ROOT/name)]
            self.assertEqual(value,dict(path=str(ctx.ROOT/name),bytes=len(raw),sha256=C.sha(raw),
                stat=C.stamp((ctx.ROOT/name).stat())))

    def test_fresh_live_snapshot_closes_on_digest_or_identity_refusal(self):
        _,pins,ctx,_,_,git=self.fixture();self.call(pins,ctx,git)
        ctx.PINS[str(ctx.ROOT/'src/a.rs')]['stat'][1]+=1
        closed=[];original=C.Store.close
        def close(store):
            fds=[fd for fd,_ in store.directories.values()]
            if store.root is not None:fds.append(store.root[0])
            original(store);closed.extend(fds)
        with mock.patch.object(C.Store,'close',close):
            with self.assertRaisesRegex(ValueError,'source identity drift'):self.call(pins,ctx,git)
        self.assertTrue(closed)
        for fd in closed:
            with self.assertRaises(OSError) as error:os.fstat(fd)
            self.assertEqual(error.exception.errno,errno.EBADF)


    def during_last_payload(self, action):
        files,pins,ctx,reads,_,git=self.fixture()
        last=ctx.ROOT/'src/b.rs'; identity=C.stamp(last.stat())[:2]
        fired=[];closed=[];actual_read=os.read;actual_close=C.Store.close
        def changed(fd, cap):
            raw=actual_read(fd,cap)
            if raw and C.stamp(os.fstat(fd))[:2]==identity and not fired:
                action(ctx.ROOT);fired.append(True)
            return raw
        def close(store):
            fds=[fd for fd,_ in store.directories.values()]
            if store.root is not None:fds.append(store.root[0])
            actual_close(store);closed.extend(fds)
        with mock.patch.object(C.os,'read',side_effect=changed),mock.patch.object(C.Store,'close',close):
            with self.assertRaisesRegex(ValueError,'retained directory replaced'):
                self.call(pins,ctx,git)
        self.assertEqual(fired,[True]);self.assertEqual(reads,sorted(files))
        self.assertTrue(closed)
        for fd in closed:
            with self.assertRaises(OSError) as error:os.fstat(fd)
            self.assertEqual(error.exception.errno,errno.EBADF)

    def test_last_payload_ancestor_replacement_refuses_before_snapshot_return(self):
        def replace(root):
            (root/'src').rename(root/'held-src');(root/'src').mkdir()
            # Leave the held leaf inode/metadata untouched; the relative
            # post-read check alone would still see that exact old file.
            for name in ('a.rs','b.rs'):(root/'src'/name).write_bytes((root/'held-src'/name).read_bytes())
        self.during_last_payload(replace)

    def test_last_payload_ancestor_mode_change_refuses_before_snapshot_return(self):
        def change(root):
            path=root/'src';path.chmod(stat.S_IMODE(path.stat().st_mode)^stat.S_IXGRP)
        self.during_last_payload(change)

    def test_success_rechecks_entire_graph_and_all_leaves_after_last_fresh_read(self):
        files,pins,ctx,reads,_,git=self.fixture();verified=[];actual=C.Store.verify
        def verify(store):
            self.assertEqual(reads,sorted(files))
            self.assertEqual(set(store.files),{str(ctx.ROOT/name) for name in files})
            actual(store);verified.append(True)
        with mock.patch.object(C.Store,'verify',verify):self.call(pins,ctx,git)
        self.assertEqual(verified,[True]);self.assertEqual(reads,sorted(files))


class ComposedInputs(unittest.TestCase):
    def test_exact_same_predicates_join_without_validation_token(self):
        ctx,pins,store,captured,configs,profile,value=descriptor();self.addCleanup(store.close)
        self.assertIsNone(C.join_stability(value,ctx,pins,store,captured,configs,profile))
        self.assertNotIn('success',value);self.assertNotIn('revision_checked',value)

    def test_every_shared_input_and_unknown_field_is_checked(self):
        ctx,pins,store,captured,configs,profile,value=descriptor();self.addCleanup(store.close)
        mutations={
            'root':lambda v:v.update(root='/different'),
            'source_revision':lambda v:v.update(source_revision='c'*40),
            'source_pins':lambda v:v['source_pins'].update({'src/a.rs':'c'*64}),
            'env':lambda v:v['captured']['env'].update(HOME='/different'),
            'tools':lambda v:v['captured']['tools']['python'].update(path='/different'),
            'configurations':lambda v:v['configurations']['/private/config'].update(state='READ'),
            'configuration_profile':lambda v:v.update(configuration_profile='different'),
            'extra':lambda v:v.update(success=True)}
        for name,mutate in mutations.items():
            changed={k:v if k in ('store','ctx') else copy.deepcopy(v) for k,v in value.items()};mutate(changed)
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'identical composed stability inputs'):
                C.join_stability(changed,ctx,pins,store,captured,configs,profile)
        other=C.Store();self.addCleanup(other.close);changed=dict(value,store=other)
        with self.assertRaisesRegex(ValueError,'identical composed stability inputs'):
            C.join_stability(changed,ctx,pins,store,captured,configs,profile)
        changed=dict(value,ctx=types.SimpleNamespace(ROOT=ctx.ROOT))
        with self.assertRaisesRegex(ValueError,'identical composed stability inputs'):
            C.join_stability(changed,ctx,pins,store,captured,configs,profile)

    def test_descriptor_is_snapshot_of_mutable_shared_inputs(self):
        ctx,pins,store,captured,configs,profile,value=descriptor();self.addCleanup(store.close)
        for mutate,undo in (
            (lambda:captured['env'].update(HOME='/changed'),lambda:captured['env'].update(HOME='/private')),
            (lambda:pins.SOURCE_PINS.update({'src/a.rs':'d'*64}),lambda:pins.SOURCE_PINS.update({'src/a.rs':'b'*64})),
            (lambda:configs['/private/config'].update(state='READ'),lambda:configs['/private/config'].update(state='ABSENT'))):
            mutate()
            with self.assertRaisesRegex(ValueError,'identical composed stability inputs'):
                C.join_stability(value,ctx,pins,store,captured,configs,profile)
            undo()


class TerminalBoundary(unittest.TestCase):
    def fixture(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);artifact=root/'retained-transport.bin';artifact.write_bytes(b'fixed')
        store=C.Store();self.addCleanup(store.close);store.read(artifact,32)
        ctx=types.SimpleNamespace(ROOT=root,PINS={});pins=types.SimpleNamespace()
        captured=dict(env={'fixed':'environment'},tools={});configs={'external':'ABSENT'}
        rooted=types.SimpleNamespace(COMMENT_PROFILE='fixed',configurations=lambda *args,**kw:dict(configs))
        return artifact,store,ctx,pins,captured,configs,rooted

    def test_non_source_artifact_changed_during_source_work_refuses_at_terminal_check(self):
        artifact,store,ctx,pins,captured,configs,rooted=self.fixture()
        def changed(*args):
            replacement=artifact.with_name('replacement');replacement.write_bytes(b'fixed')
            replacement.replace(artifact);return 'a'*40
        with mock.patch.object(C,'source_profile',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'cached file changed'):
                C.verify_stability(ctx,pins,store,captured,rooted,configs)

    def test_external_configuration_changed_during_source_work_refuses(self):
        artifact,store,ctx,pins,captured,configs,rooted=self.fixture()
        config=artifact.parent/'previously-absent-cargo-config.toml'
        rooted.configurations=lambda *args,**kw:{'external':'READ' if config.exists() else 'ABSENT'}
        def changed(*args):config.write_bytes(b'[net]\noffline = true\n');return 'a'*40
        with mock.patch.object(C,'source_profile',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'original-facts configuration drift'):
                C.verify_stability(ctx,pins,store,captured,rooted,configs)

    def test_terminal_store_follows_configuration_and_runs_on_each_call(self):
        artifact,store,ctx,pins,captured,configs,rooted=self.fixture();events=[]
        actual=store.verify
        def verify():events.append('store');actual()
        def config(*args,**kw):events.append('config');return dict(configs)
        def source(*args):events.append('source');return 'a'*40
        rooted.configurations=config
        with mock.patch.object(store,'verify',side_effect=verify),mock.patch.object(C,'source_profile',side_effect=source):
            for _ in range(2):self.assertEqual(C.verify_stability(ctx,pins,store,captured,rooted,configs),'a'*40)
        self.assertEqual(events,['store','config','source','config','store']*2)
        calls=[0]
        def changed_config(*args,**kw):
            calls[0]+=1
            if calls[0]==2:
                replacement=artifact.with_name('replacement');replacement.write_bytes(b'fixed')
                replacement.replace(artifact)
            return dict(configs)
        rooted.configurations=changed_config
        with mock.patch.object(C,'source_profile',return_value='a'*40):
            with self.assertRaisesRegex(ValueError,'cached file changed'):
                C.verify_stability(ctx,pins,store,captured,rooted,configs)


class BuildBoundary(unittest.TestCase):
    def test_actual_build_inputs_calls_original_validator_at_every_boundary(self):
        path=Path(__file__).resolve().parents[2]/'offline-router-native/native_launch.py'
        spec=importlib.util.spec_from_file_location('_preflight_native_launch',path)
        launch=importlib.util.module_from_spec(spec);spec.loader.exec_module(launch)
        root=Path('/repo');pins=types.SimpleNamespace(SOURCE_REVISION='a'*40,SOURCE_PINS={'source':'b'*64})
        ctx=types.SimpleNamespace(ROOT=root);captured=dict(env={'fixed':'environment'},tools={});configs={}
        profile='rooted-offline-neutral-toml-comments-v1';events=[];revision=['a'*40];config_live=[True]
        class Store:
            def read(self,path,cap):
                if str(path).endswith('planned.json'):return json.dumps(captured).encode('ascii')
                return b'source'
            def verify(self):events.append('store')
        store=Store()
        def stable():
            store.verify();events.append('config');C.need(config_live[0],'original-facts configuration drift')
            events.append('source');return revision[0]
        originals=types.SimpleNamespace(authenticate=lambda *args:dict(stable=stable,
            stability=C.stability_inputs(ctx,pins,store,captured,configs,profile)))
        rooted=types.SimpleNamespace(COMMENT_PROFILE=profile,configurations=lambda *args,**kw:configs)
        custody=types.SimpleNamespace(environment=lambda *args:None,join_stability=C.join_stability,
            source_profile=lambda *args:revision[0])
        modules=types.SimpleNamespace(ctx=ctx,pins=pins,a=None,originals=originals,custody=custody,
            legacy=types.SimpleNamespace(rooted_module=lambda _:rooted))
        native={launch.NATIVE+'observer/'+p:launch.sha(b'source') for p in launch.OBSERVER}
        native[launch.NATIVE+'native_launch.py']=launch.sha(b'source')
        plan=dict(schema='LI2NATIVE-OBSERVER-BUILD-PLAN-1',root=str(root),native_sources=native,
            artifact_source_profile={},capture={'directory':'/capture'},output='/output',destination='/binary')
        with mock.patch.object(launch.os.path,'lexists',return_value=False):
            _,_,expected,check=launch.build_inputs(root,plan,modules,store)
        self.assertEqual(expected,'a'*40);check();check()
        self.assertEqual(events,['store','config','source']*2)
        revision[0]='c'*40
        with self.assertRaisesRegex(ValueError,'observer build revision drift'):check()
        self.assertEqual(events,['store','config','source']*3)
        revision[0]=expected;config_live[0]=False
        with self.assertRaisesRegex(ValueError,'original-facts configuration drift'):check()
        self.assertEqual(events[-2:],['store','config'])


if __name__=='__main__':unittest.main()
