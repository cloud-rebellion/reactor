"""Unprivileged synthetic controller qualification; no accounts/units/real chown.

The actual Linux UID/systemd/cache loan remains the separate hosted-CI proof.
Fixtures use their own bounded scratch. No production path is created or read.
"""
import argparse
import ast
import copy
import contextlib
import errno
import io
import os
import pathlib
import stat
import tempfile
import types
import unittest
from unittest import mock

P = pathlib.Path
SOURCE = P(__file__).with_name('ci-uid.py')
s = types.ModuleType('ci_uid_subject'); s.__file__ = str(SOURCE)
exec(compile(SOURCE.read_bytes(), str(SOURCE), 'exec'), s.__dict__)

class UIDControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('BUILD_SCRATCH_DIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = P(self.tmp.name).resolve()
        self.owner = (os.getuid(), os.getgid())

    def scan(self, root=None, owner=None):
        # Linux file-capability behavior has its own decision cases below.
        # Darwin has a different xattr namespace, so filesystem/CAS fixtures
        # do not pretend to qualify Linux capability enforcement.
        with mock.patch.object(s, 'no_file_capabilities'):
            return s.snapshot(root or self.root, owner)

    def test_plain_bounded_read(self):
        p = self.root/'plain';p.write_bytes(b'exact source')
        self.assertEqual(s.safe_read(p),b'exact source')
        with self.assertRaisesRegex(RuntimeError,'bounded_plain'):s.safe_read(p,2)

    def test_real_read_can_change_atime_without_changing_stable_identity(self):
        p = self.root/'old-access-time';p.write_bytes(b'atime-only read fixture')
        os.utime(p,ns=(1,2))
        before=p.lstat();p.read_bytes();control=p.lstat()
        if control.st_atime_ns == before.st_atime_ns:
            self.skipTest('filesystem does not update atime; real Linux atime qualification remains required')
        os.utime(p,ns=(1,2));before=p.lstat()
        self.assertEqual(s.safe_read(p),b'atime-only read fixture')
        after=p.lstat()
        self.assertNotEqual(after.st_atime_ns,before.st_atime_ns)
        self.assertEqual(s.stable_identity(after),s.stable_identity(before))

    def test_mid_read_leaf_replacement_is_still_rejected(self):
        p=self.root/'plain';p.write_bytes(b'original')
        real=os.fstat;calls=0
        def observe(fd):
            nonlocal calls
            calls+=1;value=real(fd)
            if calls==2:
                p.rename(self.root/'retained-original');p.write_bytes(b'foreign replacement')
            return value
        with mock.patch.object(s.os,'fstat',side_effect=observe):
            with self.assertRaisesRegex(RuntimeError,'file_path_changed'):s.safe_read(p)
        self.assertEqual((self.root/'retained-original').read_bytes(),b'original')
        self.assertEqual(p.read_bytes(),b'foreign replacement')

    def test_safe_read_rejects_symlink_and_hardlink(self):
        p=self.root/'real';p.write_bytes(b'data')
        link=self.root/'link';link.symlink_to(p)
        with self.assertRaisesRegex(RuntimeError,'bounded_plain'):s.safe_read(link)
        os.link(p,self.root/'hardlink')
        with self.assertRaisesRegex(RuntimeError,'bounded_plain'):s.safe_read(p)

    def test_physical_root_cannot_follow_a_symlink_component(self):
        real=self.root/'real';real.mkdir();(self.root/'alias').symlink_to(real,target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError,'physical_path_component'):s.physical(self.root/'alias')

    def test_default_local_public_git_config_is_accepted(self):
        s.local_git_config(b'core.bare\nfalse\0remote.origin.url\nhttps://github.com/cloud-rebellion/reactor\0remote.origin.fetch\n+refs/heads/*:refs/remotes/origin/*\0')

    def test_git_actor_auth_includes_rewrites_and_filters_are_rejected(self):
        cases=[b'credential.helper\nsynthetic',b'include.path\n/private',b'includeif.gitdir:/tmp.path\n/private',b'http.https://github.com/.extraheader\nsynthetic',b'url.https://synthetic@github.com/.insteadof\nhttps://github.com/',b'http.proxy\nsynthetic',b'core.askpass\nsynthetic',b'core.fsmonitor\nsynthetic',b'filter.synthetic.clean\nsynthetic',b'remote.origin.url\nhttps://github.com/foreign/repo']
        for row in cases:
            with self.subTest(key=row.split(b'\n')[0]):
                with self.assertRaises(RuntimeError):s.local_git_config(row+b'\0')

    def test_snapshot_reads_only_original_owner_plain_tree(self):
        (self.root/'dir').mkdir();(self.root/'dir/file').write_text('source')
        view=self.scan(owner=self.owner)
        self.assertEqual([x['path'] for x in view['entries']],['','dir','dir/file'])
        with self.assertRaisesRegex(RuntimeError,'not_original_runner_owned'):self.scan(owner=(self.owner[0]+1,self.owner[1]))

    def test_snapshot_does_not_follow_symlink_or_foreign_hardlink(self):
        (self.root/'link').symlink_to('/does-not-exist')
        with self.assertRaisesRegex(RuntimeError,'symlink_in_loan'):self.scan()
        (self.root/'link').unlink();p=self.root/'one';p.write_text('x');os.link(p,self.root/'two')
        with self.assertRaisesRegex(RuntimeError,'hardlinked_entry'):self.scan()

    def test_snapshot_has_finite_count_and_special_file_refusal(self):
        (self.root/'one').write_text('x');(self.root/'two').write_text('y')
        with mock.patch.object(s,'MAX_ENTRIES',2):
            with self.assertRaisesRegex(RuntimeError,'loan_entry_count'):self.scan()
        (self.root/'one').unlink();(self.root/'two').unlink();os.mkfifo(self.root/'pipe')
        with self.assertRaisesRegex(RuntimeError,'special_file'):self.scan()

    def test_linux_file_capability_metadata_fails_closed(self):
        with mock.patch.object(s.os,'getxattr',create=True,side_effect=OSError(errno.ENODATA,'synthetic')):s.no_file_capabilities(123)
        with mock.patch.object(s.os,'getxattr',create=True,return_value=b'capability'):
            with self.assertRaisesRegex(RuntimeError,'file_capabilities'):s.no_file_capabilities(123)
        with mock.patch.object(s.os,'getxattr',create=True,side_effect=PermissionError(errno.EPERM,'synthetic')):
            with self.assertRaisesRegex(RuntimeError,'unreadable'):s.no_file_capabilities(123)

    def test_postloan_requires_same_complete_tree_and_ci_owners(self):
        (self.root/'file').write_text('x');before=self.scan(owner=self.owner);after=copy.deepcopy(before)
        for entry in after['entries']:entry['identity'][4:6]=[s.UID,s.GID]
        after['identity'][4:6]=[s.UID,s.GID];s.verify_loan(before,after)
        mutations=[lambda x:x['entries'][1]['identity'].__setitem__(1,999999),lambda x:x['entries'][1]['identity'].__setitem__(4,self.owner[0]),lambda x:x['entries'].append(copy.deepcopy(x['entries'][1])|{'path':'unreviewed-extra'}),lambda x:x['entries'].pop()]
        for mutate in mutations:
            changed=copy.deepcopy(after);mutate(changed)
            with self.assertRaises(RuntimeError):s.verify_loan(before,changed)

    def test_leaf_replaced_after_snapshot_is_never_chowned(self):
        p=self.root/'leaf';p.write_text('old');view=self.scan(owner=self.owner)
        p.rename(self.root/'retained');p.write_text('foreign')
        with mock.patch.object(s.os,'fchown') as change:
            with self.assertRaisesRegex(RuntimeError,'ownership_cas'):s.chown_entries(view,*self.owner,{self.owner})
        # The rename also changes the directory's stable metadata, so the
        # strengthened CAS refuses even before changing that root owner.
        self.assertEqual(change.call_count,0)
        self.assertEqual(p.read_text(),'foreign')

    def test_missing_unit_is_safe_only_after_successful_wait(self):
        with mock.patch.object(s,'unit_state',return_value={'LoadState':'not-found'}),mock.patch.object(s,'tasks_for_uid',return_value=0),mock.patch.object(s,'command',return_value=b''):
            self.assertTrue(s.unit_closed('owned.service','owned',0)['closed'])
            for code in (1,75,-9,None):
                with self.assertRaisesRegex(RuntimeError,'ambiguous'):s.unit_closed('owned.service','owned',code)

    def terminal(self):
        return {'Id':'owned.service','LoadState':'loaded','ActiveState':'failed','MainPID':'0','Description':'owned','User':str(s.UID),'Group':str(s.GID),'InvocationID':'a'*32}

    def test_known_terminal_identity_invocation_and_zero_tasks_are_required(self):
        with mock.patch.object(s,'unit_state',return_value=self.terminal()),mock.patch.object(s,'tasks_for_uid',return_value=0),mock.patch.object(s,'command',return_value=b''):
            self.assertTrue(s.unit_closed('owned.service','owned',1)['closed'])
        for key,value in [('Description','foreign'),('ActiveState','active'),('MainPID','10'),('User','0'),('InvocationID','')]:
            state=self.terminal();state[key]=value
            with self.subTest(key=key),mock.patch.object(s,'unit_state',return_value=state),mock.patch.object(s,'command',return_value=b''):
                with self.assertRaises(RuntimeError):s.unit_closed('owned.service','owned',1)
        with mock.patch.object(s,'unit_state',return_value=self.terminal()),mock.patch.object(s,'tasks_for_uid',return_value=1),mock.patch.object(s,'command',return_value=b''):
            with self.assertRaisesRegex(RuntimeError,'still_has_tasks'):s.unit_closed('owned.service','owned',1)

    def test_pending_native_job_blocks_owner_restoration(self):
        with mock.patch.object(s,'unit_state',return_value=self.terminal()),mock.patch.object(s,'tasks_for_uid',return_value=0),mock.patch.object(s,'command',return_value=b'12 owned.service start waiting\n'):
            with self.assertRaisesRegex(RuntimeError,'pending_native_job'):s.unit_closed('owned.service','owned',1)

    def test_original_environment_does_not_copy_actor_tokens(self):
        with mock.patch.dict(os.environ,{'GITHUB_TOKEN':'synthetic-only','SSH_AUTH_SOCK':'synthetic-only'}):
            env=s.original_env('/home/runner','/usr/bin:/bin')
        self.assertNotIn('GITHUB_TOKEN',env);self.assertNotIn('SSH_AUTH_SOCK',env)
        self.assertEqual(env['GIT_NO_REPLACE_OBJECTS'],'1')

    def test_original_tool_discovery_never_executes_as_root(self):
        result=types.SimpleNamespace(returncode=0,stdout=b'exact',stderr=b'')
        with mock.patch.object(s.subprocess,'run',return_value=result) as run:
            self.assertEqual(s.command(['/synthetic/go','version'],user=(1001,1001),env={'PATH':'/usr/bin'}),b'exact')
        argv=run.call_args.args[0]
        self.assertEqual(argv[:5],['/usr/bin/setpriv','--reuid=1001','--regid=1001','--clear-groups','--no-new-privs'])

    def test_unknown_mode_cannot_reach_root_preflight(self):
        with mock.patch.object(s.sys,'argv',['ci-uid.py','--mode','arbitrary-command']),mock.patch.object(s,'prepare') as prepare,mock.patch('sys.stderr',new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as result:s.main()
            self.assertEqual(result.exception.code,2);prepare.assert_not_called()

    def test_inside_never_accepts_docker_or_sudo_group_inheritance(self):
        with mock.patch.object(s.os,'getuid',return_value=s.UID),mock.patch.object(s.os,'geteuid',return_value=s.UID),mock.patch.object(s.os,'getgid',return_value=s.GID),mock.patch.object(s.os,'getgroups',return_value=[s.GID,988]),mock.patch.object(s,'safe_read') as read:
            with self.assertRaisesRegex(RuntimeError,'unprivileged_identity'):s.inside('/not-read')
            read.assert_not_called()

    @contextlib.contextmanager
    def owned_account(self, automatic_group_removal=False):
        home = self.root/'operation/home'
        user = s.pwd.struct_passwd((s.ACCOUNT, 'x', s.UID, s.GID, '', str(home), '/usr/sbin/nologin'))
        group = s.grp.struct_group((s.ACCOUNT, 'x', s.GID, []))
        model = types.SimpleNamespace(home=home, users=[user], groups=[group], commands=[], after_userdel=None, after_groupdel=None, failure=None)
        def lookup(records, field, key):
            for record in records:
                if getattr(record, field) == key:return record
            raise KeyError(key)
        def run(argv):
            model.commands.append(list(argv))
            name = {s.ROOT_TOOLS['userdel']:'userdel',s.ROOT_TOOLS['groupdel']:'groupdel'}.get(argv[0])
            self.assertIn(name,('userdel','groupdel'));self.assertEqual(argv[1:],[s.ACCOUNT])
            if name == model.failure:raise RuntimeError('fixed_command_failed:' + name + ':exit=10')
            if name == 'userdel':
                model.users=[]
                if automatic_group_removal:model.groups=[]
                if model.after_userdel:model.after_userdel(model)
            else:
                model.groups=[]
                if model.after_groupdel:model.after_groupdel(model)
            return b''
        with contextlib.ExitStack() as stack:
            for owner,name,effect in [(s.pwd,'getpwnam',lambda key:lookup(model.users,'pw_name',key)),(s.pwd,'getpwuid',lambda key:lookup(model.users,'pw_uid',key)),(s.pwd,'getpwall',lambda:list(model.users)),(s.grp,'getgrnam',lambda key:lookup(model.groups,'gr_name',key)),(s.grp,'getgrgid',lambda key:lookup(model.groups,'gr_gid',key))]:
                stack.enter_context(mock.patch.object(owner,name,side_effect=effect))
            stack.enter_context(mock.patch.object(s,'tasks_for_uid',return_value=0))
            stack.enter_context(mock.patch.object(s,'command',side_effect=run))
            yield model

    def test_owned_userdel_may_remove_exact_private_group(self):
        with self.owned_account(automatic_group_removal=True) as model:
            self.assertEqual(s.remove_owned_account(model.home),'removed_by_owned_userdel')
            self.assertEqual(model.commands,[[s.ROOT_TOOLS['userdel'],s.ACCOUNT]])
            s.account_absent()

    def test_retained_exact_empty_group_is_explicitly_removed(self):
        with self.owned_account() as model:
            self.assertEqual(s.remove_owned_account(model.home),'removed_by_owned_groupdel')
            self.assertEqual(model.commands,[[s.ROOT_TOOLS['userdel'],s.ACCOUNT],[s.ROOT_TOOLS['groupdel'],s.ACCOUNT]])
            s.account_absent()

    def test_foreign_account_or_group_is_never_deleted(self):
        changes=[('users',s.pwd.struct_passwd((s.ACCOUNT,'x',s.UID,s.GID,'','/foreign','/usr/sbin/nologin'))),('users',s.pwd.struct_passwd((s.ACCOUNT,'x',s.UID,s.GID,'',str(self.root/'operation/home'),'/bin/bash'))),('users',s.pwd.struct_passwd(('foreign','x',s.UID,s.GID,'','/foreign','/usr/sbin/nologin'))),('groups',s.grp.struct_group((s.ACCOUNT,'x',s.GID,['foreign']))),('groups',s.grp.struct_group(('foreign','x',s.GID,[])))]
        for field,replacement in changes:
            with self.subTest(field=field,replacement=replacement),self.owned_account() as model:
                setattr(model,field,[replacement])
                with self.assertRaises((RuntimeError,KeyError)):s.remove_owned_account(model.home)
                self.assertEqual(model.commands,[])

    def test_two_lookup_directions_must_match_before_deletion(self):
        with self.owned_account() as model,mock.patch.object(s.pwd,'getpwuid',return_value=s.pwd.struct_passwd(('foreign','x',s.UID,s.GID,'','/foreign','/usr/sbin/nologin'))):
            with self.assertRaisesRegex(RuntimeError,'account_changed'):s.remove_owned_account(model.home)
            self.assertEqual(model.commands,[])
        with self.owned_account() as model,mock.patch.object(s.grp,'getgrgid',return_value=s.grp.struct_group(('foreign','x',s.GID,[]))):
            with self.assertRaisesRegex(RuntimeError,'group_changed'):s.remove_owned_account(model.home)
            self.assertEqual(model.commands,[])

    def test_account_name_and_uid_must_both_disappear_after_userdel(self):
        residues=[s.pwd.struct_passwd((s.ACCOUNT,'x',s.UID+1,s.GID,'','/foreign','/usr/sbin/nologin')),s.pwd.struct_passwd(('foreign','x',s.UID,s.GID,'','/foreign','/usr/sbin/nologin'))]
        for residue in residues:
            with self.subTest(residue=residue),self.owned_account() as model:
                model.after_userdel=lambda m,value=residue:m.users.append(value)
                with self.assertRaisesRegex(RuntimeError,'account_remains'):s.remove_owned_account(model.home)
                self.assertEqual(model.commands,[[s.ROOT_TOOLS['userdel'],s.ACCOUNT]])

    def test_group_name_or_gid_replacement_after_userdel_is_never_deleted(self):
        replacements=[s.grp.struct_group((s.ACCOUNT,'x',s.GID+1,[])),s.grp.struct_group(('foreign','x',s.GID,[])),s.grp.struct_group((s.ACCOUNT,'x',s.GID,['foreign']))]
        for replacement in replacements:
            with self.subTest(replacement=replacement),self.owned_account() as model:
                model.after_userdel=lambda m,value=replacement:setattr(m,'groups',[value])
                with self.assertRaisesRegex(RuntimeError,'group_changed_after'):s.remove_owned_account(model.home)
                self.assertEqual(model.commands,[[s.ROOT_TOOLS['userdel'],s.ACCOUNT]])

    def test_foreign_primary_group_users_block_cleanup(self):
        foreign=s.pwd.struct_passwd(('foreign','x',s.UID+1,s.GID,'','/foreign','/usr/sbin/nologin'))
        with self.owned_account() as model:
            model.users.append(foreign)
            with self.assertRaisesRegex(RuntimeError,'foreign_primary_group'):s.remove_owned_account(model.home)
            self.assertEqual(model.commands,[])
        with self.owned_account() as model:
            model.after_userdel=lambda m:m.users.append(foreign)
            with self.assertRaisesRegex(RuntimeError,'foreign_primary_group'):s.remove_owned_account(model.home)
            self.assertEqual(model.commands,[[s.ROOT_TOOLS['userdel'],s.ACCOUNT]])

    def test_userdel_and_groupdel_failures_are_not_ignored(self):
        for name in ('userdel','groupdel'):
            with self.subTest(command=name),self.owned_account() as model:
                model.failure=name
                with self.assertRaisesRegex(RuntimeError,'fixed_command_failed:'+name+':exit=10'):s.remove_owned_account(model.home)
                self.assertEqual(len(model.commands),1 if name=='userdel' else 2)

    def test_automatic_group_removal_still_refuses_foreign_primary_gid_user(self):
        foreign=s.pwd.struct_passwd(('foreign','x',s.UID+1,s.GID,'','/foreign','/usr/sbin/nologin'))
        with self.owned_account(automatic_group_removal=True) as model:
            model.after_userdel=lambda m:m.users.append(foreign)
            with self.assertRaisesRegex(RuntimeError,'foreign_primary_group'):s.remove_owned_account(model.home)
            self.assertEqual(model.commands,[[s.ROOT_TOOLS['userdel'],s.ACCOUNT]])

    def test_group_must_disappear_after_explicit_groupdel(self):
        with self.owned_account() as model:
            original=model.groups[0]
            model.after_groupdel=lambda m:m.groups.append(original)
            with self.assertRaisesRegex(RuntimeError,'group_remains_after'):s.remove_owned_account(model.home)

    def test_cleanup_requires_zero_uid_tasks_before_each_delete(self):
        with self.owned_account() as model,mock.patch.object(s,'tasks_for_uid',return_value=1):
            with self.assertRaisesRegex(RuntimeError,'still_has_tasks'):s.remove_owned_account(model.home)
            self.assertEqual(model.commands,[])
        with self.owned_account() as model,mock.patch.object(s,'tasks_for_uid',side_effect=[0,1]):
            with self.assertRaisesRegex(RuntimeError,'still_has_tasks'):s.remove_owned_account(model.home)
            self.assertEqual(model.commands,[[s.ROOT_TOOLS['userdel'],s.ACCOUNT]])

    def test_fixed_command_attribution_exposes_no_arguments_or_output(self):
        for tool in ('userdel','groupdel'):
            result=types.SimpleNamespace(returncode=10,stdout=b'private stdout',stderr=b'private stderr')
            with self.subTest(tool=tool),mock.patch.object(s.subprocess,'run',return_value=result):
                with self.assertRaisesRegex(RuntimeError,'^fixed_command_failed:'+tool+':exit=10$'):s.command([s.ROOT_TOOLS[tool],'private argument'])
        result=types.SimpleNamespace(returncode=10,stdout=b'private stdout',stderr=b'private stderr')
        with mock.patch.object(s.subprocess,'run',return_value=result):
            with self.assertRaisesRegex(RuntimeError,'^fixed_command_failed:fixed:exit=10$'):s.command(['/unrecognized/private/tool','private argument'])

    def test_observer_records_sampled_peak_without_a_new_limit(self):
        sampled=s.threading.Event();values=iter((3,80,7))
        def sample(uid):
            self.assertEqual(uid,s.UID)
            value=next(values,7)
            if value==7:sampled.set()
            return value
        with mock.patch.object(s,'tasks_for_uid',side_effect=sample),mock.patch.object(s.UIDThreadObservation,'INTERVAL_SECONDS',0.001):
            observation=s.UIDThreadObservation();observation.start()
            try:self.assertTrue(sampled.wait(1))
            finally:proof=observation.stop()
        self.assertTrue(proof['observer_joined']);self.assertGreaterEqual(proof['successful_samples'],3)
        self.assertEqual(proof['sampled_peak_uid_threads'],80)
        self.assertTrue(proof['complete_sample_window']);self.assertTrue(proof['sampled_estimate_only'])
        self.assertFalse(proof['enforcement_or_admission_changed'])
        self.assertEqual(observation.stop(),proof)

    def test_observer_read_error_is_explicit_and_exposes_no_process_details(self):
        observed=s.threading.Event()
        def unreadable(uid):
            observed.set();raise PermissionError('private process detail must not escape')
        with mock.patch.object(s,'tasks_for_uid',side_effect=unreadable):
            observation=s.UIDThreadObservation();observation.start()
            try:self.assertTrue(observed.wait(1))
            finally:proof=observation.stop()
        self.assertTrue(proof['observer_joined']);self.assertFalse(proof['complete_sample_window'])
        self.assertGreaterEqual(proof['read_errors'],1);self.assertEqual(proof['last_error_class'],'PermissionError')
        self.assertNotIn('private',str(proof));self.assertIsNone(proof['sampled_peak_uid_threads'])

    def test_unjoined_observer_never_reads_mutable_counters_or_claims_a_peak(self):
        entered=s.threading.Event();release=s.threading.Event()
        def stubborn(uid):
            entered.set();release.wait(2);return 123
        with mock.patch.object(s,'tasks_for_uid',side_effect=stubborn),mock.patch.object(s.UIDThreadObservation,'JOIN_SECONDS',0.001):
            observation=s.UIDThreadObservation();observation.start()
            try:
                self.assertTrue(entered.wait(1));proof=observation.stop()
                self.assertFalse(proof['observer_joined']);self.assertFalse(proof['complete_sample_window'])
                for key in ('successful_samples','read_errors','last_error_class','sampled_peak_uid_threads'):self.assertIsNone(proof[key])
            finally:
                release.set();observation._thread.join(timeout=1)
            self.assertFalse(observation._thread.is_alive())
            self.assertEqual(observation.stop(),proof)

    def test_observer_start_failure_cannot_prevent_the_fixed_ci_command(self):
        result=types.SimpleNamespace(returncode=17)
        with mock.patch.object(s.threading.Thread,'start',side_effect=RuntimeError('private startup detail')),mock.patch.object(s.subprocess,'run',return_value=result) as run,mock.patch.object(s,'save') as save,mock.patch('sys.stdout',new_callable=io.StringIO) as output:
            self.assertIs(s.observed_unit_wait(['/fixed/systemd-run'],123,self.root,'legacy'),result)
        self.assertEqual(run.call_count,1)
        proof=save.call_args.args[1]
        self.assertFalse(proof['complete_sample_window']);self.assertEqual(proof['observer_start_error_class'],'RuntimeError')
        self.assertNotIn('private startup detail',output.getvalue())

    def test_observation_preserves_exact_command_status_timeout_and_clean_environment(self):
        result=types.SimpleNamespace(returncode=23)
        with mock.patch.object(s,'tasks_for_uid',return_value=81),mock.patch.object(s.subprocess,'run',return_value=result) as run,mock.patch.object(s,'save') as save,mock.patch('sys.stdout',new_callable=io.StringIO):
            self.assertIs(s.observed_unit_wait(['/fixed/systemd-run','fixed-arg'],456,self.root,'postgres'),result)
        self.assertEqual(run.call_args.args[0],['/fixed/systemd-run','fixed-arg'])
        self.assertEqual(run.call_args.kwargs,{'stdin':s.subprocess.DEVNULL,'timeout':456,'env':{'PATH':s.SYSTEM_PATH,'LC_ALL':'C'}})
        self.assertEqual(save.call_args.args[0],self.root/'uid-thread-observation.json')
        self.assertTrue(save.call_args.args[1]['native_unit_closure_still_required'])

    def test_client_exception_is_not_swallowed_by_observation_or_proof_write_error(self):
        failure=s.subprocess.TimeoutExpired(['/private/argument'],1)
        with mock.patch.object(s,'tasks_for_uid',return_value=2),mock.patch.object(s.subprocess,'run',side_effect=failure),mock.patch.object(s,'save',side_effect=PermissionError('private write detail')),mock.patch('sys.stdout',new_callable=io.StringIO) as output:
            with self.assertRaises(s.subprocess.TimeoutExpired) as raised:s.observed_unit_wait(['/fixed/systemd-run'],1,self.root,'all-checks')
        self.assertIs(raised.exception,failure)
        self.assertIn('PermissionError',output.getvalue());self.assertNotIn('private write detail',output.getvalue())
        self.assertNotIn('/private/argument',output.getvalue())

    def test_observation_write_failure_does_not_change_the_original_ci_status(self):
        result=types.SimpleNamespace(returncode=0)
        with mock.patch.object(s,'tasks_for_uid',return_value=2),mock.patch.object(s.subprocess,'run',return_value=result),mock.patch.object(s,'save',side_effect=OSError('private disk detail')),mock.patch('sys.stdout',new_callable=io.StringIO) as output:
            self.assertIs(s.observed_unit_wait(['/fixed/systemd-run'],1,self.root,'all-checks'),result)
        self.assertIn('"private_observation_saved": false',output.getvalue())
        self.assertNotIn('private disk detail',output.getvalue())

    def test_observer_rejects_invalid_samples_without_claiming_a_zero_peak(self):
        observed=s.threading.Event()
        def invalid(uid):
            observed.set();return -1
        with mock.patch.object(s,'tasks_for_uid',side_effect=invalid):
            observation=s.UIDThreadObservation();observation.start()
            try:self.assertTrue(observed.wait(1))
            finally:proof=observation.stop()
        self.assertFalse(proof['complete_sample_window']);self.assertEqual(proof['successful_samples'],0)
        self.assertIsNone(proof['sampled_peak_uid_threads']);self.assertEqual(proof['last_error_class'],'RuntimeError')

    def test_observer_constructor_and_start_exceptions_preserve_result_or_client_exception(self):
        for phase in ('constructor','start'):
            for timeout in (False,True):
                with self.subTest(phase=phase,timeout=timeout),contextlib.ExitStack() as stack:
                    result=types.SimpleNamespace(returncode=19)
                    failure=s.subprocess.TimeoutExpired(['/private/argument'],1)
                    if phase=='constructor':stack.enter_context(mock.patch.object(s,'UIDThreadObservation',side_effect=RuntimeError('private observer failure')))
                    else:
                        stack.enter_context(mock.patch.object(s.UIDThreadObservation,'start',side_effect=RuntimeError('private observer failure')))
                        stack.enter_context(mock.patch.object(s.UIDThreadObservation,'stop',return_value=s.unavailable_observation('start','RuntimeError')))
                    run=stack.enter_context(mock.patch.object(s.subprocess,'run',side_effect=failure if timeout else None,return_value=result))
                    save=stack.enter_context(mock.patch.object(s,'save'))
                    output=stack.enter_context(mock.patch('sys.stdout',new_callable=io.StringIO))
                    if timeout:
                        with self.assertRaises(s.subprocess.TimeoutExpired) as raised:s.observed_unit_wait(['/fixed/systemd-run'],1,self.root,'legacy')
                        self.assertIs(raised.exception,failure)
                    else:self.assertIs(s.observed_unit_wait(['/fixed/systemd-run'],1,self.root,'legacy'),result)
                    self.assertEqual(run.call_count,1)
                    self.assertFalse(save.call_args.args[1]['complete_sample_window'])
                    self.assertNotIn('private observer failure',output.getvalue())

    def test_observer_stop_exception_preserves_result_or_client_exception(self):
        for timeout in (False,True):
            with self.subTest(timeout=timeout):
                result=types.SimpleNamespace(returncode=21);failure=s.subprocess.TimeoutExpired(['/private/argument'],1)
                with mock.patch.object(s.UIDThreadObservation,'start'),mock.patch.object(s.UIDThreadObservation,'stop',side_effect=RuntimeError('private stop failure')),mock.patch.object(s.subprocess,'run',side_effect=failure if timeout else None,return_value=result),mock.patch.object(s,'save') as save,mock.patch('sys.stdout',new_callable=io.StringIO) as output:
                    if timeout:
                        with self.assertRaises(s.subprocess.TimeoutExpired) as raised:s.observed_unit_wait(['/fixed/systemd-run'],1,self.root,'legacy')
                        self.assertIs(raised.exception,failure)
                    else:self.assertIs(s.observed_unit_wait(['/fixed/systemd-run'],1,self.root,'legacy'),result)
                self.assertEqual(save.call_args.args[1]['observation_error_phase'],'stop')
                self.assertEqual(save.call_args.args[1]['observation_error_class'],'RuntimeError')
                self.assertNotIn('private stop failure',output.getvalue())

    def test_observer_serialization_or_output_exception_preserves_result_or_client_exception(self):
        for phase in ('serialization','output'):
            for timeout in (False,True):
                with self.subTest(phase=phase,timeout=timeout),contextlib.ExitStack() as stack:
                    result=types.SimpleNamespace(returncode=22);failure=s.subprocess.TimeoutExpired(['/private/argument'],1)
                    stack.enter_context(mock.patch.object(s.UIDThreadObservation,'start'))
                    stack.enter_context(mock.patch.object(s.UIDThreadObservation,'stop',return_value=s.unavailable_observation('synthetic','RuntimeError')))
                    stack.enter_context(mock.patch.object(s.subprocess,'run',side_effect=failure if timeout else None,return_value=result))
                    stack.enter_context(mock.patch.object(s,'save'))
                    if phase=='serialization':stack.enter_context(mock.patch.object(s.json,'dumps',side_effect=TypeError('private serialization failure')))
                    else:stack.enter_context(mock.patch('builtins.print',side_effect=BrokenPipeError('private output failure')))
                    if timeout:
                        with self.assertRaises(s.subprocess.TimeoutExpired) as raised:s.observed_unit_wait(['/fixed/systemd-run'],1,self.root,'legacy')
                        self.assertIs(raised.exception,failure)
                    else:self.assertIs(s.observed_unit_wait(['/fixed/systemd-run'],1,self.root,'legacy'),result)

class HostedPathContractTests(unittest.TestCase):
    def prefix(self, **changes):
        class HostPath(pathlib.PurePosixPath):
            def is_dir(path):
                return str(path) in directories
        home=HostPath('/home/runner')
        directories={str(HostPath('/opt/hostedtoolcache')),str(home / 'work')}
        directories.difference_update(changes.pop('missing_directories', ()))
        values={'platform':'linux','euid':0,'uid':1001,'gid':1001,'home':home,
                'workspace':home / 'work' / 'reactor' / 'reactor',
                'runner_temp':home / 'work' / '_temp',
                'go_cache':home / '.cache' / 'go-build','gopath':home / 'go'}
        values.update(changes)
        tree=ast.parse(SOURCE.read_bytes())
        prepare=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='prepare')
        stop=next(i for i,node in enumerate(prepare.body) if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='env' for target in node.targets))
        prepare.body=prepare.body[:stop]+[ast.Return(value=ast.Tuple(elts=[ast.Name(id=name,ctx=ast.Load()) for name in ('home','workspace','temporary','cache','gopath')],ctx=ast.Load()))]
        module=ast.fix_missing_locations(ast.Module(body=[prepare],type_ignores=[]))
        namespace={'P':HostPath,'sys':types.SimpleNamespace(platform=values['platform']),
                   'os':types.SimpleNamespace(geteuid=lambda:values['euid'],environ={'SUDO_UID':str(values['uid']),'SUDO_GID':str(values['gid'])}),
                   'physical':lambda path:HostPath(path),
                   'pwd':types.SimpleNamespace(getpwuid=lambda uid:types.SimpleNamespace(pw_dir=str(values['home']))),
                   'UID':s.UID,'GID':s.GID,'need':s.need,'re':s.re}
        exec(compile(module,'<owned-hosted-path-prefix>','exec'),namespace)
        args=types.SimpleNamespace(**{name:values[name] for name in ('workspace','runner_temp','go_cache','gopath')},source_sha='a'*40,run_id='1',attempt='1',tool_path='/usr/bin:/bin')
        return namespace['prepare'](args)

    def test_passwd_home_derivation_preserves_closed_host_uid_and_path_refusals(self):
        home=pathlib.PurePosixPath('/home/runner')
        got=self.prefix()
        self.assertEqual(tuple(map(str,got)),tuple(map(str,(home,home/'work'/'reactor'/'reactor',home/'work'/'_temp',home/'.cache'/'go-build',home/'go'))))
        cases=[{'platform':'darwin'},{'euid':501},{'uid':0},{'uid':s.UID},{'gid':0},{'gid':s.GID},
               {'home':pathlib.PurePosixPath('/home/foreign')},
               {'missing_directories':[str(home/'work')]},
               {'missing_directories':['/opt/hostedtoolcache']},
               {'workspace':home/'work'/'foreign'/'reactor'},
               {'runner_temp':home/'work'/'foreign-temp'},
               {'go_cache':home/'foreign-cache'},{'gopath':home/'foreign-gopath'}]
        for values in cases:
            with self.subTest(values=values),self.assertRaises(RuntimeError):self.prefix(**values)

if __name__ == '__main__':unittest.main(verbosity=2)
