"""Unprivileged synthetic controller qualification; no accounts/units/real chown.

The actual Linux UID/systemd/cache loan remains the separate hosted-CI proof.
Fixtures use their own bounded scratch. No production path is created or read.
"""
import argparse
import copy
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

if __name__ == '__main__':unittest.main(verbosity=2)
