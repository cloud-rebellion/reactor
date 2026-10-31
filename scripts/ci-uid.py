#!/usr/bin/env python3
"""Fixed hosted-GitHub Reactor CI identity, not a production/runtime installer.

Only three tracked scripts can execute. Root prepares one fresh locked identity
and lends the existing workspace/default Go cache estate without copying it.
Tests receive no root capabilities, supplementary groups or actor credentials.
An ambiguous unit or ownership outcome is retained; never blindly stop/restore.
"""
import argparse
import ctypes
import datetime
import errno
import fcntl
import grp
import hashlib
import json
import os
import pathlib
import pwd
import re
import stat
import subprocess
import sys
import time

P = pathlib.Path
UID = GID = 62001
ACCOUNT = 'reactorci'
MODES = {'all-checks': ('scripts/ci.sh', 3300), 'legacy': ('scripts/ci-legacy.sh', 3300), 'postgres': ('scripts/ci-postgres.sh', 1020)}
FIXTURE = 'postgres://reactor_test:reactor_test@127.0.0.1:5432/reactor_ci_test?sslmode=disable'
MAX_ENTRIES = 500000
MAX_MANIFEST_BYTES = 134217728
SYSTEM_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
ROOT_TOOLS = {'useradd': '/usr/sbin/useradd', 'groupadd': '/usr/sbin/groupadd', 'userdel': '/usr/sbin/userdel', 'groupdel': '/usr/sbin/groupdel', 'systemd-run': '/usr/bin/systemd-run', 'systemctl': '/usr/bin/systemctl', 'setpriv': '/usr/bin/setpriv'}
ALIAS_ROOT = P('/run/reactor-ci')

def need(value, code):
    if not value:
        raise RuntimeError(code)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()

def file_identity(s):
    return [s.st_dev, s.st_ino, stat.S_IFMT(s.st_mode), stat.S_IMODE(s.st_mode), s.st_uid, s.st_gid, s.st_nlink]

def stable_identity(s):
    # A successful ordinary read may update atime. Size/mtime/ctime and the
    # complete inode/mode/ownership identity still detect substantive drift.
    return file_identity(s) + [s.st_size, s.st_mtime_ns, s.st_ctime_ns]

def physical(path):
    p = P(path)
    need(p.is_absolute() and str(p) == os.path.normpath(str(p)), 'absolute_clean_path_required')
    cur = P('/')
    for part in p.parts[1:]:
        cur /= part
        need(not stat.S_ISLNK(cur.lstat().st_mode), 'physical_path_component_required')
    return p

def safe_read(path, limit=1048576):
    p = P(path); before = p.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit, 'bounded_plain_file_required')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        need(stable_identity(os.fstat(f.fileno())) == stable_identity(before), 'opened_file_identity_changed')
        raw = f.read(limit + 1)
        need(stable_identity(os.fstat(f.fileno())) == stable_identity(before), 'file_changed_while_reading')
    need(len(raw) <= limit and stable_identity(p.lstat()) == stable_identity(before), 'file_path_changed_while_reading')
    return raw

def save(path, value, mode=0o600):
    raw = encoded(value)
    need(len(raw) <= MAX_MANIFEST_BYTES, 'private_manifest_size_bound')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        os.fchmod(f.fileno(), mode); f.write(raw); f.flush(); os.fsync(f.fileno())
    fd = os.open(P(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)

def command(argv, timeout=15, user=None, env=None, accepted=(0,)):
    args = list(argv)
    if user:
        args = [ROOT_TOOLS['setpriv'], '--reuid=' + str(user[0]), '--regid=' + str(user[1]), '--clear-groups', '--no-new-privs', '--'] + args
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, env=env or {'PATH': SYSTEM_PATH, 'LC_ALL': 'C'})
    need(len(result.stdout) <= 1048576 and len(result.stderr) <= 65536, 'fixed_command_output_bound')
    # Only fixed tool names and native integer status may cross this boundary;
    # command arguments, output and inherited data never become diagnostics.
    label = next((name for name, path in ROOT_TOOLS.items() if args[0] == path), 'fixed')
    need(result.returncode in accepted, 'fixed_command_failed:' + label + ':exit=' + str(result.returncode))
    return result.stdout

def tasks_for_uid(uid):
    total = 0
    for p in P('/proc').iterdir():
        if not p.name.isdigit(): continue
        try: raw = (p / 'status').read_text()
        except (FileNotFoundError, ProcessLookupError): continue
        fields = {line.split(':', 1)[0]: line.split(':', 1)[1].split() for line in raw.splitlines() if ':' in line}
        need('Uid' in fields and 'Threads' in fields, 'process_identity_unreadable')
        if int(fields['Uid'][0]) == uid: total += int(fields['Threads'][0])
    return total

def account_absent():
    for lookup, key in ((pwd.getpwnam, ACCOUNT), (pwd.getpwuid, UID), (grp.getgrnam, ACCOUNT), (grp.getgrgid, GID)):
        try: lookup(key)
        except KeyError: continue
        raise RuntimeError('fixed_ci_identity_already_exists')
    need(tasks_for_uid(UID) == 0, 'fresh_ci_uid_has_processes')

def optional_identity(lookup, key):
    try: return lookup(key)
    except KeyError: return None

def remove_owned_account(home):
    # The caller has restored ownership and proved exact unit closure. Check
    # both lookup directions so replacement names/numeric IDs are never removed.
    user, by_uid = pwd.getpwnam(ACCOUNT), pwd.getpwuid(UID)
    group, by_gid = grp.getgrnam(ACCOUNT), grp.getgrgid(GID)
    need(user == by_uid and user.pw_name == ACCOUNT and user.pw_uid == UID and user.pw_gid == GID and user.pw_shell == '/usr/sbin/nologin' and user.pw_dir == str(home), 'account_changed_do_not_remove')
    need(group == by_gid and group.gr_name == ACCOUNT and group.gr_gid == GID and not group.gr_mem, 'group_changed_do_not_remove')
    need(not any(other.pw_gid == GID and other.pw_name != ACCOUNT for other in pwd.getpwall()), 'foreign_primary_group_user_do_not_remove')
    need(tasks_for_uid(UID) == 0, 'ci_uid_still_has_tasks')
    command([ROOT_TOOLS['userdel'], ACCOUNT])
    need(optional_identity(pwd.getpwnam, ACCOUNT) is None and optional_identity(pwd.getpwuid, UID) is None, 'account_remains_after_owned_userdel')
    need(tasks_for_uid(UID) == 0, 'ci_uid_still_has_tasks')
    named = optional_identity(grp.getgrnam, ACCOUNT)
    numbered = optional_identity(grp.getgrgid, GID)
    need(not any(other.pw_gid == GID for other in pwd.getpwall()), 'foreign_primary_group_user_do_not_remove')
    # shadow userdel may remove an empty same-name private group itself. This
    # is accepted only after our successful deletion and exact two-key absence.
    if named is None and numbered is None:
        return 'removed_by_owned_userdel'
    need(named == group and numbered == group, 'group_changed_after_owned_userdel_do_not_remove')
    command([ROOT_TOOLS['groupdel'], ACCOUNT])
    need(optional_identity(grp.getgrnam, ACCOUNT) is None and optional_identity(grp.getgrgid, GID) is None, 'group_remains_after_owned_groupdel')
    return 'removed_by_owned_groupdel'

def local_git_config(raw):
    for row in raw.split(b'\0'):
        if not row: continue
        key, _, value = row.partition(b'\n'); key = key.decode('utf-8').lower()
        need(not (key.startswith(('credential.', 'include.', 'includeif.', 'http.', 'https.', 'url.')) or 'extraheader' in key or key in ('core.hookspath', 'core.sshcommand', 'core.askpass', 'core.gitproxy')), 'local_git_auth_or_include_configuration_refused')
        need(not (key.startswith(('filter.', 'diff.')) or key in ('core.fsmonitor','extensions.worktreeconfig')), 'local_git_source_filter_refused')
        if key.startswith('remote.') and key.endswith('.url'):
            need(key == 'remote.origin.url' and value.decode() in ('https://github.com/cloud-rebellion/reactor', 'https://github.com/cloud-rebellion/reactor.git'), 'exact_public_origin_required')

def original_env(home, path):
    return {'HOME': str(home), 'PATH': path, 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_NO_REPLACE_OBJECTS': '1', 'GOTOOLCHAIN': 'local'}

def snapshot(root, original=None):
    root = physical(root); root_state = root.lstat()
    need(stat.S_ISDIR(root_state.st_mode), 'loan_root_directory_required')
    result = []
    def visit(fd, rel):
        s = os.fstat(fd)
        need(s.st_dev == root_state.st_dev and stat.S_ISDIR(s.st_mode), 'nested_mount_or_directory_change_refused')
        no_file_capabilities(fd)
        add(rel, s)
        for name in sorted(os.listdir(fd)):
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            need(not stat.S_ISLNK(st.st_mode), 'symlink_in_loan_tree_refused')
            need(stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode), 'special_file_in_loan_tree_refused')
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if stat.S_ISDIR(st.st_mode) else 0), dir_fd=fd)
            try:
                need(stable_identity(os.fstat(child)) == stable_identity(st), 'loan_entry_identity_changed')
                path = rel + '/' + name if rel else name
                if stat.S_ISDIR(st.st_mode): visit(child, path)
                else:
                    no_file_capabilities(child)
                    add(path, st)
            finally: os.close(child)
    def add(rel, s):
        need(len(result) < MAX_ENTRIES and len(rel) <= 4096, 'loan_entry_count_or_path_bound')
        need(not s.st_mode & 0o6000 and (stat.S_ISDIR(s.st_mode) or s.st_nlink == 1), 'setid_or_hardlinked_entry_refused')
        if original is not None: need((s.st_uid, s.st_gid) == original, 'existing_entry_not_original_runner_owned')
        result.append({'path': rel, 'identity': file_identity(s), 'stable':stable_identity(s)})
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: visit(fd, '')
    finally: os.close(fd)
    return {'root': str(root), 'identity': file_identity(root_state), 'entries': result}

def no_file_capabilities(fd):
    try: value = os.getxattr(fd, 'security.capability')
    except OSError as error:
        need(error.errno in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP), 'file_capability_metadata_unreadable')
    else: need(not value, 'file_capabilities_in_ownership_loan_refused')

def chown_entries(view, uid, gid, allowed):
    root = physical(view['root']); first = root.lstat()
    need(file_identity(first)[:3] == view['identity'][:3], 'loan_root_object_changed')
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for entry in view['entries']:
            parts = entry['path'].split('/') if entry['path'] else []
            parent = os.dup(root_fd)
            try:
                for part in parts[:-1]:
                    new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent); os.close(parent); parent = new
                fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent) if parts else os.dup(parent)
                try:
                    now = os.fstat(fd)
                    need(stable_identity(now) == entry['stable'] and (now.st_uid, now.st_gid) in allowed, 'ownership_cas_or_original_identity_changed')
                    os.fchown(fd, uid, gid)
                    after = os.fstat(fd)
                    need(file_identity(after)[:4] == entry['identity'][:4] and (after.st_uid, after.st_gid) == (uid, gid), 'ownership_loan_or_mode_verification_failed')
                finally: os.close(fd)
            finally: os.close(parent)
    finally: os.close(root_fd)

def verify_loan(before, after):
    need(after['identity'][:3] == before['identity'][:3], 'loan_root_object_changed_after_transfer')
    def content_metadata(view):
        return {e['path']:e['identity'][:4] + e['identity'][6:] + e['stable'][7:9] for e in view['entries']}
    need(content_metadata(before) == content_metadata(after), 'loan_tree_changed_before_unit_launch')
    need(all(e['identity'][4:6] == [UID,GID] for e in after['entries']), 'loan_tree_not_exclusively_ci_owned')

def unit_state(name):
    raw = command([ROOT_TOOLS['systemctl'], 'show', '--no-pager', '--property=Id,LoadState,ActiveState,SubState,User,Group,Description,InvocationID,MainPID', name], accepted=(0, 4))
    return dict(row.split('=', 1) for row in raw.decode().splitlines() if '=' in row)

def unit_closed(name, description, wait_exit):
    state = unit_state(name)
    if state.get('LoadState') == 'not-found':
        need(wait_exit == 0, 'unit_absence_without_successful_wait_is_ambiguous')
    else:
        need(state.get('Id') == name and state.get('Description') == description and state.get('User') in (str(UID), ACCOUNT) and state.get('Group') in (str(GID), ACCOUNT), 'unit_belongs_to_another_operation')
        need(state.get('ActiveState') in ('inactive', 'failed') and state.get('MainPID') == '0', 'unit_not_proved_closed')
        need(re.fullmatch('[a-f0-9]{32}', state.get('InvocationID','')) is not None, 'positive_native_unit_lifecycle_required')
    jobs = command([ROOT_TOOLS['systemctl'], 'list-jobs', '--no-legend', '--no-pager']).decode().splitlines()
    need(len(jobs) <= 256 and not any(name in line.split() for line in jobs), 'unit_has_pending_native_job')
    need(tasks_for_uid(UID) == 0, 'ci_uid_still_has_tasks')
    return {'closed': True, 'load_state': state.get('LoadState'), 'active_state': state.get('ActiveState'), 'zero_uid_tasks': True}

def prepare(args):
    need(sys.platform.startswith('linux') and os.geteuid() == 0, 'ephemeral_linux_root_controller_required')
    need(P('/opt/hostedtoolcache').is_dir() and P('/home/runner/work').is_dir(), 'hosted_github_vm_required')
    runner = (int(os.environ.get('SUDO_UID', '-1')), int(os.environ.get('SUDO_GID', '-1')))
    need(runner[0] > 0 and runner[0] != UID and runner[1] > 0 and runner[1] != GID, 'original_runner_identity_required')
    home = physical(pwd.getpwuid(runner[0]).pw_dir)
    need(str(home) == '/home/runner', 'hosted_runner_home_required')
    workspace, temporary, cache, gopath = map(physical, (args.workspace, args.runner_temp, args.go_cache, args.gopath))
    need(str(workspace) == '/home/runner/work/reactor/reactor' and str(temporary) == '/home/runner/work/_temp', 'fixed_hosted_reactor_workspace_required')
    need(str(cache) == str(home / '.cache/go-build') and str(gopath) == str(home / 'go'), 'default_cache_estate_scope_refused')
    need(re.fullmatch('[a-f0-9]{40}', args.source_sha) and re.fullmatch('[0-9]{1,20}', args.run_id) and re.fullmatch('[0-9]{1,3}', args.attempt), 'source_or_run_identity_invalid')
    need('' not in args.tool_path.split(':') and all(P(p).is_absolute() for p in args.tool_path.split(':')), 'absolute_tool_path_required')
    env = original_env(home, args.tool_path)
    go = physical(args.go)
    need(str(go).startswith('/opt/hostedtoolcache/go/1.26.10/') and go.name == 'go', 'pinned_hosted_go_binary_required')
    got = command([str(go), 'env', '-json', 'GOCACHE', 'GOPATH', 'GOROOT'], user=runner, env=env)
    got = json.loads(got)
    need(physical(got['GOCACHE']) == cache and physical(got['GOPATH']) == gopath and ':' not in got['GOPATH'], 'actual_default_cache_estate_mismatch')
    need(physical(got['GOROOT']) == go.parent.parent, 'original_go_root_mismatch')
    go_version = command([str(go), 'version'], user=runner, env=env).decode()
    need(go_version.startswith('go version go1.26.10 '), 'go_patch_version_mismatch')
    git = ['/usr/bin/git', '-C', str(workspace)]
    need(command(git + ['rev-parse', 'HEAD'], user=runner, env=env).decode().strip() == args.source_sha, 'workspace_exact_source_mismatch')
    need(command(git + ['rev-parse', '--show-toplevel'], user=runner, env=env).decode().strip() == str(workspace), 'ordinary_workspace_root_required')
    need(stat.S_ISDIR((workspace / '.git').lstat().st_mode), 'ordinary_git_directory_required')
    if args.mode == 'all-checks': need(not (workspace / '.git/shallow').exists(), 'full_history_required_for_original_secret_scan')
    local_git_config(command(git + ['config', '--local', '--null', '--list'], user=runner, env=env))
    need(not (workspace / '.git/objects/info/alternates').exists(), 'external_git_object_store_refused')
    command(git + ['diff', '--no-ext-diff', '--no-textconv', '--quiet', 'HEAD', '--'], user=runner, env=env)
    script = workspace / MODES[args.mode][0]
    need(script.is_file() and not script.is_symlink(), 'fixed_tracked_ci_script_required')
    own = physical(P(__file__).absolute())
    need(own == workspace / 'scripts/ci-uid.py', 'tracked_controller_location_required')
    for rel in ('scripts/ci-uid.py', MODES[args.mode][0]):
        raw = command(git + ['cat-file', 'blob', args.source_sha + ':' + rel], user=runner, env=env)
        need(raw == safe_read(workspace / rel), 'tracked_ci_source_bytes_changed')
    original_bun = command(['/bin/sh', '-c', 'command -v bun || true'], user=runner, env=env).decode().strip()
    need(bool(original_bun) == bool(args.bun), 'original_bun_presence_must_be_preserved')
    bun = None
    if args.bun:
        bun = P(args.bun).resolve(strict=True)
        need(P(original_bun).resolve(strict=True) == bun and stat.S_ISREG(bun.stat().st_mode), 'original_bun_binary_mismatch')
        need(re.fullmatch(r'/[A-Za-z0-9_./+-]+',str(bun)) is not None, 'unsupported_bun_binding_path')
    views = [snapshot(root, runner) for root in (workspace, cache, gopath)]
    need(sum(len(v['entries']) for v in views) <= MAX_ENTRIES, 'combined_loan_entry_bound')
    account_absent()
    unit = 'reactor-ci-' + args.mode + '-' + args.run_id + '-' + args.attempt + '.service'
    need(unit_state(unit).get('LoadState') == 'not-found', 'fixed_unit_name_already_exists')
    return {'runner': runner, 'home': str(home), 'views': views, 'workspace': str(workspace), 'cache': str(cache), 'gopath': str(gopath), 'go': str(go), 'goroot': got['GOROOT'], 'go_version': go_version, 'bun': str(bun) if bun else None, 'bun_version': command([str(bun), '--version'], user=runner, env=env).decode() if bun else None, 'bun_identity': file_identity(bun.stat()) if bun else None, 'source_sha': args.source_sha, 'mode': args.mode, 'unit': unit, 'run_id': args.run_id, 'attempt': args.attempt}

def inside(config_path):
    need(os.getuid() == os.geteuid() == UID and os.getgid() == GID and set(os.getgroups()).issubset({GID}), 'fresh_unprivileged_identity_required')
    raw = safe_read(config_path, 65536); state = P(config_path).lstat()
    need((state.st_uid, state.st_gid, stat.S_IMODE(state.st_mode)) == (0, 0, 0o644), 'root_owned_inside_configuration_required')
    cfg = json.loads(raw)
    status = dict(line.split(':', 1) for line in P('/proc/self/status').read_text().splitlines() if ':' in line)
    need(all(int(status[k].strip(), 16) == 0 for k in ('CapEff', 'CapPrm', 'CapAmb')) and status.get('NoNewPrivs', '').strip() == '1', 'capability_or_setuid_escalation_not_disabled')
    initial_threads = tasks_for_uid(UID)
    need(initial_threads <= 8, 'fresh_uid_initial_thread_headroom_missing')
    for item in cfg['aliases']:
        s = P(item['alias']).lstat()
        need(file_identity(s)[:3] == item['identity'][:3] and (s.st_uid, s.st_gid) == (UID, GID), 'alias_does_not_reference_exact_existing_object')
    need(command([cfg['go'], 'version']).decode() == cfg['go_version'], 'inside_go_version_changed')
    if cfg['bun']:
        need(file_identity(P(cfg['bun']).lstat())[:3] == cfg['bun_identity'][:3], 'inside_bun_not_exact_original_executable')
        need(command([cfg['bun'], '--version']).decode() == cfg['bun_version'], 'inside_bun_availability_changed')
    env = dict(os.environ)
    need('SUDO_UID' not in env and 'GITHUB_TOKEN' not in env and 'ACTIONS_RUNTIME_TOKEN' not in env and 'SSH_AUTH_SOCK' not in env, 'actor_authentication_inherited')
    need(not P('/home/runner').exists(), 'host_runner_home_not_hidden')
    os.chdir(cfg['workspace'])
    need(command(['/usr/bin/git', 'rev-parse', 'HEAD'], env=env).decode().strip() == cfg['source_sha'], 'inside_source_changed')
    local_git_config(command(['/usr/bin/git', 'config', '--local', '--null', '--list'], env=env))
    command(['/usr/bin/git', 'diff', '--no-ext-diff', '--no-textconv', '--quiet', 'HEAD', '--'], env=env)
    print(json.dumps({'result': 'isolated_ci_preflight_passed', 'mode': cfg['mode'], 'uid': UID, 'initial_uid_threads': initial_threads, 'caps_zero': True, 'source_sha': cfg['source_sha'], 'same_existing_cache_objects': True, 'bun_present': bool(cfg['bun'])}), flush=True)
    return subprocess.run(['/bin/bash', MODES[cfg['mode']][0]], stdin=subprocess.DEVNULL, env=env).returncode

def execute(prepared):
    cfg = prepared; marker = 'reactor-ci-' + cfg['mode'] + '-' + cfg['run_id'] + '-' + cfg['attempt']
    state = P('/var/tmp') / marker
    need(not state.exists() and not state.is_symlink(), 'operation_namespace_exists_no_blind_retry')
    need(not ALIAS_ROOT.exists() and not ALIAS_ROOT.is_symlink(), 'fixed_alias_namespace_exists_no_blind_reuse')
    state.mkdir(mode=0o711)
    os.chmod(state, 0o711)
    control = state / 'control'; control.mkdir(mode=0o700)
    ALIAS_ROOT.mkdir(mode=0o711)
    save(control / 'intent.json', {'schema': 'reactor-ci-uid-loan-v1', 'unit': cfg['unit'], 'uid': UID, 'gid': GID, 'source_sha': cfg['source_sha'], 'mode': cfg['mode'], 'runner': cfg['runner']})
    save(control / 'original-ownership.json', cfg['views'])
    description = marker + ':' + digest(safe_read(control / 'intent.json'))
    # Account and ownership phases are one-shot. A failure before a known unit
    # closure is retained with the private original manifest, never guessed away.
    command([ROOT_TOOLS['groupadd'], '--gid', str(GID), ACCOUNT])
    command([ROOT_TOOLS['useradd'], '--uid', str(UID), '--gid', str(GID), '--no-create-home', '--home-dir', str(state / 'home'), '--shell', '/usr/sbin/nologin', '--password', '!', ACCOUNT])
    need(pwd.getpwnam(ACCOUNT).pw_uid == UID and grp.getgrnam(ACCOUNT).gr_gid == GID and tasks_for_uid(UID) == 0, 'new_account_identity_not_exclusive')
    for name in ('home', 'tmp'):
        p = state / name; p.mkdir(mode=0o700); os.chown(p, UID, GID)
    aliases = []
    for name, view in zip(('workspace', 'gocache', 'gopath'), cfg['views']):
        p = ALIAS_ROOT / name; p.mkdir(mode=0o755)
        aliases.append({'physical': view['root'], 'alias': str(p), 'identity': view['identity']})
    for view in cfg['views']: chown_entries(view, UID, GID, {tuple(cfg['runner'])})
    for view in cfg['views']: verify_loan(view, snapshot(view['root'], (UID,GID)))
    save(control / 'loan-complete.json', {'roots': len(aliases), 'entries': sum(len(v['entries']) for v in cfg['views'])})
    tools = ALIAS_ROOT / 'tools'; tools.mkdir(mode=0o755)
    bun_alias = None
    if cfg['bun']:
        bun_alias = str(tools / 'bun'); P(bun_alias).touch(mode=0o444)
    inside_cfg = {'mode': cfg['mode'], 'workspace': aliases[0]['alias'], 'aliases': aliases, 'source_sha': cfg['source_sha'], 'go': cfg['go'], 'go_version': cfg['go_version'], 'bun': bun_alias, 'bun_identity': cfg['bun_identity'], 'bun_version': cfg['bun_version']}
    save(state / 'inside.json', inside_cfg, mode=0o644)
    maximum = MODES[cfg['mode']][1]
    args = [ROOT_TOOLS['systemd-run'], '--quiet', '--wait', '--pipe', '--unit=' + cfg['unit'], '--property=Description=' + description, '--property=User=' + str(UID), '--property=Group=' + str(GID), '--property=NoNewPrivileges=yes', '--property=CapabilityBoundingSet=', '--property=AmbientCapabilities=', '--property=RestrictSUIDSGID=yes', '--property=ProtectHome=tmpfs', '--property=ProtectControlGroups=yes', '--property=Restart=no', '--property=KillMode=control-group', '--property=TimeoutStopSec=15s', '--property=RuntimeMaxSec=' + str(maximum) + 's', '--property=MemoryMax=4G', '--property=TasksMax=512', '--property=WorkingDirectory=' + aliases[0]['alias'], '--property=BindPaths=' + ' '.join(item['physical'] + ':' + item['alias'] for item in aliases)]
    if cfg['bun']: args += ['--property=BindReadOnlyPaths=' + cfg['bun'] + ':' + bun_alias]
    path = str(P(cfg['go']).parent) + ':' + aliases[2]['alias'] + '/bin:' + str(tools) + ':' + SYSTEM_PATH
    env = {'HOME': str(state / 'home'), 'TMPDIR': str(state / 'tmp'), 'PATH': path, 'LC_ALL': 'C', 'USER':ACCOUNT, 'LOGNAME':ACCOUNT, 'CI': 'true', 'GITHUB_ACTIONS': 'true', 'GOCACHE': aliases[1]['alias'], 'GOPATH': aliases[2]['alias'], 'GOROOT': cfg['goroot'], 'GOTOOLCHAIN': 'local', 'GOMAXPROCS': '2', 'GOFLAGS': '-p=1', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_NO_REPLACE_OBJECTS': '1'}
    if cfg['mode'] == 'postgres': env['REACTOR_TEST_POSTGRES_URL'] = FIXTURE
    args += ['/usr/bin/env', '-i'] + [k + '=' + v for k, v in env.items()] + ['/usr/bin/python3', aliases[0]['alias'] + '/scripts/ci-uid.py', '--inside', str(state / 'inside.json')]
    save(control / 'unit-launch-intent.json', {'unit': cfg['unit'], 'description': description, 'environment_names_only': sorted(env), 'same_existing_object_aliases': aliases})
    result = subprocess.run(args, stdin=subprocess.DEVNULL, timeout=maximum + 60, env={'PATH': SYSTEM_PATH, 'LC_ALL': 'C'})
    save(control / 'unit-client-result.json', {'exit_code': result.returncode})
    proof = unit_closed(cfg['unit'], description, result.returncode)
    save(control / 'unit-closed.json', proof)
    current = [snapshot(v['root']) for v in cfg['views']]
    for before, after in zip(cfg['views'], current):
        need(after['identity'][:3] == before['identity'][:3], 'physical_root_changed_before_restoration')
        need(all(tuple(e['identity'][4:6]) in {(UID, GID), tuple(cfg['runner'])} for e in after['entries']), 'foreign_cache_or_workspace_owner_do_not_restore')
    # Zero UID tasks is checked again immediately before any ownership change.
    unit_closed(cfg['unit'], description, result.returncode)
    save(control / 'restore-intent.json', {'root_identities': [v['identity'][:3] for v in current]})
    for view in current: chown_entries(view, cfg['runner'][0], cfg['runner'][1], {(UID, GID), tuple(cfg['runner'])})
    restored = [snapshot(v['root'], tuple(cfg['runner'])) for v in cfg['views']]
    save(control / 'restored.json', {'original_roots': len(restored), 'existing_and_new_entry_count': sum(len(v['entries']) for v in restored), 'source_or_cache_deleted_by_controller': False, 'modes_changed_by_controller': False})
    unit_closed(cfg['unit'], description, result.returncode)
    group_removal = remove_owned_account(state / 'home')
    account_absent()
    save(control / 'finished.json', {'unit_exit_code': result.returncode, 'ownership_restored': True, 'fresh_account_removed': True, 'group_removal': group_removal})
    print(json.dumps({'result': 'isolated_ci_finished', 'mode': cfg['mode'], 'exit_code': result.returncode, 'ownership_restored': True, 'account_removed': True, 'private_receipt': str(control), 'runtime_nproc_policy_changed': False}), flush=True)
    return result.returncode

def main():
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument('--inside', type=P)
    a.add_argument('--mode', choices=tuple(MODES)); a.add_argument('--workspace'); a.add_argument('--source-sha'); a.add_argument('--runner-temp'); a.add_argument('--go-cache'); a.add_argument('--gopath'); a.add_argument('--go'); a.add_argument('--tool-path'); a.add_argument('--run-id'); a.add_argument('--attempt')
    b = a.add_mutually_exclusive_group(); b.add_argument('--bun'); b.add_argument('--bun-absent', action='store_true')
    a.add_argument('--execute', action='store_true'); args = a.parse_args()
    if args.inside:
        need(not args.execute and args.mode is None, 'inside_fixed_mode_only')
        return inside(args.inside)
    need(all(getattr(args, k) for k in ('mode', 'workspace', 'source_sha', 'runner_temp', 'go_cache', 'gopath', 'go', 'tool_path', 'run_id', 'attempt')) and (args.bun or args.bun_absent), 'explicit_fixed_ci_inputs_required')
    prepared = prepare(args)
    if not args.execute:
        print(json.dumps({'result': 'read_only_ci_uid_preflight', 'mode': args.mode, 'source_sha': args.source_sha, 'existing_entry_count': sum(len(v['entries']) for v in prepared['views']), 'effects': False}))
        return 0
    return execute(prepared)

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({'result': 'ci_identity_refused_or_exact_settlement_required', 'reason': str(error) if isinstance(error, RuntimeError) else type(error).__name__, 'blind_retry_stop_or_owner_restore_permitted': False}), file=sys.stderr)
        sys.exit(75)
