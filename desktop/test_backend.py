"""Regression checks for local configuration, cancellation, and IPA verification."""
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import signal
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('backend', HERE / 'backend.py')
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)


class LocalWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_config_is_private_and_roundtrips_without_shell_evaluation(self):
        backend.save_config(self.root, 'ABCDEFGHIJ', 'dev.example.unfairplayed', '00008150-0123456789012345')
        p = self.root / '.unfairplayed.env'
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        self.assertEqual(backend.read_config(self.root)['TEAM_ID'], 'ABCDEFGHIJ')
        with p.open('a') as f:
            f.write('UNRECOGNIZED=$(touch /tmp/never-run)\n')
        self.assertNotIn('UNRECOGNIZED', backend.read_config(self.root))

    def test_invalid_config_does_not_overwrite_existing_config(self):
        backend.save_config(self.root, 'ABCDEFGHIJ', 'dev.example.unfairplayed', '')
        before = (self.root / '.unfairplayed.env').read_bytes()
        for team, bundle in [('ABCDEFGHIJ\nX=1', 'dev.example.app'), ('ABCDEFGHIJ', 'dev.example.app\nX=1')]:
            with self.assertRaises(ValueError):
                backend.save_config(self.root, team, bundle, '')
        self.assertEqual(before, (self.root / '.unfairplayed.env').read_bytes())

    def test_switching_to_helper_id_does_not_require_an_unused_custom_draft(self):
        backend.save_config(self.root, 'ABCDEFGHIJ', 'dev.example.fixedhelper', '',
                            {'DEBUG_BUNDLE_MODE': 'helper', 'DEBUG_CUSTOM_BUNDLE_ID': 'unfinished draft'})
        self.assertEqual(backend.read_config(self.root)['DEBUG_BUNDLE_MODE'], 'helper')
        with self.assertRaises(ValueError):
            backend.save_config(self.root, 'ABCDEFGHIJ', 'dev.example.fixedhelper', '',
                                {'DEBUG_BUNDLE_MODE': 'custom', 'DEBUG_CUSTOM_BUNDLE_ID': 'unfinished draft'})

    def test_helper_id_reuse_resolves_saved_helper_not_caller_bundle(self):
        (self.root / 'fpdecrypt.sh').touch()
        backend.save_config(self.root, 'ABCDEFGHIJ', 'dev.example.fixedhelper', '')
        args = ['backend.py', '--root', str(self.root), 'debug-install', '--ipa', str(self.root / 'input.ipa'),
                '--signer', 'xcode:ABCDEFGHIJ', '--mode', 'helper', '--bundle', 'dev.should.beignored']
        with patch.object(sys, 'argv', args), patch.object(backend, 'require_device', return_value='phone'), patch.object(backend, 'run_job', return_value=0) as job:
            self.assertEqual(backend.main(), 0)
        command = job.call_args.args[0]
        self.assertEqual(command[command.index('--bundle') + 1], 'dev.example.fixedhelper')

    def test_team_dropdown_uses_xcode_team_ids_and_names(self):
        prefs = {'IDEProvisioningTeamByIdentifier': {'account-id': [
            {'teamID': 'ABCDEFGHIJ', 'teamName': 'Example (Personal Team)'},
            {'teamID': 'INVALID', 'teamName': 'Must not appear'}]}}
        response = subprocess.CompletedProcess([], 0, plistlib.dumps(prefs).decode(), '')
        with patch.object(backend, 'capture', return_value=response), patch.object(backend.Path, 'home', return_value=self.root):
            teams = backend.development_teams(self.root)
        self.assertEqual(teams, [{'id': 'ABCDEFGHIJ', 'name': 'Example (Personal Team)', 'source': 'Xcode'}])

    def test_watch_and_simulators_are_excluded_from_devices(self):
        def device(kind, reality, modern=True):
            hardware = {'deviceType': kind, 'reality': reality, 'udid': kind}
            if modern:
                return {'properties': {'hardware': hardware, 'connection': {'state': 'connected'}, 'state': {'name': kind}}}
            return {'hardwareProperties': hardware, 'connectionProperties': {'tunnelState': 'connected'}, 'deviceProperties': {'name': kind}}
        fixture = {'result': {'devices': [device('appleWatch', 'physical'), device('iPhone', 'simulated'),
                                          device('iPhone', 'physical'), device('iPad', 'physical', False)]}}
        def fake_capture(args, timeout=20):
            Path(args[-1]).write_text(json.dumps(fixture))
            return subprocess.CompletedProcess(args, 0, '', '')
        with patch.object(backend, 'capture', side_effect=fake_capture), patch.object(backend.device_connection, 'wired_devices', return_value={'iphone'}):
            result = backend.devices()
            self.assertEqual([d['id'] for d in result], ['iPhone', 'iPad'])
            self.assertTrue(result[0]['wired'])
            self.assertFalse(result[1]['wired'])

    def test_concurrent_jobs_are_rejected(self):
        with backend.job_lock(self.root):
            with self.assertRaises(ValueError):
                with backend.job_lock(self.root):
                    pass
        with backend.job_lock(self.root):
            pass

    def test_stop_terminates_child_process_group(self):
        pidfile = self.root / 'grandchild.pid'
        child_code = ('import subprocess,sys,time,pathlib; '
                      'p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(120)"]); '
                      f'pathlib.Path({str(pidfile)!r}).write_text(str(p.pid)); time.sleep(120)')
        code = ('import sys; from pathlib import Path; '
                f'sys.path.insert(0,{str(HERE)!r}); import backend; '
                f'sys.exit(backend.run_job([sys.executable,"-c",{child_code!r}],Path({str(self.root)!r})))')
        job = subprocess.Popen([sys.executable, '-c', code])
        try:
            for _ in range(100):
                if pidfile.exists():
                    break
                time.sleep(.03)
            self.assertTrue(pidfile.exists())
            grandchild = int(pidfile.read_text())
            job.terminate()
            self.assertEqual(job.wait(timeout=8), 130)
            state = subprocess.run(['/bin/ps', '-o', 'stat=', '-p', str(grandchild)], capture_output=True, text=True).stdout.strip()
            self.assertTrue(not state or state.startswith('Z'), state)
        finally:
            if job.poll() is None:
                job.kill(); job.wait()
            if pidfile.exists():
                try:
                    os.kill(int(pidfile.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_download_failure_never_reports_success_or_overwrites_inputs(self):
        (self.root / 'fpdecrypt.sh').touch()
        tool = self.root / 'ipatool'
        tool.write_text('#!/bin/sh\necho "authentication failed" >&2\nexit 7\n')
        tool.chmod(0o700)
        original = self.root / 'original.ipa'
        original.write_bytes(b'keep-original')
        env = dict(os.environ, PATH=str(self.root) + ':' + os.environ['PATH'], HOME=str(self.root / 'test home'))
        result = subprocess.run([sys.executable, str(HERE / 'backend.py'), '--root', str(self.root),
                                 'download', 'com.example.app', '--app-id', '123'], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 7)
        self.assertNotIn('FPD_RESULT=', result.stdout)
        self.assertEqual(original.read_bytes(), b'keep-original')

    def test_download_success_uses_downloads_output_with_spaces_in_home(self):
        (self.root / 'fpdecrypt.sh').touch()
        tool = self.root / 'ipatool'
        tool.write_text('''#!/usr/bin/env python3
import pathlib, sys
dest = pathlib.Path(sys.argv[sys.argv.index('--output')+1])
dest.write_bytes(b'downloaded fixture')
''')
        tool.chmod(0o700)
        test_home = self.root / 'test home'
        env = dict(os.environ, PATH=str(self.root)+':'+os.environ['PATH'], HOME=str(test_home))
        result = subprocess.run([sys.executable, str(HERE / 'backend.py'), '--root', str(self.root),
                                 'download', 'com.example.app', '--app-id', '123'], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        marker = next(line for line in result.stdout.splitlines() if line.startswith('FPD_RESULT='))
        ipa = Path(marker.split('=', 1)[1])
        self.assertEqual(ipa.parent, test_home / 'Downloads/Unfairplayed-Output/downloads')
        self.assertEqual(ipa.read_bytes(), b'downloaded fixture')
        self.assertFalse((self.root / 'iOS/out').exists())


class VerifyIPATests(unittest.TestCase):
    @staticmethod
    def macho(cryptid, subtype=0):
        return struct.pack('<8I', 0xfeedfacf, 0x0100000c, subtype, 2, 1, 24, 0, 0) + struct.pack('<6I', 0x2c, 24, 0, 0, cryptid, 0)

    def verify(self, binary=None, payload=True):
        with tempfile.TemporaryDirectory() as folder:
            ipa = Path(folder) / 'test with spaces.ipa'
            with zipfile.ZipFile(ipa, 'w') as archive:
                archive.writestr('Payload/Test.app/Info.plist' if payload else 'empty.txt', b'placeholder')
                if binary:
                    archive.writestr('Payload/Test.app/Test', binary)
            return subprocess.run(['/bin/bash', str(ROOT / 'verify_ipa.sh'), str(ipa)], capture_output=True, text=True)

    def test_small_arm64_decrypted_binary_is_checked(self):
        result = self.verify(self.macho(0))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('cryptid=0', result.stdout)

    def test_small_arm64_encrypted_binary_is_rejected(self):
        result = self.verify(self.macho(1))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ENCRYPTED', result.stdout)

    def test_arm64e_nonzero_cryptid_is_rejected(self):
        result = self.verify(self.macho(2, 0x80000002))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ENCRYPTED', result.stdout)

    def test_mixed_universal_binary_checks_every_slice(self):
        first, second = self.macho(0), self.macho(1, 0x80000002)
        header = struct.pack('>2I', 0xcafebabe, 2)
        header += struct.pack('>5I', 0x0100000c, 0, 4096, len(first), 12)
        header += struct.pack('>5I', 0x0100000c, 0x80000002, 8192, len(second), 12)
        binary = header.ljust(4096, b'\0') + first
        binary = binary.ljust(8192, b'\0') + second
        result = self.verify(binary)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ENCRYPTED', result.stdout)

    def test_empty_payload_is_not_a_successful_decryption(self):
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('no Mach-O', result.stderr)

    def test_non_ipa_archive_is_rejected(self):
        self.assertNotEqual(self.verify(payload=False).returncode, 0)


class TrustRetryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.test_home = self.root / 'test home'
        self.output = self.test_home / 'Downloads/Unfairplayed-Output'
        for name in ('export_ipa.sh', 'verify_ipa.sh'):
            shutil.copy2(ROOT / name, self.root / name)
        # Resume must work without the original IPA, staged payload, or build.
        (self.root / 'fpdecrypt.sh').touch()
        self.tools = self.root / 'tools'
        self.tools.mkdir()
        mock = self.tools / 'xcrun'
        mock.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys, zipfile, struct
root = pathlib.Path(os.environ['FP_TEST_ROOT'])
args = sys.argv[1:]
with (root / 'calls').open('a') as f:
    f.write(json.dumps(args) + '\\n')
if args[:3] == ['devicectl', 'list', 'devices']:
    result = {'result': {'devices': [{'properties': {
        'hardware': {'deviceType': 'iPhone', 'reality': 'physical', 'udid': 'test-device'},
        'connection': {'state': 'connected'}, 'state': {'name': 'Test iPhone'}}}]}}
    pathlib.Path(args[args.index('--json-output')+1]).write_text(json.dumps(result))
elif args[:4] == ['devicectl', 'device', 'process', 'launch']:
    if not (root / 'trusted').exists():
        if (root / 'locked').exists():
            print('The device is locked. Unlock the device to launch this application.')
        else:
            print('Unable to launch because it has an invalid code signature, inadequate entitlements or its profile has not been explicitly trusted by the user.')
        sys.exit(1)
    print('Helper launched and export finished.')
elif args[:4] == ['devicectl', 'device', 'copy', 'from']:
    dest = pathlib.Path(args[args.index('--destination')+1])
    cryptid = int((root / 'bad-output').exists())
    macho = struct.pack('<8I', 0xfeedfacf, 0x0100000c, 0, 2, 1, 24, 0, 0) + struct.pack('<6I', 0x2c, 24, 0, 0, cryptid, 0)
    with zipfile.ZipFile(dest, 'w') as z:
        z.writestr('Payload/Test.app/Test', macho)
elif args[:4] == ['devicectl', 'device', 'uninstall', 'app']:
    if (root / 'uninstall-fails').exists():
        print('Device disconnected during uninstall.')
        sys.exit(9)
    print('Helper uninstalled.')
else:
    print('Unexpected command: ' + repr(args))
    sys.exit(99)
''')
        mock.chmod(0o700)
        self.env = dict(os.environ, PATH=str(self.tools)+':'+os.environ['PATH'], FP_TEST_ROOT=str(self.root), HOME=str(self.test_home))

    def tearDown(self):
        self.temp.cleanup()

    def initial_export(self):
        return subprocess.run(['/bin/bash', str(self.root / 'export_ipa.sh'), 'test-device',
                               'dev.example.helper', 'Test App'], env=self.env, capture_output=True, text=True)

    def retry(self):
        return subprocess.run([sys.executable, str(HERE / 'backend.py'), '--root', str(self.root),
                               'resume-export', '--device', 'test-device', '--bundle', 'dev.example.helper',
                               '--name', 'Test App'], env=self.env, capture_output=True, text=True)

    def test_untrusted_failure_emits_context_without_pulling(self):
        result = self.initial_export()
        self.assertEqual(result.returncode, 78, result.stderr)
        marker = next(line for line in result.stdout.splitlines() if line.startswith('FPD_TRUST_REQUIRED='))
        self.assertEqual(json.loads(marker.split('=', 1)[1]),
                         {'device': 'test-device', 'bundle': 'dev.example.helper', 'name': 'Test App'})
        self.assertNotIn('copy', (self.root / 'calls').read_text())
        self.assertNotIn('FPD_EXPORT_COMPLETE=', result.stdout)

    def test_trusting_then_retrying_exports_without_rebuilding(self):
        self.assertEqual(self.initial_export().returncode, 78)
        (self.root / 'trusted').touch()
        result = self.retry()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.output / 'Test App-decrypted.ipa').is_file())
        self.assertIn('cryptid=0', result.stdout)
        calls = [json.loads(line) for line in (self.root / 'calls').read_text().splitlines()]
        self.assertEqual(sum('launch' in args for args in calls), 2)
        self.assertFalse(any('install' in args or 'build' in args for args in calls))

    def test_retry_still_untrusted_requests_trust_again(self):
        result = self.retry()
        self.assertEqual(result.returncode, 78)
        self.assertIn('FPD_TRUST_REQUIRED=', result.stdout)

    def test_locked_device_is_not_misreported_as_untrusted_certificate(self):
        (self.root / 'locked').touch()
        result = self.initial_export()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('FPD_TRUST_REQUIRED=', result.stdout)

    def test_completed_export_reports_exact_helper_and_host_output(self):
        (self.root / 'trusted').touch()
        result = self.initial_export()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        marker = next(line for line in result.stdout.splitlines() if line.startswith('FPD_EXPORT_COMPLETE='))
        completed = json.loads(marker.split('=', 1)[1])
        self.assertEqual(completed['device'], 'test-device')
        self.assertEqual(completed['bundle'], 'dev.example.helper')
        self.assertEqual(completed['ipa'], str(self.output / 'Test App-decrypted.ipa'))
        self.assertNotIn('uninstall', (self.root / 'calls').read_text())

    def test_failed_verification_does_not_report_completed_export(self):
        (self.root / 'trusted').touch()
        (self.root / 'bad-output').touch()
        result = self.initial_export()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('FPD_EXPORT_COMPLETE=', result.stdout)

    def uninstall(self, bundle='dev.example.helper'):
        info = self.root / 'iOS/build/Build/Products/Debug-iphoneos/Unfairplayed.app/Info.plist'
        info.parent.mkdir(parents=True, exist_ok=True)
        info.write_bytes(plistlib.dumps({'CFBundleIdentifier': 'dev.example.helper'}))
        return subprocess.run([sys.executable, str(HERE / 'backend.py'), '--root', str(self.root),
                               'uninstall-helper', '--device', 'test-device', '--bundle', bundle],
                              env=self.env, capture_output=True, text=True)

    def test_uninstall_uses_completed_device_and_preserves_local_ipa(self):
        (self.root / 'trusted').touch()
        self.assertEqual(self.initial_export().returncode, 0)
        ipa = self.output / 'Test App-decrypted.ipa'
        before = ipa.read_bytes()
        (self.root / '.unfairplayed.env').write_text('DEVICE=another-device\n')
        result = self.uninstall()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(ipa.read_bytes(), before)
        calls = [json.loads(line) for line in (self.root / 'calls').read_text().splitlines()]
        self.assertEqual(calls[-1], ['devicectl', 'device', 'uninstall', 'app', '--device', 'test-device', 'dev.example.helper'])

    def test_uninstall_refuses_a_different_app_bundle(self):
        result = self.uninstall('com.example.target')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('不一致', result.stderr)
        self.assertFalse((self.root / 'calls').exists())

    def test_uninstall_failure_keeps_exported_ipa(self):
        (self.root / 'trusted').touch()
        self.assertEqual(self.initial_export().returncode, 0)
        ipa = self.output / 'Test App-decrypted.ipa'
        before = ipa.read_bytes()
        (self.root / 'uninstall-fails').touch()
        result = self.uninstall()
        self.assertEqual(result.returncode, 9)
        self.assertIn('disconnected', result.stdout)
        self.assertEqual(ipa.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
