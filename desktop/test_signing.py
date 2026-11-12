"""Signing capability, archive safety, environment selection, and bundle reuse checks."""
import datetime
import json
import os
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import debug_ipa
import frida_env
import signing
import backend
import device_connection


class SigningTests(unittest.TestCase):
    def setUp(self):
        self.future = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)).isoformat()
        self.item = dict(source='imported', devices=['phone-a'], allDevices=False,
                         expires=self.future, certificateExpires=self.future, debuggable=False)
        self.profile = {'TeamIdentifier': ['ABCDEFGHIJ'], 'Entitlements': {
            'application-identifier': 'ABCDEFGHIJ.fixed.app', 'get-task-allow': False,
            'keychain-access-groups': ['ABCDEFGHIJ.*']}}

    def test_imported_identity_is_device_scoped_but_not_bundle_scoped(self):
        self.assertEqual(signing.availability(self.item, 'phone-a'), '')
        self.assertIn('UDID', signing.availability(self.item, 'phone-b'))
        self.assertIn('选择', signing.availability(self.item, ''))
        ent = signing.signing_entitlements(self.profile, 'dev.other.app', False)
        self.assertEqual(ent['application-identifier'], 'ABCDEFGHIJ.fixed.app')
        self.assertEqual(ent['keychain-access-groups'], ['ABCDEFGHIJ.dev.other.app'])
        self.assertFalse(ent['get-task-allow'])

    def test_distribution_profile_cannot_silently_enable_debugging(self):
        self.assertIn('get-task-allow', signing.availability(self.item, 'phone-a', True))
        with self.assertRaisesRegex(ValueError, 'get-task-allow'):
            signing.signing_entitlements(self.profile, 'dev.other.app', True)
        self.profile['Entitlements']['get-task-allow'] = True
        self.assertTrue(signing.signing_entitlements(self.profile, 'dev.other.app', True)['get-task-allow'])

    def test_expired_profile_and_certificate_disable_selection(self):
        for field in ('expires', 'certificateExpires'):
            item = dict(self.item, **{field: '2000-01-01T00:00:00+00:00'})
            self.assertIn('过期', signing.availability(item, 'phone-a'))
        self.assertEqual(signing.availability(dict(self.item, allDevices=True), 'other'), '')

    def test_wildcard_identity_expands_and_restricts_its_prefix(self):
        self.profile['Entitlements']['application-identifier'] = 'ABCDEFGHIJ.dev.example.*'
        ent = signing.signing_entitlements(self.profile, 'dev.example.app', False)
        self.assertEqual(ent['application-identifier'], 'ABCDEFGHIJ.dev.example.app')
        with self.assertRaises(ValueError):
            signing.signing_entitlements(self.profile, 'dev.other.app', False)

    def test_main_only_install_removes_extensions_without_provisioning_them(self):
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder) / 'Test.app'; app.mkdir()
            (app / 'Test').write_bytes(b'main executable')
            framework = app / 'Frameworks/Keep.framework'; framework.mkdir(parents=True)
            for path in ('PlugIns/Widget.appex', 'PlugIns/Share.appex', 'Watch/Watch.app/PlugIns/Watch.appex', 'AppClips/Clip.app'):
                (app / path).mkdir(parents=True)
            with patch.object(debug_ipa, 'credential_for') as provision, patch.object(signing, 'sign_app') as sign:
                debug_ipa.prepare_extensions(Path(folder), app, 'com.original.app', 'dev.helper.app', 'xcode:ABCDEFGHIJ', 'phone-a', True, False)
            provision.assert_not_called(); sign.assert_not_called()
            self.assertEqual((app / 'Test').read_bytes(), b'main executable')
            self.assertTrue(framework.is_dir())
            self.assertFalse((app / 'PlugIns').exists())
            self.assertFalse((app / 'Watch').exists())
            self.assertFalse((app / 'AppClips').exists())

    def test_keep_extensions_signs_their_own_ids(self):
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder) / 'Test.app'
            extension = app / 'PlugIns/Widget.appex'; extension.mkdir(parents=True)
            (extension / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'com.original.app.Widget'}))
            with patch.object(debug_ipa, 'credential_for', return_value={'identity': 'CERT'}) as provision, patch.object(signing, 'sign_app') as sign:
                debug_ipa.prepare_extensions(Path(folder), app, 'com.original.app', 'dev.helper.app', 'xcode:ABCDEFGHIJ', 'phone-a', True, True)
            provision.assert_called_once_with(Path(folder), 'xcode:ABCDEFGHIJ', 'dev.helper.app.Widget', 'phone-a', True)
            sign.assert_called_once_with(extension, {'identity': 'CERT'}, 'dev.helper.app.Widget', True)
            self.assertTrue(extension.is_dir())

    def test_missing_extension_signature_reports_the_extension_id(self):
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder) / 'Test.app'
            extension = app / 'PlugIns/Widget.appex'; extension.mkdir(parents=True)
            (extension / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'com.original.app.Widget'}))
            with patch.object(debug_ipa, 'credential_for', side_effect=signing.ProvisioningError('login required', 'account')):
                with self.assertRaises(signing.ProvisioningError) as result:
                    debug_ipa.prepare_extensions(Path(folder), app, 'com.original.app', 'dev.helper.app', 'xcode:ABCDEFGHIJ', 'phone-a', True, True)
            self.assertEqual(result.exception.bundle, 'dev.helper.app.Widget')
            self.assertEqual(result.exception.reason, 'account')
            self.assertIn('保留应用扩展', str(result.exception))

    def test_existing_valid_profile_avoids_new_xcode_registration(self):
        profile = dict(self.profile)
        profile['Entitlements'] = dict(self.profile['Entitlements'], **{'application-identifier': 'ABCDEFGHIJ.dev.example.app', 'get-task-allow': True})
        metadata = dict(self.item, team='ABCDEFGHIJ', appIdentifier='ABCDEFGHIJ.dev.example.app', debuggable=True)
        with patch.object(signing, 'local_profiles', return_value=[(Path('/profile'), profile, metadata)]), patch.object(signing, 'profile_identity', return_value='CERT'), patch.object(signing.subprocess, 'run') as build:
            credential = signing.provision_xcode(Path('/project'), 'ABCDEFGHIJ', 'dev.example.app', 'phone-a')
        self.assertEqual(credential['identity'], 'CERT')
        self.assertEqual(credential['profilePath'], Path('/profile'))
        build.assert_not_called()

    def test_session_restore_drops_deleted_output(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(Path, 'home', return_value=Path(folder)):
            root = Path(folder); ipa = root / 'signed.ipa'; ipa.touch(); app = root / 'Test.app'; app.mkdir()
            session = dict(bundle='dev.example.debug', ipa=str(ipa), app=str(app), session=str(root / 'session.json'))
            (root / 'session.json').write_text(json.dumps(session))
            debug_ipa.remember_session(session)
            self.assertEqual(debug_ipa.last_session(), session)
            ipa.unlink()
            self.assertIsNone(debug_ipa.last_session())

    def test_generated_id_is_stable_and_can_be_reused_or_customized(self):
        first = signing.debug_bundle('com.example.app', 'new', '', 'ABCDEFGHIJ')
        self.assertEqual(first, signing.debug_bundle('com.example.app', 'new', '', 'ABCDEFGHIJ'))
        self.assertNotEqual(first, signing.debug_bundle('com.example.app', 'new', '', '0123456789'))
        self.assertEqual(signing.debug_bundle('com.example.app', 'reuse', '', ''), 'com.example.app')
        self.assertEqual(signing.debug_bundle('com.example.app', 'custom', first, ''), first)
        for value in ('', '../bad', 'a\nb.c'):
            with self.assertRaises(ValueError):
                signing.debug_bundle('com.example.app', 'custom', value, '')

    def test_history_remembers_successful_ids_without_duplicates(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(Path, 'home', return_value=Path(folder)):
            session = dict(bundle='dev.example.debug', originalBundle='com.example.app', name='Example', signer='xcode:ABCDEFGHIJ')
            debug_ipa.remember_bundle(session)
            debug_ipa.remember_bundle(dict(session, name='Updated'))
            self.assertEqual(debug_ipa.bundle_history(), [dict(session, name='Updated')])
            path = Path(folder) / 'Library/Application Support/Unfairplayed/debug-bundles.json'
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_id_history_keeps_ten_recent_unique_ids_and_evicts_oldest(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(Path, 'home', return_value=Path(folder)):
            for number in range(12):
                debug_ipa.remember_bundle(dict(bundle=f'dev.example.app{number}', name=str(number), signer='xcode:ABCDEFGHIJ'))
            values = debug_ipa.bundle_history()
            self.assertEqual(len(values), 10)
            self.assertEqual(values[0]['bundle'], 'dev.example.app11')
            self.assertEqual(values[-1]['bundle'], 'dev.example.app2')
            debug_ipa.remember_bundle(dict(bundle='dev.example.app4', name='reused', signer='xcode:ABCDEFGHIJ'))
            values = debug_ipa.bundle_history()
            self.assertEqual(values[0]['bundle'], 'dev.example.app4')
            self.assertEqual(len({v['bundle'] for v in values}), 10)
            path = Path(folder) / 'Library/Application Support/Unfairplayed/debug-bundles.json'
            self.assertEqual(len(json.loads(path.read_text())), 10)

    def test_old_history_is_physically_trimmed_to_ten(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(Path, 'home', return_value=Path(folder)):
            path = Path(folder) / 'Library/Application Support/Unfairplayed/debug-bundles.json'
            path.parent.mkdir(parents=True)
            values = [dict(bundle=f'dev.example.app{i}', name=str(i)) for i in range(40)]
            path.write_text(json.dumps(values))
            self.assertEqual(debug_ipa.bundle_history(), values[:10])
            self.assertEqual(json.loads(path.read_text()), values[:10])

    def test_reusing_helper_id_uses_the_explicit_helper_identifier(self):
        self.assertEqual(signing.debug_bundle('com.original.app', 'helper', 'dev.example.helper', 'ABCDEFGHIJ'), 'dev.example.helper')

    def test_new_xcode_id_is_prepared_and_remembered_only_after_success(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(Path, 'home', return_value=Path(folder)):
            with patch.object(signing, 'provision_xcode') as provision:
                debug_ipa.create_bundle(Path('/root'), 'dev.example.created', 'xcode:ABCDEFGHIJ', 'phone-a', 'Created')
            provision.assert_called_once_with(Path('/root'), 'ABCDEFGHIJ', 'dev.example.created', 'phone-a')
            self.assertEqual(debug_ipa.bundle_history()[0]['bundle'], 'dev.example.created')
            with patch.object(signing, 'provision_xcode', side_effect=signing.ProvisioningError('login required', 'account')):
                with self.assertRaises(signing.ProvisioningError):
                    debug_ipa.create_bundle(Path('/root'), 'dev.example.failed', 'xcode:ABCDEFGHIJ', 'phone-a')
            self.assertEqual([v['bundle'] for v in debug_ipa.bundle_history()], ['dev.example.created'])

    def test_imported_identity_creates_a_local_id_without_contacting_xcode(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(Path, 'home', return_value=Path(folder)), patch.object(signing, 'imported_signers', return_value=[{'id': 'imported:sample'}]), patch.object(signing, 'provision_xcode') as provision:
            debug_ipa.create_bundle(Path('/root'), 'dev.example.local', 'imported:sample')
            provision.assert_not_called()
            self.assertEqual(debug_ipa.bundle_history()[0]['bundle'], 'dev.example.local')

    def test_signing_failures_offer_specific_next_actions(self):
        self.assertEqual(signing.provisioning_failure('error: No Accounts: Add a new account in Accounts settings.').reason, 'account')
        self.assertEqual(signing.provisioning_failure('You may create up to 10 App IDs every 7 days').reason, 'quota')
        self.assertEqual(signing.provisioning_failure('The network connection was lost.').reason, 'network')

    def test_input_is_verified_before_signing_or_installing(self):
        with tempfile.TemporaryDirectory() as folder:
            ipa = Path(folder) / 'encrypted.ipa'
            with zipfile.ZipFile(ipa, 'w') as z:
                z.writestr('Payload/Test.app/Test', b'fixture')
            with patch.object(signing, 'run', side_effect=ValueError('ENCRYPTED')), patch.object(signing, 'resolve_imported') as resolve:
                with self.assertRaisesRegex(ValueError, 'ENCRYPTED'):
                    debug_ipa.install_debug(Path(folder), ipa, 'imported:any', 'phone-a', 'new', '')
                resolve.assert_not_called()

    def test_helper_payload_is_never_resigned_or_stripped(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = root / 'Helper.app'; app.mkdir()
            (app / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'dev.test.helper'}))
            payload = app / 'EmbeddedPayload/Target/Frameworks/Private.framework'
            payload.mkdir(parents=True)
            signature = payload / '_CodeSignature/CodeResources'
            signature.parent.mkdir(); signature.write_bytes(b'original signature')
            profile = root / 'profile'; profile.write_bytes(b'fixture')
            calls = []
            def run(args, **kwargs):
                calls.append([str(a) for a in args])
                return plistlib.dumps({'get-task-allow': False}) if '-d' in args else b''
            with patch.object(signing, 'run', side_effect=run):
                signing.sign_app(app, {'profile': self.profile, 'profilePath': profile, 'identity': 'hash'}, 'dev.new.helper', False, True)
            self.assertEqual(signature.read_bytes(), b'original signature')
            self.assertFalse(any('EmbeddedPayload' in ' '.join(c) for c in calls))


class DebuggerLaunchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'session.json'
        self.session = {'bundle': 'dev.example.debug', 'device': 'test-phone', 'debuggable': True,
                        'frida': '/selected/env/bin/frida', 'app': '/tmp/Test.app', 'executable': 'Test'}
        self.path.write_text(json.dumps(self.session))
        wired = patch.object(device_connection, 'require_wired')
        self.wired = wired.start()
        self.addCleanup(wired.stop)
        running = patch.object(debug_ipa, 'running_target_pid', return_value=None)
        self.running = running.start()
        self.addCleanup(running.stop)

    def tearDown(self):
        self.temp.cleanup()

    def mock_launch(self, args, **kwargs):
        path = Path(args[args.index('--json-output') + 1])
        path.write_text(json.dumps({'result': {'process': {'processIdentifier': 1234}}}))
        return b''

    def test_frida_default_launches_app_and_attaches_to_returned_pid(self):
        with patch.object(debug_ipa, 'prepare_frida', return_value='/selected/env/bin/frida'), patch.object(signing, 'run', side_effect=self.mock_launch) as launch, patch.object(debug_ipa.os, 'execv') as execute:
            debug_ipa.attach(self.path, 'frida')
        args = launch.call_args.args[0]
        self.assertNotIn('--terminate-existing', args)
        self.assertNotIn('--start-stopped', args)
        self.assertEqual(args[-1], 'dev.example.debug')
        execute.assert_called_once_with('/selected/env/bin/frida', ['/selected/env/bin/frida', '-D', 'test-phone', '-p', '1234'])

    def test_running_app_is_attached_without_any_launch_or_termination(self):
        self.running.return_value = 6789
        with patch.object(debug_ipa, 'prepare_frida', return_value='/selected/env/bin/frida'), patch.object(signing, 'run') as launch, patch.object(debug_ipa.os, 'execv') as execute:
            debug_ipa.attach(self.path, 'frida')
        launch.assert_not_called()
        execute.assert_called_once_with('/selected/env/bin/frida', ['/selected/env/bin/frida', '-D', 'test-phone', '-p', '6789'])

    def test_unknown_running_state_never_restarts_the_app(self):
        self.running.side_effect = ValueError('cannot inspect processes')
        with patch.object(debug_ipa, 'prepare_frida', return_value='/selected/env/bin/frida'), patch.object(debug_ipa, 'launch_target') as launch, patch.object(debug_ipa.os, 'execv') as execute:
            with self.assertRaisesRegex(ValueError, 'cannot inspect processes'):
                debug_ipa.attach(self.path, 'frida')
        launch.assert_not_called()
        execute.assert_not_called()

    def test_lldb_still_starts_suspended(self):
        with patch.object(signing, 'run', side_effect=self.mock_launch) as launch, patch.object(debug_ipa.os, 'execv'):
            debug_ipa.attach(self.path, 'lldb')
        self.assertIn('--start-stopped', launch.call_args.args[0])
        self.assertNotIn('--terminate-existing', launch.call_args.args[0])
        self.wired.assert_not_called()
        self.assertIn('device process attach --pid 1234', (self.path.parent / 'debug-session.lldb').read_text())

    def test_lldb_attach_reuses_the_running_pid_without_launching(self):
        self.running.return_value = 6789
        with patch.object(debug_ipa, 'launch_target') as launch, patch.object(debug_ipa.os, 'execv') as execute:
            debug_ipa.attach(self.path, 'lldb')
        launch.assert_not_called()
        self.wired.assert_not_called()
        self.assertIn('device process attach --pid 6789', (self.path.parent / 'debug-session.lldb').read_text())
        execute.assert_called_once()

    def test_lldb_launch_explicitly_restarts_suspended_even_if_running(self):
        self.running.return_value = 6789
        with patch.object(signing, 'run', side_effect=self.mock_launch) as launch, patch.object(debug_ipa.os, 'execv'):
            debug_ipa.attach(self.path, 'lldb', lldb_launch=True)
        self.running.assert_not_called()
        self.assertIn('--terminate-existing', launch.call_args.args[0])
        self.assertIn('--start-stopped', launch.call_args.args[0])
        self.assertIn('device process attach --pid 1234', (self.path.parent / 'debug-session.lldb').read_text())

    def test_lldb_attach_unknown_state_never_restarts(self):
        self.running.side_effect = ValueError('cannot inspect processes')
        with patch.object(debug_ipa, 'launch_target') as launch, patch.object(debug_ipa.os, 'execv') as execute:
            with self.assertRaisesRegex(ValueError, 'cannot inspect processes'):
                debug_ipa.attach(self.path, 'lldb')
        launch.assert_not_called(); execute.assert_not_called()

    def test_lldb_mode_reaches_launcher_and_uses_saved_setting(self):
        root = self.path.parent
        (root / 'fpdecrypt.sh').touch()
        (root / '.unfairplayed.env').write_text('LLDB_MODE=launch\n')
        for mode in ('attach', 'launch', None):
            args = ['backend.py', '--root', str(root), 'open-debugger', '--session', str(self.path), '--tool', 'lldb']
            if mode:
                args += ['--lldb-mode', mode]
            with patch.object(sys, 'argv', args), patch.object(backend.subprocess, 'run'):
                self.assertEqual(backend.main(), 0)
            command = (root / 'Open-LLDB.command').read_text()
            self.assertEqual('--lldb-launch' in command, mode != 'attach')
            self.assertNotIn('--frida-spawn', command)

    def test_failed_launch_never_starts_frida_with_stale_pid(self):
        with patch.object(debug_ipa, 'prepare_frida', return_value='/selected/env/bin/frida'), patch.object(signing, 'run', side_effect=ValueError('device locked')), patch.object(debug_ipa.os, 'execv') as execute:
            with self.assertRaisesRegex(ValueError, 'device locked'):
                debug_ipa.attach(self.path, 'frida')
        execute.assert_not_called()

    def test_wireless_blocks_both_frida_modes_before_launch_or_download(self):
        for spawn in (False, True):
            with patch.object(device_connection, 'require_wired', side_effect=ValueError('USB required')), patch.object(debug_ipa, 'prepare_frida') as prepare, patch.object(debug_ipa.os, 'execv') as execute:
                with self.assertRaisesRegex(ValueError, 'USB required'):
                    debug_ipa.attach(self.path, 'frida', frida_spawn=spawn)
            prepare.assert_not_called()
            execute.assert_not_called()

    def test_wireless_blocks_terminal_frida_launcher_but_not_lldb(self):
        root = self.path.parent
        (root / 'fpdecrypt.sh').touch()
        for tool in ('frida', 'lldb'):
            args = ['backend.py', '--root', str(root), 'open-debugger', '--session', str(self.path), '--tool', tool]
            with patch.object(sys, 'argv', args), patch.object(device_connection, 'require_wired', side_effect=ValueError('USB required')) as check, patch.object(backend.subprocess, 'run') as terminal:
                if tool == 'frida':
                    with self.assertRaisesRegex(ValueError, 'USB required'):
                        backend.main()
                    terminal.assert_not_called()
                else:
                    self.assertEqual(backend.main(), 0)
                    check.assert_not_called()
                    terminal.assert_called_once()

    def test_selected_mode_reaches_terminal_launcher(self):
        root = self.path.parent
        (root / 'fpdecrypt.sh').touch()
        for mode in ('attach', 'spawn'):
            args = ['backend.py', '--root', str(root), 'open-debugger', '--session', str(self.path),
                    '--tool', 'frida', '--frida-mode', mode]
            with patch.object(sys, 'argv', args), patch.object(backend.subprocess, 'run'):
                self.assertEqual(backend.main(), 0)
            command = (root / 'Open-FRIDA.command').read_text()
            self.assertEqual('--frida-spawn' in command, mode == 'spawn')

    def test_advanced_spawn_is_explicit_and_skips_native_launch(self):
        with patch.object(debug_ipa, 'prepare_frida', return_value='/selected/env/bin/frida'), patch.object(signing, 'run') as launch, patch.object(debug_ipa.os, 'execv') as execute:
            debug_ipa.attach(self.path, 'frida', frida_spawn=True)
        launch.assert_not_called()
        self.assertIn('-f', execute.call_args.args[1])


class RunningAppTests(unittest.TestCase):
    def test_main_process_matches_bundle_install_location_not_another_app_or_extension(self):
        session = {'bundle': 'dev.example.debug', 'device': 'phone', 'executable': 'SameName'}
        app_url = 'file:///private/var/containers/Bundle/Application/ABC/My%20App.app/'
        processes = [
            {'executable': 'file:///private/var/containers/Bundle/Application/OTHER/My%20App.app/SameName', 'processIdentifier': 1},
            {'executable': app_url + 'PlugIns/Extension.appex/SameName', 'processIdentifier': 2},
            {'executable': '/var/containers/Bundle/Application/ABC/My App.app/SameName', 'processIdentifier': 3}]
        def run(args, **kwargs):
            if 'apps' in args:
                result = {'apps': [{'bundleIdentifier': session['bundle'], 'url': app_url}]}
            else:
                result = {'runningProcesses': processes}
            Path(args[args.index('--json-output') + 1]).write_text(json.dumps({'result': result}))
            return b''
        with patch.object(signing, 'run', side_effect=run):
            self.assertEqual(debug_ipa.running_target_pid(session), 3)
            processes.pop()
            self.assertIsNone(debug_ipa.running_target_pid(session))

    def test_process_query_failure_is_not_treated_as_not_running(self):
        def run(args, **kwargs):
            if 'apps' in args:
                result = {'apps': [{'bundleIdentifier': 'dev.example.app', 'url': 'file:///var/Test.app/'}]}
            else:
                result = {}
            Path(args[args.index('--json-output') + 1]).write_text(json.dumps({'result': result}))
            return b''
        with patch.object(signing, 'run', side_effect=run):
            with self.assertRaisesRegex(ValueError, '运行状态'):
                debug_ipa.running_target_pid({'bundle': 'dev.example.app', 'device': 'phone', 'executable': 'Test'})


class ConnectionTests(unittest.TestCase):
    def test_usb_registry_matches_device_udid_not_just_presence_of_a_phone(self):
        first = '00008150-0123456789012345'
        second = '00008150-ABCDEF0123456789'
        def phone(serial, product='iPhone', vendor=0x05ac):
            return {'USB Product Name': product, 'USB Serial Number': serial, 'idVendor': vendor}
        tree = [{'IORegistryEntryChildren': [phone(first.replace('-', '')), phone('0123456789abcdef' * 2 + '01234567', 'iPad'),
                                            phone(second, vendor=123), phone(second, product='USB Drive')]}]
        found = device_connection.usb_udids_from_registry(tree)
        self.assertIn(device_connection.normalize_udid(first), found)
        self.assertNotIn(device_connection.normalize_udid(second), found)
        with patch.object(device_connection, 'wired_devices', return_value=found):
            device_connection.require_wired(first)
            with self.assertRaisesRegex(ValueError, 'USB'):
                device_connection.require_wired(second)
        self.assertEqual(len(found), 2)

    def test_missing_or_failed_usb_inventory_disables_frida(self):
        with patch.object(device_connection.subprocess, 'run', side_effect=OSError('unavailable')):
            self.assertEqual(device_connection.wired_devices(), set())
        with patch.object(device_connection, 'wired_devices', return_value=set()):
            with self.assertRaisesRegex(ValueError, 'USB'):
                device_connection.require_wired('00008150-0123456789012345')


class ArchiveTests(unittest.TestCase):
    def check_archive(self, files=(), links=()):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'test.ipa'
            with zipfile.ZipFile(path, 'w') as z:
                for name in files:
                    z.writestr(name, b'fixture')
                for name, target in links:
                    info = zipfile.ZipInfo(name); info.create_system = 3
                    info.external_attr = 0o120777 << 16
                    z.writestr(info, target)
            debug_ipa.validate_archive(path)

    def test_traversal_and_symlink_escape_are_rejected(self):
        for name in ('../outside', '/outside', 'Payload/../../outside', 'Payload\\outside'):
            with self.assertRaises(ValueError):
                self.check_archive([name])
        for target in ('../../../outside', '/outside'):
            with self.assertRaises(ValueError):
                self.check_archive(links=[('Payload/App.app/link', target)])

    def test_links_cannot_be_used_as_extraction_parent_or_chain_outside(self):
        with self.assertRaises(ValueError):
            self.check_archive(['Payload/App.app/link/file'], [('Payload/App.app/link', 'dir')])
        with self.assertRaises(ValueError):
            self.check_archive(links=[('Payload/App.app/a', '../..'), ('Payload/App.app/b', 'a/../escape')])
        with self.assertRaises(ValueError):
            self.check_archive(links=[('Payload/App.app/a', 'b'), ('Payload/App.app/b', 'a')])
        self.check_archive(['Payload/App.app/F.framework/Versions/A/F'],
                           [('Payload/App.app/F.framework/Versions/Current', 'A'),
                            ('Payload/App.app/F.framework/F', 'Versions/Current/F')])


class FridaTests(unittest.TestCase):
    def test_base_is_default_and_other_env_requires_explicit_selection(self):
        choices = [dict(id='/fake/base/bin/frida', name='Conda · base', available=True),
                   dict(id='/fake/env/bin/frida', name='Conda · iOSRev', available=True)]
        with patch.object(frida_env, 'environments', return_value=choices), patch.object(Path, 'is_file', return_value=True), patch.object(os, 'access', return_value=True):
            self.assertEqual(frida_env.find_frida(), choices[0]['id'])
            self.assertEqual(frida_env.find_frida(choices[1]['id']), choices[1]['id'])
        with patch.object(frida_env, 'environments', return_value=[dict(choices[0], available=False), choices[1]]):
            self.assertIsNone(frida_env.find_frida())

    def test_missing_custom_executable_does_not_fall_back_to_another_env(self):
        with self.assertRaises(ValueError):
            frida_env.find_frida('/nonexistent/frida')
        with self.assertRaises(ValueError):
            frida_env.find_frida('relative/frida')

    def test_environment_path_roundtrips_with_spaces_and_never_executes_shell(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = '/tmp/my env/bin/frida'
            backend.save_config(root, 'ABCDEFGHIJ', 'dev.example.helper', '', {'FRIDA_PATH': path, 'FRIDA_MODE': 'spawn', 'LLDB_MODE': 'launch'})
            self.assertEqual(backend.read_config(root)['FRIDA_PATH'], path)
            self.assertEqual(backend.read_config(root)['FRIDA_MODE'], 'spawn')
            self.assertEqual(backend.read_config(root)['LLDB_MODE'], 'launch')
            with self.assertRaises(ValueError):
                backend.save_config(root, 'ABCDEFGHIJ', 'dev.example.helper', '', {'LLDB_MODE': 'invalid'})
            with self.assertRaises(ValueError):
                backend.save_config(root, 'ABCDEFGHIJ', 'dev.example.helper', '', {'FRIDA_MODE': 'invalid'})
            with self.assertRaises(ValueError):
                backend.save_config(root, 'ABCDEFGHIJ', 'dev.example.helper', '', {'FRIDA_PATH': path + '\nTEAM_ID=bad'})


if __name__ == '__main__':
    unittest.main()
