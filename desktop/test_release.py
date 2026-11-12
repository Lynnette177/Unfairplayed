"""Release isolation, privacy gates, and native workspace preparation."""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import unittest

import release_tools

ROOT = Path(__file__).resolve().parent.parent


class ReleaseTests(unittest.TestCase):
    def test_project_signing_selections_are_removed_from_public_copies(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'project.pbxproj'
            source.write_text('DEVELOPMENT_TEAM = PRIVATE123;\nDevelopmentTeam = PRIVATE123;\nPROVISIONING_PROFILE_SPECIFIER = "private profile";\nCODE_SIGN_IDENTITY = "personal identity";\nPRODUCT_BUNDLE_IDENTIFIER = dev.private.test;\nCODE_SIGN_STYLE = Automatic;\n')
            copied = root / 'public/project.pbxproj'
            release_tools.copy_public(source, copied)
            text = copied.read_text()
            self.assertNotIn('PRIVATE123', text)
            self.assertNotIn('private profile', text)
            self.assertNotIn('personal identity', text)
            self.assertIn('PRODUCT_BUNDLE_IDENTIFIER = dev.unfairplayed.helper;', text)
            self.assertIn('CODE_SIGN_STYLE = Automatic;', text)
            self.assertIn('PRIVATE123', source.read_text())

    def test_source_and_runtime_allowlists_exclude_private_state(self):
        paths = release_tools.source_files(ROOT)
        self.assertIn('desktop/WorkspaceBootstrap.swift', paths)
        self.assertIn('desktop/InjectionRuntime/libhooker.dylib', paths)
        self.assertNotIn('.unfairplayed.env', paths)
        self.assertFalse(any(p.startswith(('desktop/build/', 'desktop/dist/', '.git/')) for p in paths))
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'runtime'
            release_tools.stage_runtime(ROOT, destination)
            value = json.loads((destination / 'manifest.json').read_text())
            for entry in value['files']:
                self.assertEqual(release_tools.digest((destination / entry['path']).read_bytes()), entry['sha256'])
            self.assertTrue((destination / 'iOS/Unfairplayed.xcodeproj/project.pbxproj').exists())
            self.assertFalse((destination / '.unfairplayed.env').exists())

    def test_privacy_gate_rejects_identifiers_in_binary_and_unicode_without_echoing_values(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); path = root / 'binary'
            secret = 'unique-private-test-identity'
            for encoding in ('utf-8', 'utf-16-le', 'utf-16-be'):
                path.write_bytes(b'\0' + secret.encode(encoding) + b'\0')
                with self.assertRaises(ValueError) as error:
                    release_tools.audit_tree(root, {secret: 'test-identifier'})
                self.assertNotIn(secret, str(error.exception))
            path.write_bytes(b'clean data')
            release_tools.audit_tree(root, {secret: 'test-identifier'})
            private = root / 'certificate.pfx'; private.write_bytes(b'private file')
            with self.assertRaisesRegex(ValueError, 'private-artifact'):
                release_tools.audit_tree(root, {})
            private.unlink()
            named = root / (secret + '.txt'); named.write_text('no secret in the contents')
            with self.assertRaises(ValueError) as error:
                release_tools.audit_tree(root, {secret: 'test-identifier'})
            self.assertNotIn(secret, str(error.exception))

    def test_source_archive_has_no_git_history_and_preserves_executable_mode(self):
        import zipfile
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'Unfairplayed'; root.mkdir()
            script = root / 'run.sh'; script.write_text('#!/bin/bash\n'); script.chmod(0o755)
            archive = Path(folder) / 'source.zip'
            release_tools.write_zip(root, archive)
            with zipfile.ZipFile(archive) as value:
                self.assertEqual(value.namelist(), ['Unfairplayed/run.sh'])
                self.assertEqual(value.getinfo('Unfairplayed/run.sh').external_attr >> 16 & 0o777, 0o755)

    def test_native_workspace_prepare_preserves_private_files_and_rejects_invalid_templates(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / 'bootstrap-test'
            compiled = subprocess.run(['xcrun', 'swiftc', '-swift-version', '5', '-parse-as-library',
                '-framework', 'CryptoKit', str(ROOT / 'desktop/WorkspaceBootstrap.swift'),
                str(ROOT / 'desktop/test_workspace_bootstrap.swift'), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([binary], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('checks passed', result.stdout)
