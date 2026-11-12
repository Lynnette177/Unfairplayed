"""IPA inventory, encryption labels, cached icons, and external-file reuse."""
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ipa_library


def macho(cryptid):
    return struct.pack('<8I', 0xfeedfacf, 0x0100000c, 0, 2, 1, 24, 0, 0) + struct.pack('<6I', 0x2c, 24, 0, 0, cryptid, 0)


def png():
    def chunk(name, value):
        return struct.pack('>I', len(value)) + name + value + struct.pack('>I', zlib.crc32(name + value))
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>2I5B', 1, 1, 8, 6, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(b'\0\0\x7f\xff\xff')) + chunk(b'IEND', b'')


class LibraryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name) / 'home'; self.home.mkdir()
        self.root = Path(self.temp.name) / 'project'; self.root.mkdir()
        self.home_patch = patch.object(Path, 'home', return_value=self.home)
        self.home_patch.start(); self.addCleanup(self.home_patch.stop)
        self.addCleanup(self.temp.cleanup)

    def ipa(self, path, cryptid=1, version='1.0'):
        path.parent.mkdir(parents=True, exist_ok=True)
        info = {'CFBundleDisplayName': 'Example', 'CFBundleIdentifier': 'com.example.app',
                'CFBundleExecutable': 'App', 'CFBundleShortVersionString': version,
                'CFBundleIcons': {'CFBundlePrimaryIcon': {'CFBundleIconFiles': ['AppIcon60x60']}}}
        with zipfile.ZipFile(path, 'w') as z:
            z.writestr('Payload/Example.app/Info.plist', plistlib.dumps(info))
            z.writestr('Payload/Example.app/App', macho(cryptid))
            z.writestr('Payload/Example.app/AppIcon60x60@2x.png', png())
        return path

    def test_metadata_icon_and_labels_are_read_without_modifying_the_ipa(self):
        path = self.ipa(self.home / 'Downloads/App-decrypted.ipa', cryptid=0)
        before = hashlib.sha256(path.read_bytes()).digest()
        item = ipa_library.inspect_ipa(path)
        self.assertEqual((item['name'], item['bundle'], item['version']), ('Example', 'com.example.app', '1.0'))
        self.assertEqual((item['kind'], item['state']), ('decrypted', 'decrypted'))
        self.assertEqual(Path(item['icon']).read_bytes(), png())
        self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)

    def test_encrypted_and_partial_packages_are_never_presented_as_reusable_exports(self):
        fake_name = self.ipa(self.home / 'fake-decrypted.ipa', cryptid=1)
        item = ipa_library.inspect_ipa(fake_name)
        self.assertEqual((item['kind'], item['state']), ('downloaded', 'encrypted'))
        partial = ipa_library.inspect_ipa(self.ipa(self.home / 'App-PARTIAL.ipa', cryptid=0))
        self.assertTrue(partial['partial'])
        self.assertEqual(partial['kind'], 'downloaded')

    def test_cached_metadata_is_reused_and_replaced_when_the_archive_changes(self):
        path = self.ipa(self.home / 'example.ipa')
        self.assertEqual(ipa_library.inspect_ipa(path)['version'], '1.0')
        with patch.object(ipa_library.zipfile, 'ZipFile', side_effect=AssertionError('should use metadata cache')):
            self.assertEqual(ipa_library.inspect_ipa(path)['version'], '1.0')
        self.ipa(path, version='2.0')
        self.assertEqual(ipa_library.inspect_ipa(path)['version'], '2.0')

    def test_registered_external_paths_are_private_deduplicated_and_not_copied(self):
        path = self.ipa(Path(self.temp.name) / 'external files/App.ipa')
        before = path.read_bytes()
        ipa_library.add_paths([str(path), str(path)])
        ipa_library.add_paths([str(path)])
        items = ipa_library.inventory(self.root)
        self.assertEqual([i['path'] for i in items], [str(path.resolve())])
        self.assertEqual(path.read_bytes(), before)
        self.assertFalse((self.home / 'Downloads/Unfairplayed-Output').exists())
        self.assertEqual(stat.S_IMODE(ipa_library.library_store().stat().st_mode), 0o600)

    def test_automatic_discovery_covers_downloads_exports_and_legacy_output(self):
        output = self.home / 'Downloads/Unfairplayed-Output'
        downloaded = self.ipa(output / 'downloads/encrypted.ipa')
        exported = self.ipa(output / 'Example-decrypted.ipa', 0)
        legacy = self.ipa(self.root / 'iOS/out/old.ipa')
        upper = self.ipa(self.home / 'Downloads/UPPER.IPA')
        self.ipa(output / 'debug/job/App-debug-signed.ipa', 0)
        items = ipa_library.inventory(self.root)
        self.assertEqual({i['path'] for i in items}, {str(p.resolve()) for p in (downloaded, exported, legacy, upper)})

    def test_a_broken_archive_does_not_hide_healthy_items(self):
        path = self.home / 'Downloads'; path.mkdir()
        (path / 'broken.ipa').write_bytes(b'not a zip')
        self.ipa(path / 'good.ipa')
        items = ipa_library.inventory(self.root)
        self.assertEqual(len(items), 2)
        broken = next(i for i in items if i['name'] == 'broken')
        self.assertTrue(broken['error'])
        self.assertEqual(broken['kind'], 'downloaded')

    def test_universal_header_checks_every_architecture(self):
        first, second = macho(0), macho(1)
        header = struct.pack('>2I', 0xcafebabe, 2)
        header += struct.pack('>5I', 0x0100000c, 0, 4096, len(first), 12)
        header += struct.pack('>5I', 0x0100000c, 0x80000002, 8192, len(second), 12)
        binary = (header.ljust(4096, b'\0') + first).ljust(8192, b'\0') + second
        self.assertEqual(ipa_library.encryption_state(io.BytesIO(binary), len(binary)), 'encrypted')
        self.assertEqual(ipa_library.encryption_state(io.BytesIO(b'invalid'), 7), 'unknown')


if __name__ == '__main__':
    unittest.main()
