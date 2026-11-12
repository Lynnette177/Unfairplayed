"""Real iOS Mach-O injection and failure atomicity checks (no device required)."""
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backend
import dylib_injection as injection


class DylibInjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.fixtures = Path(cls.temp.name)
        cls.sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
        (cls.fixtures / 'main.c').write_text('int main(void) { return 0; }\n')
        (cls.fixtures / 'library.c').write_text('int injected_probe(void) { return 42; }\n')
        for arch in ('arm64', 'arm64e'):
            cls.compile(cls.fixtures / 'main.c', cls.fixtures / ('main-' + arch), arch)
            cls.compile(cls.fixtures / 'library.c', cls.fixtures / (arch + '.dylib'), arch, library=True)
        subprocess.run(['xcrun', 'lipo', '-create', cls.fixtures / 'main-arm64', cls.fixtures / 'main-arm64e', '-output', cls.fixtures / 'main-fat'], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def compile(cls, source, destination, arch='arm64', library=False):
        args = ['xcrun', 'clang', '-target', arch + '-apple-ios13.0', '-isysroot', cls.sdk,
                '-Wl,-headerpad_max_install_names', str(source), '-o', str(destination)]
        if library:
            args += ['-dynamiclib', '-Wl,-install_name,/Library/Test/' + destination.name]
        subprocess.run(args, check=True, capture_output=True)

    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.root = Path(self.work.name)
        self.app = self.root / 'Test.app'; self.app.mkdir()
        (self.app / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable': 'Test'}))
        shutil.copyfile(self.fixtures / 'main-arm64', self.app / 'Test')
        self.dylib = self.root / '中文 probe.dylib'
        shutil.copyfile(self.fixtures / 'arm64.dylib', self.dylib)

    def tearDown(self):
        self.work.cleanup()

    def test_plain_injection_preserves_sources_and_adds_real_load_command(self):
        original = self.dylib.read_bytes()
        before = (self.app / 'Test').read_bytes()
        result = injection.inject(self.app, [self.dylib], substrate=False)
        after = (self.app / 'Test').read_bytes()
        self.assertEqual(self.dylib.read_bytes(), original)
        self.assertEqual(len(after), len(before))
        self.assertIn('@executable_path/UnfairplayedDylibs/' + self.dylib.name, injection.dylib_names(after, injection.slices(after)[0]))
        self.assertEqual([x['name'] for x in result['injected']], [self.dylib.name])
        first_data = injection.first_payload_offset(before, injection.slices(before)[0])
        self.assertEqual(before[first_data:], after[first_data:])
        copied = self.app / injection.DIRECTORY / self.dylib.name
        self.assertIn('@executable_path/UnfairplayedDylibs/' + self.dylib.name, injection.dylib_names(copied.read_bytes(), injection.slices(copied.read_bytes())[0], True))

    def test_modern_runtime_is_arm64_and_legacy_retains_both_slices(self):
        for mode, subtypes in [('modern', {0}), ('legacy', {0, 2})]:
            if (self.app / injection.DIRECTORY).exists():
                shutil.rmtree(self.app / injection.DIRECTORY)
            shutil.copyfile(self.fixtures / 'main-arm64', self.app / 'Test')
            injection.inject(self.app, [self.dylib], compatibility=mode)
            for name in injection.RUNTIME_NAMES:
                b = (self.app / injection.DIRECTORY / name).read_bytes()
                self.assertEqual({i['subtype'] & 0xffffff for i in injection.slices(b)}, subtypes)
                deps = [n for item in injection.slices(b) for n in injection.dylib_names(b, item)]
                self.assertFalse(any('iPatchDylibs' in n for n in deps))

    def test_all_fat_slices_receive_load_commands_without_moving_code(self):
        shutil.copyfile(self.fixtures / 'main-fat', self.app / 'Test')
        fatlib = self.root / 'Universal.dylib'
        subprocess.run(['xcrun', 'lipo', '-create', self.fixtures / 'arm64.dylib', self.fixtures / 'arm64e.dylib', '-output', fatlib], check=True, capture_output=True)
        before = (self.app / 'Test').read_bytes()
        injection.inject(self.app, [fatlib], substrate=False)
        after = (self.app / 'Test').read_bytes()
        for item in injection.slices(before):
            new = next(i for i in injection.slices(after) if i['offset'] == item['offset'])
            self.assertIn('@executable_path/UnfairplayedDylibs/Universal.dylib', injection.dylib_names(after, new))
            offset = item['offset'] + injection.first_payload_offset(before, item)
            end = item['offset'] + item['size']
            self.assertEqual(before[offset:end], after[offset:end])

    def test_insufficient_padding_never_changes_main_binary(self):
        for occupied in (False, True):
            shutil.copyfile(self.fixtures / 'main-arm64', self.app / 'Test')
            b = bytearray((self.app / 'Test').read_bytes())
            item = injection.slices(b)[0]
            end = 32 + item['command_size']
            if occupied:
                b[end + 30] = 0x41
            else:
                # Declared payload is zero-valued, but still must not be overwritten.
                for cmd, pos, length in item['commands']:
                    if cmd == 0x19 and struct.unpack_from('<I', b, pos + 64)[0]:
                        struct.pack_into('<I', b, pos + 72 + 48, end)
                        break
            (self.app / 'Test').write_bytes(b)
            with self.assertRaisesRegex(ValueError, '头部空间不足'):
                injection.add_load_commands(self.app / 'Test', ['@executable_path/UnfairplayedDylibs/Probe.dylib'])
            self.assertEqual((self.app / 'Test').read_bytes(), bytes(b))

    def test_non_ios_architecture_conflicts_and_duplicate_names_are_rejected(self):
        with self.assertRaisesRegex(ValueError, '架构'):
            injection.inject(self.app, [self.fixtures / 'arm64e.dylib'], substrate=False)
        with self.assertRaisesRegex(ValueError, '重复'):
            injection.inject(self.app, [self.dylib, self.dylib], substrate=False)
        runtime = self.root / 'libsubstrate.dylib'; shutil.copyfile(self.dylib, runtime)
        with self.assertRaisesRegex(ValueError, '冲突'):
            injection.inject(self.app, [runtime])
        mac = bytearray(self.dylib.read_bytes())
        for cmd, pos, _ in injection.slices(mac)[0]['commands']:
            if cmd == 0x32:
                struct.pack_into('<I', mac, pos + 8, 7)  # iOS simulator
        self.dylib.write_bytes(mac)
        with self.assertRaisesRegex(ValueError, '模拟器'):
            injection.inject(self.app, [self.dylib])
        self.assertFalse((self.app / injection.DIRECTORY).exists())

    def test_dependencies_between_selected_libraries_are_rebound(self):
        dependency = self.root / 'Dependency.dylib'; shutil.copyfile(self.dylib, dependency)
        source = self.root / 'dependent.c'; source.write_text('extern int injected_probe(void); int other(void) { return injected_probe(); }')
        dependent = self.root / 'Dependent.dylib'
        subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios13.0', '-isysroot', self.sdk, '-dynamiclib', '-Wl,-headerpad_max_install_names', source, dependency, '-o', dependent], check=True, capture_output=True)
        # Its input dependency install name comes from the original copied library.
        subprocess.run(['xcrun', 'install_name_tool', '-change', '/Library/Test/arm64.dylib', '/var/jb/usr/lib/Dependency.dylib', dependent], check=True, capture_output=True)
        injection.inject(self.app, [dependency, dependent], substrate=False)
        b = (self.app / injection.DIRECTORY / 'Dependent.dylib').read_bytes()
        self.assertIn('@loader_path/Dependency.dylib', injection.dylib_names(b, injection.slices(b)[0]))

    def test_invalid_fat_and_load_command_metadata_are_rejected(self):
        b = bytearray((self.app / 'Test').read_bytes())
        struct.pack_into('<I', b, 36, 0xfffffff8)
        with self.assertRaises(ValueError): injection.slices(b)
        with self.assertRaises(ValueError): injection.slices(b'\xca\xfe\xba\xbe\0\0\0\x20')
        with self.assertRaises(ValueError): injection.slices(b'not a Mach-O')

    def test_fat64_and_swapped_fat_headers_are_patched(self):
        images = [(self.fixtures / ('main-' + arch)).read_bytes() for arch in ('arm64', 'arm64e')]
        for endian, wide, magic in [('>', True, b'\xca\xfe\xba\xbf'), ('<', False, b'\xbe\xba\xfe\xca')]:
            offsets = [4096, (4096 + len(images[0]) + 4095) & ~4095]
            data = bytearray(offsets[1] + len(images[1]))
            data[:8] = magic + struct.pack(endian + 'I', 2)
            stride = 32 if wide else 20
            for index, (image, offset) in enumerate(zip(images, offsets)):
                cpu, subtype = struct.unpack_from('<II', image, 4)
                values = [cpu, subtype, offset, len(image), 12] + ([0] if wide else [])
                struct.pack_into(endian + ('IIQQII' if wide else 'IIIII'), data, 8 + stride * index, *values)
                data[offset:offset + len(image)] = image
            binary = self.app / 'Test'; binary.write_bytes(data)
            injection.add_load_commands(binary, ['@executable_path/UnfairplayedDylibs/Probe.dylib'])
            patched = binary.read_bytes()
            for item in injection.slices(patched):
                self.assertIn('@executable_path/UnfairplayedDylibs/Probe.dylib', injection.dylib_names(patched, item))

    def test_later_fat_slice_failure_does_not_write_an_earlier_slice(self):
        binary = self.app / 'Test'
        data = bytearray((self.fixtures / 'main-fat').read_bytes())
        second = injection.slices(data)[1]
        data[second['offset'] + 32 + second['command_size'] + 30] = 0x41
        binary.write_bytes(data)
        with self.assertRaisesRegex(ValueError, '头部空间不足'):
            injection.add_load_commands(binary, ['@executable_path/UnfairplayedDylibs/Probe.dylib'])
        self.assertEqual(binary.read_bytes(), bytes(data))

    def test_config_and_backend_pass_all_selected_paths_and_mode(self):
        paths = [str(self.dylib), str(self.root / 'path with spaces.dylib')]
        settings = dict(INJECTION_ENABLED='1', INJECTION_DYLIBS=json.dumps(paths), INJECTION_SUBSTRATE='0', INJECTION_COMPATIBILITY='legacy')
        backend.save_config(self.root, 'ABCDEFGHIJ', 'dev.example.helper', '', settings)
        saved = backend.read_config(self.root)
        self.assertEqual(json.loads(saved['INJECTION_DYLIBS']), paths)
        self.assertEqual(saved['INJECTION_COMPATIBILITY'], 'legacy')
        with self.assertRaises(ValueError):
            backend.save_config(self.root, 'ABCDEFGHIJ', 'dev.example.helper', '', dict(INJECTION_DYLIBS='["relative.dylib"]'))
        (self.root / 'fpdecrypt.sh').touch()
        argv = ['backend.py', '--root', str(self.root), 'debug-install', '--ipa', str(self.root / 'input.ipa'), '--signer', 'xcode:ABCDEFGHIJ', '--injection-compatibility', 'legacy', '--no-injection-substrate']
        for path in paths: argv += ['--dylib', path]
        with patch.object(sys, 'argv', argv), patch.object(backend, 'require_device', return_value='phone'), patch.object(backend, 'run_job', return_value=0) as job:
            backend.main()
        args = job.call_args.args[0]
        self.assertEqual([args[i + 1] for i, a in enumerate(args) if a == '--dylib'], paths)
        self.assertIn('--no-injection-substrate', args)
        self.assertEqual(args[args.index('--injection-compatibility') + 1], 'legacy')
