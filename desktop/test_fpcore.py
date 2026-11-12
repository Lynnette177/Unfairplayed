"""Native parser/acceptance regression without invoking device decryption APIs."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class CoreValidationTests(unittest.TestCase):
    def test_data_only_framework_and_rejected_invalid_candidates(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / 'core-test'
            source = Path(__file__).with_suffix('.c')
            compiled = subprocess.run(['xcrun', 'clang', '-std=c11', '-O2', str(source), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn('checks passed', result.stdout)
