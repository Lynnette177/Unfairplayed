"""Native file-backed task logging regressions."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class TaskLogTests(unittest.TestCase):
    def test_complete_logs_survive_tail_limits_failures_retries_and_restart(self):
        source = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / 'logs-test'
            p = subprocess.run(['xcrun', 'swiftc', '-swift-version', '5', '-parse-as-library',
                                str(source / 'TaskLogStore.swift'), str(source / 'test_task_logs.swift'),
                                '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            p = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn('checks passed', p.stdout)
