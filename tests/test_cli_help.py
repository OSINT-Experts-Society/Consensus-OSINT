import subprocess
import sys
import unittest


class RootHelpTests(unittest.TestCase):
    def test_root_help_displays_command_reference(self):
        result = subprocess.run(
            [sys.executable, "-m", "consensus_osint.cli", "--help"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("consensus · help", result.stdout.lower())
        self.assertIn("scan", result.stdout.lower())
        self.assertNotIn("what would you like to do?", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
