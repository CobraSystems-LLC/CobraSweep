import os
import tempfile
import unittest
from pathlib import Path

from cobrasweep import (
    SweepError,
    SweepStats,
    guard_path,
    shred_file,
    sweep_target,
    SweepTarget,
)


class ShredTests(unittest.TestCase):
    def test_shred_removes_file_and_returns_size(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "secret.txt"
            payload = b"sensitive-bytes" * 1000
            target.write_bytes(payload)

            destroyed = shred_file(target, passes=1)

            self.assertEqual(destroyed, len(payload))
            self.assertFalse(target.exists())
            # Nothing shred-shaped should remain in the directory.
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_shred_refuses_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SweepError):
                shred_file(Path(tmp))

    def test_shred_refuses_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SweepError):
                shred_file(Path(tmp) / "nope.txt")


class GuardTests(unittest.TestCase):
    def test_refuses_root_and_home(self) -> None:
        with self.assertRaises(SweepError):
            guard_path(Path.home())
        if os.name == "posix":
            with self.assertRaises(SweepError):
                guard_path(Path("/"))
            with self.assertRaises(SweepError):
                guard_path(Path("/etc"))

    @unittest.skipUnless(os.name == "posix", "POSIX path rule")
    def test_refuses_posix_paths_outside_home_and_temp(self) -> None:
        with self.assertRaises(SweepError):
            guard_path(Path("/var/log/syslog"))

    def test_accepts_temp_and_home_children(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            resolved = guard_path(Path(tmp) / "file.txt")
            self.assertTrue(str(resolved).endswith("file.txt"))


class SweepTargetTests(unittest.TestCase):
    def test_dry_run_counts_but_keeps_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "a.tmp").write_bytes(b"x" * 10)
            (base / "b.tmp").write_bytes(b"y" * 20)
            target = SweepTarget(name="t", description="d", paths=[base])

            stats = sweep_target(target, shred=False, execute=False)

            self.assertEqual(stats.files_removed, 2)
            self.assertEqual(stats.bytes_freed, 30)
            self.assertTrue((base / "a.tmp").exists())  # dry run kept them

    def test_execute_removes_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            nested = base / "nested"
            nested.mkdir()
            (nested / "a.tmp").write_bytes(b"x" * 10)
            target = SweepTarget(name="t", description="d", paths=[base])

            stats = sweep_target(target, shred=False, execute=True)

            self.assertEqual(stats.files_removed, 1)
            self.assertEqual(list(base.iterdir()), [])

    def test_stats_merge(self) -> None:
        a = SweepStats(files_removed=1, bytes_freed=10, errors=["e1"])
        b = SweepStats(files_removed=2, bytes_freed=20, errors=["e2"])
        a.merge(b)
        self.assertEqual((a.files_removed, a.bytes_freed, a.errors), (3, 30, ["e1", "e2"]))


if __name__ == "__main__":
    unittest.main()
