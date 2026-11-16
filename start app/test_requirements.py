import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from requirements import FOLDERS, host_workspace, prepare_workspace, requirement_enabled


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'workspace'

    def test_creates_owner_only_directory_without_replacing_existing_data(self):
        prepare_workspace(self.path)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o700)
        marker = self.path / 'saved-session'
        marker.write_text('preserve')
        prepare_workspace(self.path)
        self.assertEqual(marker.read_text(), 'preserve')

    def test_rejects_symlinks_and_publicly_writable_directories(self):
        target = self.root / 'target'
        target.mkdir()
        self.path.symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError):
            prepare_workspace(self.path)
        self.path.unlink()
        self.path.mkdir(mode=0o777)
        self.path.chmod(0o777)
        with self.assertRaises(ValueError):
            prepare_workspace(self.path)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o777)

    def test_rejects_foreign_owned_directory(self):
        self.path.mkdir()
        metadata = SimpleNamespace(st_uid=os.getuid() + 1, st_mode=self.path.stat().st_mode)
        with patch('requirements.os.fstat', return_value=metadata), self.assertRaises(ValueError):
            prepare_workspace(self.path)

    def test_host_workspace_resolves_only_the_system_alias_parent(self):
        real = self.root / 'real'
        real.mkdir()
        alias = self.root / 'alias'
        alias.symlink_to(real, target_is_directory=True)
        (real / 'omp-manager').symlink_to(self.root, target_is_directory=True)
        path = host_workspace(alias)
        self.assertEqual(path, real.resolve() / 'omp-manager')
        self.assertTrue(path.is_symlink())
        with self.assertRaises(OSError):
            prepare_workspace(path)

    def test_private_omp_copy_is_not_a_revocable_host_mount(self):
        folders = {key: {"id": key, "label": label, "path": path, "kind": "folder"}
                   for key, label, path in FOLDERS}
        self.assertNotIn("host-omp", folders)
        self.assertEqual(folders["omp-copy"]["path"], "/home/sandbox/.omp")
        for installed in (False, True):
            self.assertTrue(requirement_enabled(folders["omp-copy"], installed, ["omp-copy", "host-omp"]))


if __name__ == '__main__':
    unittest.main()
