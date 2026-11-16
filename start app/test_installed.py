import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import installed
from runtime import Cancelled, NIX


def _coreutils():
    """GNU coreutils for real private copies; the Darwin devShell supplies them instead of BSD /usr/bin/cp."""
    return os.environ.get("START_APP_COREUTILS") or ("/usr/bin" if sys.platform.startswith("linux") else "")


class InstalledProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        coreutils = _coreutils()
        if not coreutils:
            raise AssertionError("Run in the launcher devShell: private copies need START_APP_COREUTILS (GNU cp)")
        version = subprocess.run([str(Path(coreutils) / "cp"), "--version"], check=True, text=True,
                                 capture_output=True).stdout
        if "GNU coreutils" not in version:
            raise AssertionError(f"{coreutils}/cp is not GNU coreutils")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = self.root / "source-store"
        self.store.mkdir()
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.core = self.package("core", "agent", b"agent-runtime")
        self.optional = self.package("optional", "language-server", b"optional-tool")
        self.dependency = self.package("dependency", "helper", b"runtime-library")
        self.copies = 0
        for change in (
            patch.object(installed, "_STORE_ROOT", re.compile(re.escape(str(self.store)) + r"/[^/]+\Z")),
            patch.object(installed, "store_root", side_effect=lambda value:
                         str(self.store / Path(value).relative_to(self.store).parts[0])),
            patch.dict(os.environ, {"START_APP_COREUTILS": _coreutils()}),
        ):
            change.start()
            self.addCleanup(change.stop)

    def package(self, name, command, content):
        root = self.store / name
        (root / "bin").mkdir(parents=True)
        program = root / "bin" / command
        program.write_bytes(content)
        program.chmod(0o755)
        return root

    def bundle(self, root):
        return {"roots": [str(root)], "primary_roots": [str(root)],
                "programs": [str(path) for path in (root / "bin").iterdir()]}

    def execute(self, argv, cwd=None):
        if argv[0] == "nix-store":
            return "\n".join(sorted(set(argv[3:]) | {str(self.dependency)})) + "\n"
        self.copies += 1
        return subprocess.run(argv, cwd=cwd, check=True, text=True, capture_output=True).stdout

    def install(self, bundles, run=None, cancel=lambda: None):
        return installed.install_profile(self.state, bundles, run or self.execute, cancel)

    def test_private_copy_keeps_dependencies_but_not_unrelated_store_entries(self):
        unrelated = self.package("unrelated", "secret-tool", b"not-selected")
        profile = self.install({"core": self.bundle(self.core)})
        self.assertEqual((profile / "store/core/bin/agent").read_bytes(), b"agent-runtime")
        self.assertEqual((profile / "store/dependency/bin/helper").read_bytes(), b"runtime-library")
        self.assertFalse((profile / "store" / unrelated.name).exists())
        self.assertEqual(os.readlink(profile / "programs/agent"), str(self.core / "bin/agent"))
        self.assertNotEqual((profile / "store/core/bin/agent").stat().st_ino,
                            (self.core / "bin/agent").stat().st_ino)
        (profile / "store/core/bin/agent").write_bytes(b"private-copy")
        self.assertEqual((self.core / "bin/agent").read_bytes(), b"agent-runtime")

    def test_deselection_uses_a_new_generation_and_same_selection_reuses_cache(self):
        selected = {"core": self.bundle(self.core), "optional": self.bundle(self.optional)}
        first = self.install(selected)
        self.assertEqual(self.install(selected), first)
        self.assertEqual(self.copies, 1)
        second = self.install({"core": self.bundle(self.core)})
        self.assertNotEqual(first, second)
        self.assertTrue((first / "store/optional/bin/language-server").exists())
        self.assertFalse((second / "store/optional").exists())
        self.assertFalse((second / "programs/language-server").exists())
        self.assertTrue((second / "store/dependency/bin/helper").exists())

    def test_lexical_wrapper_root_is_not_lost_when_commands_are_symlinks(self):
        profile_root = self.store / "profile"
        (profile_root / "bin").mkdir(parents=True)
        (profile_root / "bin/agent").symlink_to(self.core / "bin/agent")
        bundle = {"roots": [str(self.core)], "primary_roots": [str(profile_root)],
                  "programs": [str(profile_root / "bin/agent")]}
        profile = self.install({"agent": bundle})
        self.assertTrue((profile / "store/profile/bin/agent").is_symlink())
        self.assertTrue((profile / "store/core/bin/agent").is_file())

    def test_failed_copy_never_publishes_a_partial_installation(self):
        def fail(argv, cwd=None):
            if argv[0] == "nix-store":
                return self.execute(argv, cwd)
            destination = Path(argv[argv.index("--target-directory") + 1])
            (destination / "incomplete").write_bytes(b"partial")
            raise RuntimeError("copy failed")
        bundles = {"core": self.bundle(self.core)}
        with self.assertRaisesRegex(RuntimeError, "copy failed"):
            self.install(bundles, run=fail)
        self.assertEqual(list((self.state / "installed").iterdir()), [])
        self.assertEqual((self.core / "bin/agent").read_bytes(), b"agent-runtime")

    def test_cancelled_copy_never_publishes_and_preserves_prior_generation(self):
        previous = self.install({"core": self.bundle(self.core)})
        def cancel():
            raise RuntimeError("cancelled")
        bundles = {"core": self.bundle(self.core), "optional": self.bundle(self.optional)}
        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            self.install(bundles, cancel=cancel)
        self.assertEqual(list((self.state / "installed").iterdir()), [previous])
        self.assertEqual((previous / "store/core/bin/agent").read_bytes(), b"agent-runtime")

    def test_untrusted_or_incomplete_closure_is_rejected_before_copying(self):
        bundles = {"core": self.bundle(self.core)}
        for output in ("/home/user/private\n", str(self.dependency) + "\n"):
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, "closure"):
                self.install(bundles, run=lambda *args, **kwargs: output)
        self.assertEqual(self.copies, 0)
        self.assertFalse((self.state / "installed").exists())

    def test_symlinked_cache_and_changed_manifest_are_refused(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.state / "installed").symlink_to(outside)
        bundles = {"core": self.bundle(self.core)}
        with self.assertRaisesRegex(ValueError, "owner-only"):
            self.install(bundles)
        self.assertEqual(list(outside.iterdir()), [])
        (self.state / "installed").unlink()
        profile = self.install({"core": self.bundle(self.core)})
        (profile / "manifest.json").write_text(json.dumps({"version": 999}))
        with self.assertRaisesRegex(ValueError, "incomplete or changed"):
            self.install(bundles)

    def test_stop_during_closure_query_or_copy_never_publishes(self):
        previous = self.install({"core": self.bundle(self.core)})
        bundles = {"core": self.bundle(self.core), "optional": self.bundle(self.optional)}
        for stage in ("nix-store", "copy"):
            with self.subTest(stage=stage):
                stopped = []
                copies = self.copies

                def run(argv, cwd=None):
                    output = self.execute(argv, cwd)
                    if (argv[0] == "nix-store") == (stage == "nix-store"):
                        stopped.append(True)  # Stop arrives while this child is finishing.
                    return output

                def cancel():
                    if stopped:
                        raise Cancelled("Launch cancelled")

                with self.assertRaises(Cancelled):
                    self.install(bundles, run=run, cancel=cancel)
                self.assertEqual(self.copies, copies + (stage == "copy"))
                self.assertEqual(list((self.state / "installed").iterdir()), [previous])
        self.assertEqual((previous / "store/core/bin/agent").read_bytes(), b"agent-runtime")

    def test_first_bundle_wins_a_command_name(self):
        python = self.package("python-debugpy", "python3", b"debugpy-python")
        plain = self.package("python-core", "python3", b"core-python")
        profile = self.install({"debugpy": self.bundle(python), "core": self.bundle(plain)})
        self.assertEqual(os.readlink(profile / "programs/python3"), str(python / "bin/python3"))
        self.assertEqual((profile / "store/python-core/bin/python3").read_bytes(), b"core-python")


class BuildPackagesTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.launcher = Path(installed.__file__).parent

    def run_nix(self, argv, cwd=None):
        self.calls.append((argv, cwd))
        attribute = argv[argv.index("build") + 1].removeprefix("path:.#").removesuffix("^out")
        return f"/nix/store/{'a' * 32}-{attribute}\n"

    def built(self):
        return [(argv[argv.index("build") + 1], cwd) for argv, cwd in self.calls]

    def test_only_selected_outputs_build_with_fresh_nix_flags(self):
        checks = []
        agent, outputs = installed.build_packages(["ssh", "gh", "ssh"], "omsp", "/src", self.run_nix,
                                                  lambda: checks.append(True))
        self.assertEqual(agent, f"/nix/store/{'a' * 32}-agent-omsp")
        self.assertEqual(outputs, {key: f"/nix/store/{'a' * 32}-package-{key}" for key in ("gh", "ssh")})
        self.assertEqual(self.built(), [("path:.#agent-omsp^out", "/src"), ("path:.#package-gh^out", self.launcher),
                                        ("path:.#package-ssh^out", self.launcher)])
        self.assertTrue(all(tuple(argv[:len(NIX)]) == NIX for argv, _ in self.calls))
        self.assertEqual(len(checks), 3)

    def test_empty_selection_builds_only_the_agent(self):
        agent, outputs = installed.build_packages([], "omp", "/src", self.run_nix, lambda: None)
        self.assertEqual((agent, outputs), (f"/nix/store/{'a' * 32}-agent-omp", {}))
        self.assertEqual(self.built(), [("path:.#agent-omp^out", "/src")])

    def test_stop_after_a_build_prevents_further_builds(self):
        def cancel():
            raise Cancelled("Launch cancelled")
        with self.assertRaises(Cancelled):
            installed.build_packages(["gh", "ssh"], "omp", "/src", self.run_nix, cancel)
        self.assertEqual(self.built(), [("path:.#agent-omp^out", "/src")])

    def test_invalid_requests_build_nothing(self):
        for selected, agent in ((["/nix/store/tool"], "omp"), (["github:owner/repo"], "omp"), ("gh", "omp"),
                                (["gh"], "bash")):
            with self.subTest(selected=selected, agent=agent), self.assertRaises(ValueError):
                installed.build_packages(selected, agent, "/src", self.run_nix, lambda: None)
        self.assertEqual(self.calls, [])

    def test_output_must_be_exactly_one_store_path(self):
        for output in ("", f"/nix/store/{'a' * 32}-one\n/nix/store/{'b' * 32}-two\n", "/home/user/tool\n"):
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, "one Nix store output"):
                installed.build_packages([], "omp", "/src", lambda argv, cwd=None: output, lambda: None)


if __name__ == "__main__":
    unittest.main()
