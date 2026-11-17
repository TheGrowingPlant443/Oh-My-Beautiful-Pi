"""Portable VM contracts: resource bounds, effective isolation and real snapshot extraction."""
import copy
import hashlib
import resource
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import socket
import time
import threading
from unittest.mock import Mock, patch
import tarfile
import tempfile
import unittest

from macos_runtime import (GIB, default_resources, validate_resources, verify_config,
                           prepare_lima_home, write_tree, _excluded_source, GuestSession, VmBackend, VmRun)
from policy import Policy, new_keyring_unlock
from runtime import Cancelled, OwnedChildren
from vm.guest import (discovery_home, extract_snapshot, GuestPolicy, installation_settings, prepare_descriptor_limit,
                      retire_engine_sockets, Layout, Supervisor, receive_omp_copy)
from vm.fetch_image import fetch
from vm import emulation


class ResourcesTests(unittest.TestCase):
    def test_defaults_leave_host_memory(self):
        self.assertEqual(default_resources(12, 16), {"cpus": 6, "memory_gib": 10, "disk_gib": 64})
        self.assertEqual(default_resources(2, 8), {"cpus": 2, "memory_gib": 4, "disk_gib": 64})
        with self.assertRaises(ValueError):
            default_resources(4, 7)

    def test_exact_schema_and_host_bounds(self):
        valid = default_resources(12, 16)
        for change in ({"cpus": True}, {"cpus": 13}, {"memory_gib": 13}, {"memory_gib": 3},
                       {"disk_gib": 31}, {"unknown": 1}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "vm.json"):
                validate_resources({**valid, **change}, 12, 16, "state/vm.json")
        self.assertEqual(validate_resources(valid, 12, 16, "vm.json"), valid)

    def test_guest_descriptor_floor_preserves_hard_limit(self):
        with patch("vm.guest.resource.getrlimit", return_value=(1024, 1048576)), \
                patch("vm.guest.resource.setrlimit") as change:
            prepare_descriptor_limit()
            change.assert_called_once_with(resource.RLIMIT_NOFILE, (65536, 1048576))
        with patch("vm.guest.resource.getrlimit", return_value=(131072, 1048576)), \
                patch("vm.guest.resource.setrlimit") as change:
            prepare_descriptor_limit()
            change.assert_not_called()
        with patch("vm.guest.resource.getrlimit", return_value=(1024, 4096)), \
                patch("vm.guest.resource.setrlimit") as change:
            with self.assertRaisesRegex(RuntimeError, "guest supervisor needs a NOFILE"):
                prepare_descriptor_limit()
            change.assert_not_called()

    def test_image_digest_is_checked_before_use(self):
        payload = b"pinned image bytes"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            for expected in (digest, "0" * 64):
                response = io.BytesIO(payload)
                response.url = "https://example.invalid/pinned.img"
                destination = Path(directory) / expected
                with patch("vm.fetch_image.urllib.request.urlopen", return_value=response):
                    if expected == digest:
                        fetch(response.url, expected, destination)
                        self.assertEqual(destination.read_bytes(), payload)
                        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
                    else:
                        with self.assertRaisesRegex(ValueError, "mandatory pin"):
                            fetch(response.url, expected, destination)

    def test_emulation_is_guest_only_and_never_preserves_privileges(self):
        with patch("vm.emulation.os.geteuid", return_value=0), \
                patch("vm.emulation.platform.system", return_value="Darwin"):
            with self.assertRaisesRegex(RuntimeError, "only inside the owned Linux guest"):
                emulation.provision()
        fields = emulation.registration("/nix/store/pinned/bin/qemu-x86_64").split(":")
        self.assertEqual(fields[1:4], ["ombp-x86_64", "M", "0"])
        self.assertEqual(fields[-1], "F")
        self.assertEqual(len(emulation.MAGIC), len(emulation.MASK))
        self.assertEqual(emulation.MAGIC[18:20], b"\x3e\x00")
        with tempfile.NamedTemporaryFile() as outside:
            with self.assertRaisesRegex(ValueError, "pinned Nix runtime"):
                emulation.static_interpreter(outside.name)

    def test_effective_config_refuses_mount_forward_and_agent(self):
        resources = default_resources(12, 16)
        instance = {"vmType": "vz", "arch": "aarch64", "cpus": 6, "memory": 10 * GIB, "disk": 64 * GIB,
                    "config": {"vmType": "vz", "arch": "aarch64", "containerd": {"system": False, "user": False},
                               "ssh": dict.fromkeys(("forwardAgent", "forwardX11", "forwardX11Trusted",
                                                     "loadDotSSHPubKeys"), False),
                               "propagateProxyEnv": False, "plain": False,
                               "vmOpts": {"vz": {"rosetta": {"enabled": False}}},
                               "portForwards": [{"ignore": True, "guestIP": "0.0.0.0", "proto": "any",
                                                 "guestIPMustBeZero": False}]}}
        verify_config(instance, "aarch64", resources)
        for key, value in (("mounts", [{"location": "~"}]), ("containerd", {"system": False, "user": True}),
                           ("ssh", {"forwardAgent": True}), ("portForwards", []),
                           ("portForwards", [{"ignore": True, "guestIP": "0.0.0.0", "proto": "any",
                                              "guestIPMustBeZero": True}])):
            bad = copy.deepcopy(instance)
            bad["config"][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                verify_config(bad, "aarch64", resources)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_saved_new_files_unicode_links_and_filters(self):
        source = self.root / "source"
        source.mkdir()
        (source / "new saved ø.txt").write_text("uncommitted content")
        (source / "link").symlink_to("new saved ø.txt")
        for name in ("node_modules", ".git", "target", "worktrees"):
            (source / name).mkdir()
            (source / name / "excluded").write_text("no")
        archive = io.BytesIO()
        write_tree(archive, source, _excluded_source)
        archive.seek(0)
        out = self.root / "received"
        extract_snapshot(archive, out)
        self.assertEqual((out / "link").read_text(), "uncommitted content")
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["link", "new saved ø.txt"])

    def test_sender_refuses_escaping_links_and_special_files(self):
        source = self.root / "source"
        source.mkdir()
        (source / "escape").symlink_to("../outside")
        with self.assertRaises(ValueError):
            write_tree(io.BytesIO(), source, _excluded_source)
        (source / "escape").unlink()
        os.mkfifo(source / "fifo")
        with self.assertRaises(ValueError):
            write_tree(io.BytesIO(), source, _excluded_source)

    def test_receiver_refuses_path_traversal_and_parent_symlink(self):
        for index, (name, kind, target) in enumerate((("../outside", tarfile.REGTYPE, ""),
                                                    ("/outside", tarfile.REGTYPE, ""),
                                                    ("link", tarfile.SYMTYPE, "../outside"),
                                                    ("hardlink", tarfile.LNKTYPE, "file"))):
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w") as tar:
                entry = tarfile.TarInfo(name)
                entry.type, entry.linkname = kind, target
                tar.addfile(entry)
            archive.seek(0)
            with self.subTest(name=name), self.assertRaises(ValueError):
                extract_snapshot(archive, self.root / str(index))
        self.assertFalse((self.root / "outside").exists())


class RecoverySocketTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path("/tmp").resolve())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for relative in ("engine", "engine/api", "engine/upstream"):
            (self.root / relative).mkdir(mode=0o700)
        self.path = self.root / "engine/api/podman.sock"

    def test_dead_owned_socket_is_retired_without_removing_data(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.bind(str(self.path))
        saved = self.root / "engine/saved-data"
        saved.write_text("preserve")
        retire_engine_sockets(self.root)
        self.assertFalse(self.path.exists())
        self.assertEqual(saved.read_text(), "preserve")
        retire_engine_sockets(self.root)

    def test_live_socket_and_non_socket_objects_are_not_replaced(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.bind(str(self.path))
            sock.listen()
            with self.assertRaisesRegex(RuntimeError, "still live"):
                retire_engine_sockets(self.root)
            self.assertTrue(self.path.is_socket())
        self.path.unlink()
        self.path.write_text("not a socket")
        with self.assertRaisesRegex(RuntimeError, "unexpected engine socket object"):
            retire_engine_sockets(self.root)
        self.assertEqual(self.path.read_text(), "not a socket")
        self.path.unlink()
        self.path.symlink_to(self.root / "elsewhere")
        with self.assertRaisesRegex(RuntimeError, "unexpected engine socket object"):
            retire_engine_sockets(self.root)
        self.assertTrue(self.path.is_symlink())


class ProjectionTests(unittest.TestCase):
    def test_unchanged_programs_do_not_resolve_during_revocation_or_load(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            program = "/nix/store/" + "a" * 32 + "-linux/bin/tool"
            policy = Policy(Path(directory) / "state", program_resolver=lambda p: calls.append(p) or program)
            data = policy.snapshot()
            data["programs"] = ["tool"]
            policy.replace(data)
            self.assertEqual(calls, ["tool"])
            data = policy.snapshot()
            data["folders"] = []
            policy.replace(data)
            self.assertEqual(calls, ["tool"])
            loaded = Policy(policy.directory, program_resolver=lambda p: self.fail("resolved saved program"))
            self.assertEqual(loaded.snapshot()["programs"], [program])

    def test_guest_applies_generations_without_resolving_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = GuestPolicy(Path(directory), lambda event: None)
            projection = {"programs": [], "disabled_requirements": [], "folders": []}
            self.assertEqual(policy.apply(3, projection), 3)
            with self.assertRaisesRegex(ValueError, "Stale"):
                policy.apply(2, projection)
            self.assertEqual(policy.generation, 3)


class InstallationTransportTests(unittest.TestCase):
    def backend(self, directory):
        backend = object.__new__(VmBackend)
        # The real backend resolves new grants inside the VM; this saved grant is later unavailable there.
        backend.policy = Policy(Path(directory) / "state", program_resolver=lambda value: value)
        backend.lock = threading.Lock()
        backend.requirements = []
        return backend

    def test_command_lists_survive_persistence_and_installed_mode_ignores_inspection_revocations(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = self.backend(directory)
            backend._save_requirements([
                {"id": "package-gh", "label": "GitHub CLI", "path": "/nix/store/x-gh", "kind": "program",
                 "programs": ["gh", "gh"]},
                {"id": "sandbox-tools", "label": "Tools", "path": "/nix/store/x-tools", "kind": "program",
                 "programs": "rg"},
                {"id": "host-omp", "label": "OMP", "path": "/home/sandbox/.omp", "kind": "folder"},
                {"id": "nix-store", "label": "Store", "path": "/nix/store", "kind": "folder"},
                {"id": "sandbox-run", "label": "Run", "path": "/run", "kind": "folder"}])
            saved = json.loads((backend.policy.directory / "requirements.json").read_text())
            self.assertEqual([row.get("programs") for row in saved], [["gh"], None, None, None, None])
            self.assertIn("omp-copy", [row["id"] for row in saved])
            self.assertNotIn("host-omp", [row["id"] for row in saved])
            data = backend.policy.snapshot()
            data["disabled_requirements"] = ["package-gh", "nix-store", "sandbox-run"]
            backend.policy.replace(data)
            enabled = lambda rows: {row["id"]: row["enabled"] for row in rows}
            self.assertEqual(enabled(backend.requirements_status()),
                             {"package-gh": True, "sandbox-tools": True, "omp-copy": True,
                              "nix-store": True, "sandbox-run": False})
            inspection = {"installed_mode": False, "selected_packages": []}
            self.assertEqual(enabled(backend.requirements_status(inspection)),
                             {"package-gh": False, "sandbox-tools": True, "omp-copy": True,
                              "nix-store": False, "sandbox-run": False})

    def test_installed_launch_is_not_blocked_by_saved_inspection_programs(self):
        class Session:
            def request(self, action, **arguments):
                if action == "resolve_program":
                    return {"path": "/nix/store/" + "b" * 32 + "-other/bin/tool"}
                raise AssertionError(action)

        class Snapshotted(Exception):
            pass
        with tempfile.TemporaryDirectory() as directory:
            backend = self.backend(directory)
            data = backend.policy.snapshot()
            data["programs"] = ["/nix/store/" + "a" * 32 + "-gone/bin/tool"]
            backend.policy.replace(data)
            settings = {"source": directory, "mode": "container", "desktop": False, "gpu": "none", "agent": "omp"}
            with patch.object(backend, "prepare", return_value=Session()), \
                    patch.object(backend, "_send_snapshot", side_effect=Snapshotted):
                with self.assertRaises(Snapshotted):
                    backend.launch(settings, None, OwnedChildren(), lambda phase: None,
                                   installation={"installed_mode": True, "selected_packages": []})
                with self.assertRaisesRegex(ValueError, "not a Linux executable"):
                    backend.launch(settings, None, OwnedChildren(), lambda phase: None,
                                   installation={"installed_mode": False, "selected_packages": []})
            self.assertEqual(backend.policy.snapshot()["programs"], data["programs"])

    def test_guest_start_revalidates_installation_and_discovery_home(self):
        self.assertEqual(installation_settings({"installed_mode": True, "selected_packages": ["ssh", "gh", "ssh"],
                                                "keyboard_layout": "dk"}),
                         {"installed_mode": True, "selected_packages": ["gh", "ssh"], "keyboard_layout": "dk"})
        valid = {"installed_mode": True, "selected_packages": [], "keyboard_layout": "default"}
        for value in (None, {**valid, "installed_mode": 1}, {**valid, "selected_packages": ["/nix/store/x"]},
                      {**valid, "selected_packages": ["nixpkgs#hello"]}, {**valid, "extra": 1},
                      {"installed_mode": True, "selected_packages": []}, {**valid, "keyboard_layout": "us"},
                      {**valid, "keyboard_layout": "dk --socket=/tmp/x"}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                installation_settings(value)
        self.assertEqual(discovery_home("/host/Users/u"), "/host/Users/u")
        for value in ("/home/u", "/host/Users/../root", "/host/Users/u/", "/host//Users/u", "/host/Users/u\0",
                      "host/Users/u", 5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                discovery_home(value)


class PrivateOmpTransportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "host"
        self.source = self.home / ".omp"
        self.source.mkdir(parents=True)
        (self.source / "target").mkdir()
        (self.source / "target" / "session").write_text("private session")
        (self.source / ".git").mkdir()
        (self.source / ".git" / "config").write_text("local configuration")
        self.supervisor = object.__new__(Supervisor)
        self.supervisor.layout = Layout(self.root / "guest").create()
        self.supervisor.lock = threading.Lock()
        self.supervisor.phase = "idle"
        self.supervisor.run = None
        self.supervisor.omp_copy = None
        self.supervisor.policy = GuestPolicy(self.supervisor.layout.state, lambda event: None)
        self.supervisor.keyring_backend = Mock()
        self.key = new_keyring_unlock()
        self.backend = object.__new__(VmBackend)
        self.backend.policy = Policy(self.root / "host-state")
        self.backend.home = self.root / "lima"
        self.backend.wrapper = "/nix/store/test/bin/ombp-guest"
        self.backend._ssh = Mock(return_value=["owned-ssh"])
        self.backend.requirements = []
        self.backend.lock = threading.Lock()
        self.session = Mock()
        self.session.request.side_effect = self.request
        self.children = Mock()
        self.children.popen.side_effect = self.receiver
        self.log = io.BytesIO()
        self.sent = b""

    def tearDown(self):
        self.supervisor.cancel()

    def request(self, action, **args):
        args.pop("timeout", None)
        return getattr(self.supervisor, action)(args)

    def receiver(self, command, **kwargs):
        self.assertEqual(command[0], "owned-ssh")
        token = self.supervisor.omp_copy.token
        self.assertTrue(command[1].endswith("receive-omp-copy " + token))
        owner = self

        class Upload(io.BytesIO):
            def close(self):
                if not self.closed:
                    owner.sent = self.getvalue()
                    receive_omp_copy(owner.supervisor.layout, token, io.BytesIO(owner.sent))
                super().close()

        process = Mock()
        process.stdin = Upload()
        process.stdout = io.BytesIO(b"ok\n")
        process.returncode = 0
        self.transfer = process
        return process

    def copy(self):
        with patch("macos_runtime.Path.home", return_value=self.home), \
                patch("mac_network.keyring_unlock", return_value=self.key):
            self.backend._copy_omp(self.session, self.children, self.log)

    def begin(self, replace=False, request_id=None):
        return self.supervisor.omp_copy_begin(
            {"replace": replace, "request_id": request_id, "keyring_unlock": self.key})["token"]

    def request_recopy(self, request_id="a" * 32):
        pending = self.backend.policy.directory / "omp-recopy.json"
        pending.write_text(json.dumps({"replace_previous": True, "request_id": request_id}))
        pending.chmod(0o600)
        return pending

    def stage(self, token):
        from omp_copy import write_snapshot
        archive = io.BytesIO()
        write_snapshot(archive, self.source)
        data = archive.getvalue()
        receive_omp_copy(self.supervisor.layout, token, io.BytesIO(data))
        return hashlib.sha256(data).hexdigest()

    def test_full_copy_then_restart_preserves_guest_edits_without_reading_source(self):
        self.assertFalse(self.supervisor.omp_copy_status({})["copied"])
        self.copy()
        target = self.supervisor.layout.state / "home/.omp"
        self.assertEqual((target / ".git/config").read_text(), "local configuration")
        self.assertEqual((target / "target/session").read_text(), "private session")
        self.assertTrue(self.supervisor.omp_copy_status({})["copied"])
        self.session.request.assert_any_call("omp_copy_begin", replace=False, request_id=None,
                                             keyring_unlock=self.key)
        (target / "target/session").write_text("guest edit")
        with patch("macos_runtime.write_snapshot", side_effect=AssertionError("source read")), \
                patch("macos_runtime.Path.home", side_effect=AssertionError("home inspected")):
            self.backend._copy_omp(self.session, self.children, self.log)
        self.assertEqual((target / "target/session").read_text(), "guest edit")
        self.children.adopt.assert_called_once_with(self.session.process, group=True)
        self.children.release.assert_called_once_with(self.session.process)
        self.assertNotIn(b"private session", self.log.getvalue())

    def test_keyring_validation_precedes_staging_and_home_creation(self):
        def validate(key):
            self.assertEqual(key, self.key)
            self.assertIsNone(self.supervisor.omp_copy)
            self.assertFalse((self.supervisor.layout.state / "home").exists())
            self.children.popen.assert_not_called()

        self.supervisor.keyring_backend._keyring_password.side_effect = validate
        self.copy()
        self.supervisor.keyring_backend._keyring_password.assert_called_once_with(self.key)

    def test_initial_copy_preserves_existing_authorized_guest_omp(self):
        target = self.supervisor.layout.state / "home/.omp"
        target.mkdir(parents=True)
        (target / "existing").write_text("existing guest session")
        self.copy()
        self.assertEqual((target.with_name(".omp.previous") / "existing").read_text(), "existing guest session")
        self.assertEqual((target / "target/session").read_text(), "private session")

    def test_missing_host_source_is_marked_copied_and_never_overwritten_on_restart(self):
        self.source.rename(self.home / "elsewhere")
        self.copy()
        target = self.supervisor.layout.state / "home/.omp"
        self.assertTrue(self.supervisor.omp_copy_status({})["copied"])
        self.assertEqual(list(target.iterdir()), [])
        (target / "new-session").write_text("guest session")
        with patch("macos_runtime.write_snapshot", side_effect=AssertionError("repeated copy")):
            self.copy()
        self.assertEqual((target / "new-session").read_text(), "guest session")

    def test_explicit_recopy_consumes_receipt_only_after_success_and_replaces_backup(self):
        self.copy()
        target = self.supervisor.layout.state / "home/.omp"
        (target / "target/session").write_text("previous guest edit")
        previous = target.with_name(".omp.previous")
        previous.mkdir()
        (previous / "obsolete").write_text("older backup")
        pending = self.request_recopy()
        (self.source / "target/session").write_text("new host data")
        self.copy()
        self.assertFalse(pending.exists())
        self.assertEqual((target / "target/session").read_text(), "new host data")
        self.assertEqual((previous / "target/session").read_text(), "previous guest edit")
        self.assertFalse((previous / "obsolete").exists())
        self.assertEqual(self.supervisor.omp_copy_status({})["request_id"], "a" * 32)
        self.session.request.assert_any_call("omp_copy_begin", replace=True, request_id="a" * 32,
                                             keyring_unlock=self.key)

    def assert_recopy_replay_preserves_previous(self, interrupted):
        self.copy()
        target = self.supervisor.layout.state / "home/.omp"
        previous = target.with_name(".omp.previous")
        (target / "target/session").write_bytes(b"original guest edits\x00\xff")
        (target / "guest-only").write_bytes(b"must survive recopy retry")

        def contents(directory):
            return {path.relative_to(directory): path.read_bytes()
                    for path in directory.rglob("*") if path.is_file()}

        original = contents(target)
        pending = self.request_recopy()
        (self.source / "target/session").write_text("new host snapshot")
        replace = os.replace

        def interrupt_receipt(source, destination, **kwargs):
            if source == "receipt" and destination == "omp-copy.json":
                raise OSError("interrupted receipt publication")
            return replace(source, destination, **kwargs)

        def lose_acknowledgement(action, **args):
            result = self.request(action, **args)
            if action == "omp_copy_commit":
                raise OSError("lost successful commit acknowledgement")
            return result

        fault = (patch("omp_copy.os.replace", side_effect=interrupt_receipt) if interrupted else
                 patch.object(self.session, "request", side_effect=lose_acknowledgement))
        with fault, patch("macos_runtime.terminate"), self.assertRaises(OSError):
            self.copy()
        self.assertEqual(json.loads(pending.read_text()),
                         {"replace_previous": True, "request_id": "a" * 32})
        self.assertEqual((self.supervisor.layout.state / ".omp-copy-pending.json").exists(), interrupted)
        self.assertEqual(contents(previous), original)
        self.assertEqual((target / "target/session").read_text(), "new host snapshot")
        (target / "target/session").write_text("guest edits after publication")
        self.session.request.reset_mock()
        self.children.popen.reset_mock()
        with patch("macos_runtime.write_snapshot", side_effect=AssertionError("source read")), \
                patch("macos_runtime.Path.home", side_effect=AssertionError("home inspected")):
            self.backend._copy_omp(self.session, self.children, self.log)
        self.session.request.assert_called_once_with("omp_copy_status")
        self.children.popen.assert_not_called()
        self.assertFalse(pending.exists())
        self.assertFalse((self.supervisor.layout.state / ".omp-copy-pending.json").exists())
        self.assertEqual(self.supervisor.omp_copy_status({})["request_id"], "a" * 32)
        self.assertEqual(contents(previous), original)
        self.assertEqual((target / "target/session").read_text(), "guest edits after publication")

        latest = contents(target)
        pending = self.request_recopy("b" * 32)
        (self.source / "target/session").write_text("next explicit snapshot")
        self.copy()
        self.assertFalse(pending.exists())
        self.assertEqual(self.supervisor.omp_copy_status({})["request_id"], "b" * 32)
        self.assertEqual(contents(previous), latest)
        self.assertEqual((target / "target/session").read_text(), "next explicit snapshot")

    def test_lost_successful_commit_acknowledgement_does_not_repeat_recopy(self):
        self.assert_recopy_replay_preserves_previous(interrupted=False)

    def test_interrupted_intent_recovers_on_next_status_without_repeating_recopy(self):
        self.assert_recopy_replay_preserves_previous(interrupted=True)

    def test_begin_rejects_inconsistent_or_invalid_request_identity(self):
        for replace, request_id in ((True, None), (True, ""), (True, "A" * 32),
                                    (True, "a" * 31), (True, 1), (False, "a" * 32),
                                    (1, "a" * 32)):
            with self.subTest(replace=replace, request_id=request_id), self.assertRaises(ValueError):
                self.begin(replace, request_id)
        self.assertIsNone(self.supervisor.omp_copy)
        self.assertEqual(self.supervisor.phase, "idle")
        self.supervisor.keyring_backend._keyring_password.assert_not_called()
        self.assertEqual(list(self.supervisor.layout.root.glob("omp-incoming-*")), [])

    def test_invalid_pending_request_is_not_upgraded_or_consumed(self):
        self.copy()
        pending = self.backend.policy.directory / "omp-recopy.json"
        for value in ({"replace_previous": True}, {"replace_previous": True, "request_id": "invalid"}):
            with self.subTest(value=value):
                pending.write_text(json.dumps(value))
                pending.chmod(0o600)
                with patch("macos_runtime.Path.home", side_effect=AssertionError("home inspected")), \
                        self.assertRaises(ValueError):
                    self.backend._copy_omp(self.session, self.children, self.log)
                self.assertEqual(json.loads(pending.read_text()), value)

    def test_failed_transfer_never_commits_or_consumes_recopy(self):
        pending = self.request_recopy()
        self.children.release.side_effect = Cancelled("cancelled release")
        with patch("macos_runtime.write_snapshot", side_effect=Cancelled("cancelled")), \
                patch("macos_runtime.terminate"):
            with self.assertRaises(Cancelled):
                self.copy()
        self.assertTrue(pending.exists())
        self.assertEqual(json.loads(pending.read_text())["request_id"], "a" * 32)
        self.assertFalse(self.supervisor.omp_copy_status({})["copied"])
        self.assertEqual(self.supervisor.phase, "idle")
        self.assertNotIn("omp_copy_commit", [call.args[0] for call in self.session.request.call_args_list])
        self.assertTrue(self.transfer.stdin.closed)
        self.assertTrue(self.transfer.stdout.closed)

    def test_staged_archive_requires_live_session_commit_and_matching_digest(self):
        token = self.begin()
        digest = self.stage(token)
        self.assertFalse(self.supervisor.omp_copy_status({})["copied"])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.supervisor.omp_copy_commit({"token": token, "digest": "0" * 64})
        self.assertFalse(self.supervisor.omp_copy_status({})["copied"])
        with self.assertRaisesRegex(ValueError, "no longer owned"):
            self.supervisor.omp_copy_commit({"token": token, "digest": digest})

    def test_cancellation_invalidates_receiver_and_stale_commit(self):
        token = self.begin()
        digest = self.stage(token)
        self.supervisor.cancel()
        with self.assertRaises(OSError):
            receive_omp_copy(self.supervisor.layout, token, io.BytesIO(b"stale"))
        with self.assertRaisesRegex(ValueError, "no longer owned"):
            self.supervisor.omp_copy_commit({"token": token, "digest": digest})
        self.assertFalse(self.supervisor.omp_copy_status({})["copied"])

    def test_copy_cannot_race_active_guest_or_another_copy(self):
        self.supervisor.phase = "running"
        with self.assertRaisesRegex(ValueError, "idle"):
            self.begin()
        self.supervisor.phase = "idle"
        self.begin()
        with self.assertRaisesRegex(ValueError, "idle"):
            self.begin()
        snapshot_id = "b" * 32
        (self.supervisor.layout.snapshots / snapshot_id).mkdir()
        with self.assertRaisesRegex(ValueError, "already copying"):
            self.supervisor.start({
                "source_snapshot_id": snapshot_id, "desktop": False, "gpu": "none", "agent": "omsp",
                "keyring_unlock": self.key, "proxy_ca": "not used", "workspace": None,
                "installation": {"installed_mode": True, "selected_packages": [], "keyboard_layout": "default"},
                "git_discovery_home": "/host/Users/example"})

    def test_stop_during_install_checks_cancellation_before_publish(self):
        token = self.begin()
        digest = self.stage(token)

        def interrupted(stream, state, replace, request_id, check):
            self.assertEqual(state, self.supervisor.layout.state)
            self.assertIsNone(request_id)
            self.supervisor.cancel()
            check()
            self.fail("installation survived cancellation")

        with patch("vm.guest.install_snapshot", side_effect=interrupted), self.assertRaises(Cancelled):
            self.supervisor.omp_copy_commit({"token": token, "digest": digest})
        self.assertFalse(self.supervisor.omp_copy_status({})["copied"])
        self.assertEqual(self.supervisor.phase, "idle")

    def test_keyring_validation_failure_prevents_initial_copy(self):
        home = self.supervisor.layout.state / "home"
        home.mkdir()
        (home / "existing").write_text("private")
        self.supervisor.keyring_backend._keyring_password.side_effect = ValueError("no keyring unlock key")
        with self.assertRaisesRegex(ValueError, "no keyring unlock key"):
            self.begin()
        self.assertIsNone(self.supervisor.omp_copy)
        self.supervisor.keyring_backend._keyring_password.assert_called_once_with(self.key)
        self.assertEqual((home / "existing").read_text(), "private")

    def test_missing_legacy_requirement_is_added_and_cannot_be_revoked(self):
        self.backend._save_requirements([])
        self.assertEqual([row["id"] for row in self.backend.requirements_status()], ["omp-copy"])
        data = self.backend.policy.snapshot()
        data["disabled_requirements"] = ["omp-copy", "host-omp"]
        self.backend.policy.replace(data)
        self.assertTrue(self.backend.requirements_status()[0]["enabled"])

    def test_overlapping_host_state_is_rejected_before_sending(self):
        self.backend.policy = Policy(self.source / "launcher-state")
        with self.assertRaisesRegex(ValueError, "must not overlap"):
            self.copy()
        self.children.popen.assert_not_called()

    def test_overlapping_vm_state_is_rejected_before_sending(self):
        self.backend.home = self.source / "vm"
        with self.assertRaisesRegex(ValueError, "must not overlap"):
            self.copy()
        self.children.popen.assert_not_called()


class FailureBoundaryTests(unittest.TestCase):
    def test_old_run_events_cannot_finish_a_new_workload(self):
        backend = object.__new__(VmBackend)
        backend.run = VmRun()
        backend._on_event({"event": "exited", "run": 1, "error": "old"})
        self.assertFalse(backend.run.workload.done.is_set())
        self.assertEqual(backend.run.events.get_nowait()["run"], 1)
        backend.run.guest_run = 2
        backend._on_event({"event": "exited", "run": 1, "error": "old"})
        self.assertTrue(backend.run.events.empty())
        self.assertFalse(backend.run.workload.done.is_set())
        backend._on_event({"event": "exited", "run": 2, "error": "current"})
        self.assertTrue(backend.run.workload.done.is_set())
        self.assertEqual(backend.run.workload.error, "current")

    def test_pending_supervisor_handshake_is_owned_and_cancelled(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryFile() as log:
            marker = Path(directory) / "ready"
            children, failures = OwnedChildren(), []
            code = "import pathlib,sys,time; pathlib.Path(sys.argv[1]).touch(); time.sleep(60)"
            def connect():
                try:
                    GuestSession([sys.executable, "-c", code, str(marker)],
                                 lambda e: None, log, lambda s: None, children=children)
                except RuntimeError as error:
                    failures.append(str(error))
            thread = threading.Thread(target=connect)
            thread.start()
            try:
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(marker.exists())
                children.cancel(grace=1)
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
                self.assertTrue(failures)
            finally:
                children.retire()
                thread.join(timeout=5)

    def test_prepared_session_transfers_from_operation_to_backend(self):
        code = ("import json,struct,sys; b=json.dumps({'event':'hello'}).encode(); "
                "sys.stdout.buffer.write(struct.pack('>I',len(b))+b); sys.stdout.buffer.flush(); sys.stdin.buffer.read()")
        children = OwnedChildren()
        with tempfile.TemporaryFile() as log:
            session = GuestSession([sys.executable, "-c", code], lambda e: None, log, lambda s: None,
                                   children=children)
            try:
                children.release(session.process)
                children.retire()
                self.assertIsNone(session.process.poll())
            finally:
                session.close()

    def test_ssh_child_retires_after_controller_sigkill(self):
        helper = Path(__file__).parent / "vm/owned_ssh.py"
        child = ("import signal,sys; "
                 "signal.signal(signal.SIGTERM, lambda *_: (print('retired',flush=True),sys.exit(0))); "
                 "print('ready',flush=True); signal.pause()")
        parent_code = ("import os,subprocess,sys,time; "
                       "subprocess.Popen([sys.executable,sys.argv[1],str(os.getpid()),sys.executable,'-c',sys.argv[2]]); "
                       "time.sleep(60)")
        parent = subprocess.Popen([sys.executable, "-B", "-c", parent_code, str(helper), child],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(parent.stdout.readline().strip(), "ready")
            parent.kill()
            output, error = parent.communicate(timeout=5)
            self.assertEqual(output.strip(), "retired", error)
        finally:
            if parent.poll() is None:
                parent.kill()
            parent.communicate(timeout=5)

    def test_control_write_backpressure_is_inside_request_deadline(self):
        # A real framed child announces itself, then stops consuming stdin altogether.
        child = ("import json,struct,sys,time; b=json.dumps({'event':'hello'}).encode(); "
                 "sys.stdout.buffer.write(struct.pack('>I',len(b))+b); sys.stdout.buffer.flush(); time.sleep(60)")
        with tempfile.TemporaryFile() as log:
            session = GuestSession([sys.executable, "-c", child], lambda e: None, log, lambda s: None)
            try:
                started = time.monotonic()
                with self.assertRaises(TimeoutError):
                    session.request("policy", timeout=0.2, projection="x" * 900_000)
                self.assertLess(time.monotonic() - started, 2)
            finally:
                session.close()

    def test_emergency_retirement_finishes_before_workload_completion(self):
        backend = object.__new__(VmBackend)
        backend.session = None
        run = VmRun()
        reached, release = threading.Event(), threading.Event()
        def force_stop():
            reached.set()
            self.assertTrue(release.wait(5))
        def revoke(active):
            active.revoked = True
        backend._revoke = revoke
        backend._force_stop_vm = force_stop
        thread = threading.Thread(target=backend._retire_unconfirmed, args=(run, "control lost"))
        thread.start()
        try:
            self.assertTrue(reached.wait(5))
            self.assertFalse(run.workload.done.is_set())
            self.assertFalse(run.retirement.acquire(blocking=False))
        finally:
            release.set()
            thread.join()
        self.assertTrue(run.workload.done.is_set())
        self.assertEqual(run.workload.error, "control lost")

    def test_stop_request_and_retirement_confirmation_share_one_deadline(self):
        clock, requests, forced = [0.0], [], []
        class Unresponsive:
            alive = True
            def request(self, action, timeout):
                requests.append((action, timeout))
                clock[0] += timeout
                raise TimeoutError("paused supervisor")
        backend = object.__new__(VmBackend)
        backend.session = Unresponsive()
        backend._revoke = lambda run: setattr(run, "revoked", True)
        backend._force_stop_vm = lambda: forced.append(clock[0])
        with patch("macos_runtime.time.monotonic", lambda: clock[0]):
            backend._retire_unconfirmed(VmRun(), "unacknowledged policy")
        self.assertEqual(requests, [("stop", 5), ("status", 5)])
        self.assertEqual(forced, [10])

    def test_directory_swap_never_archives_outside_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, outside = root / "source", root / "outside"
            source.mkdir()
            outside.mkdir()
            (source / "sub").mkdir()
            (outside / "secret").write_text("must not be transferred")
            original = os.fwalk
            def swapped(*args, **kwargs):
                for row in original(*args, **kwargs):
                    yield row
                    if Path(row[0]) == source:
                        (source / "sub").rmdir()
                        (source / "sub").symlink_to(outside, target_is_directory=True)
            archive = io.BytesIO()
            with patch("macos_runtime.os.fwalk", swapped):
                write_tree(archive, source, _excluded_source)
            archive.seek(0)
            with tarfile.open(fileobj=archive) as tar:
                self.assertNotIn("sub/secret", tar.getnames())

    def test_guest_reader_applies_policy_during_build_and_eof_retires_child(self):
        # Exercise the real supervisor protocol/worker/EOF path, replacing only the expensive Nix build
        # with an owned sleeping process. No container can start: EOF cancels this build first.
        fixture = """
import sys
from pathlib import Path
from vm.guest import Channel, Layout, Supervisor
class Building(Supervisor):
    def _build(self, run):
        child = run.children.popen([sys.executable, '-c', 'import time; time.sleep(60)'],
                                   stdout=self.log, stderr=self.log, start_new_session=True)
        self.emit({'event':'build-child','pid':child.pid})
        child.wait()
        run.children.check()
        raise RuntimeError('Unexpected build completion')
layout = Layout(Path(sys.argv[1])).create()
(layout.snapshots / ('a' * 32)).mkdir()
channel = Channel(sys.stdin.buffer, sys.stdout.buffer)
supervisor = Building(channel, layout)
channel.send({'event':'hello'})
supervisor.serve()
"""
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryFile() as log:
            seen, ready = [], threading.Event()
            def event(frame):
                if frame.get("event") == "build-child":
                    seen.append(frame["pid"])
                    ready.set()
            session = GuestSession([sys.executable, "-B", "-c", fixture, directory],
                                   event, log, lambda session: None)
            try:
                session.request("start", source_snapshot_id="a" * 32, desktop=False, gpu="none",
                                agent="omp", keyring_unlock="test", proxy_ca="test", workspace=None,
                                installation={"installed_mode": True, "selected_packages": ["gh"],
                                              "keyboard_layout": "default"},
                                git_discovery_home="/host/Users/u")
                self.assertTrue(ready.wait(5))
                self.assertEqual(session.request("status")["phase"], "building")
                self.assertEqual(session.request("policy", timeout=1, generation=4,
                                                projection={"programs": [], "folders": [],
                                                            "disabled_requirements": []}), {"applied": 4})
                started = time.monotonic()
            finally:
                session.close()
            self.assertLess(time.monotonic() - started, 5)
            with self.assertRaises(ProcessLookupError):
                os.kill(seen[0], 0)


if __name__ == "__main__":
    unittest.main()
