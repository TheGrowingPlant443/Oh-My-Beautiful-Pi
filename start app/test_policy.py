import json
from pathlib import Path
import socket
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from policy import Policy, origin
from packages import DEFAULT_PACKAGES, validate_packages
from requirements import HOST_WORKSPACE, host_workspace


class OriginTests(unittest.TestCase):
    def test_subpaths_normalize_but_subdomains_remain_distinct(self):
        self.assertEqual(origin("https://EXAMPLE.com:443/v1/models?x=y"), "https://example.com")
        self.assertEqual(origin("http://example.com:8080/a"), "http://example.com:8080")
        self.assertNotEqual(origin("https://api.example.com"), origin("https://example.com"))

    def test_credentials_and_local_addresses_rejected(self):
        for value in ("ftp://example.com", "https://user:secret@example.com", "http://127.0.0.1",
                      "https://[::1]", "http://169.254.169.254", "http://localhost", "http://10.1.1.1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                origin(value)


class PackageTests(unittest.TestCase):
    def test_selection_is_canonical_and_can_be_empty(self):
        self.assertEqual(validate_packages(["ssh", "gh", "ssh"]), ["gh", "ssh"])
        self.assertEqual(validate_packages([]), [])
        self.assertEqual(validate_packages(["obsidian"]), ["obsidian"])

    def test_selection_rejects_nonlists_nonstrings_and_arbitrary_packages(self):
        for value in (None, "gh", ("gh",), {"gh": True}, [None], [1], [True], [{}], [[]],
                      ["not-a-supported-package"], ["pkgs.gh"], ["/nix/store/tool"], ["github:owner/repo"], ["GH"],
                      ["path:.#package-gh"], ["../gh"], ["gh\x00"]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_packages(value)

    def test_swift_choices_follow_the_isolated_linux_target(self):
        with patch("packages.SYSTEM", "aarch64-linux"):
            for value in (["sourcekit-lsp"], ["swift"], ["gh", "swift"]):
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, "aarch64-linux"):
                    validate_packages(value)
            self.assertEqual(validate_packages(["swiftlint"]), ["swiftlint"])
        with patch("packages.SYSTEM", "x86_64-linux"):
            self.assertEqual(validate_packages(["swift", "sourcekit-lsp"]), ["sourcekit-lsp", "swift"])


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = Policy(self.root / "state")
        self.folder = self.root / "vault"
        self.folder.mkdir()

    def test_installed_defaults_and_selection_persist_without_aliasing(self):
        initial = self.policy.snapshot()
        self.assertTrue(initial["installed_mode"])
        self.assertTrue(initial["hide_language_server_denials"])
        self.assertEqual(initial["selected_packages"], ["basic-tools", "chromium", "gh", "ssh"])
        initial["selected_packages"].clear()
        self.assertEqual(self.policy.snapshot()["selected_packages"], DEFAULT_PACKAGES)
        for mode, selection, expected in ((False, ["ssh", "gh", "ssh"], ["gh", "ssh"]),
                                           (True, [], []), (True, ["obsidian"], ["obsidian"])):
            with self.subTest(mode=mode, selection=selection):
                self.policy.replace({**self.policy.snapshot(), "installed_mode": mode,
                                     "selected_packages": selection})
                loaded = Policy(self.policy.directory).snapshot()
                self.assertEqual((loaded["installed_mode"], loaded["selected_packages"]), (mode, expected))
                self.assertEqual(json.loads(self.policy.path.read_text())["selected_packages"], expected)

    def test_installation_snapshot_is_a_fresh_copy_of_the_latest_choice(self):
        first = self.policy.installation()
        self.assertEqual(first, {"installed_mode": True, "selected_packages": DEFAULT_PACKAGES})
        first["selected_packages"].clear()
        first["installed_mode"] = False
        self.assertEqual(self.policy.installation(), {"installed_mode": True, "selected_packages": DEFAULT_PACKAGES})
        self.policy.replace({**self.policy.snapshot(), "selected_packages": ["ssh"]})
        self.assertEqual(self.policy.installation(), {"installed_mode": True, "selected_packages": ["ssh"]})
        self.assertEqual(first, {"installed_mode": False, "selected_packages": []})

    def test_legacy_policy_defaults_to_installed_without_losing_choices(self):
        folder = str(self.folder.resolve())
        launch = {"source": folder, "mode": "container", "desktop": True, "gpu": "none", "agent": "omsp"}
        self.policy.deny("program", "gopls", "Program is not selected")
        self.policy.deny("folder", "/private", "not shared")
        history = self.policy.events()
        legacy = self.policy.snapshot()
        for key in ("installed_mode", "selected_packages", "hide_language_server_denials"):
            del legacy[key]
        legacy.update(folders=[{"path": folder, "write": False}], programs=[f"/nix/store/{'a' * 32}-tool/bin/tool"],
                      websites=["https://example.com"], credential_origins=["https://example.com"],
                      disabled_requirements=["chromium"], internet=False, folder_write_default=True,
                      auto_start=launch)
        self.policy.save("policy.json", legacy)
        migrated = Policy(self.policy.directory)
        snapshot = migrated.snapshot()
        self.assertTrue(snapshot.pop("installed_mode"))
        self.assertEqual(snapshot.pop("selected_packages"), DEFAULT_PACKAGES)
        self.assertTrue(snapshot.pop("hide_language_server_denials"))
        self.assertEqual(snapshot, legacy)
        self.assertEqual(migrated.events(), history)
        migrated.replace(migrated.snapshot())
        self.assertTrue(json.loads(migrated.path.read_text())["installed_mode"])
        self.assertEqual(Policy(migrated.directory).snapshot(), migrated.snapshot())
        # An explicit saved choice, including no optional packages, is never replaced by the defaults.
        self.policy.save("policy.json", {**legacy, "selected_packages": []})
        self.assertEqual(Policy(self.policy.directory).installation(),
                         {"installed_mode": True, "selected_packages": []})

    def test_installation_and_history_view_changes_keep_authority_and_history(self):
        self.policy.deny("program", "gopls", "Program is not selected")
        self.policy.deny("website", "https://evil.test", "denied")
        history = self.policy.events()
        before = self.policy.snapshot()
        for change in ({"hide_language_server_denials": False}, {"hide_language_server_denials": True},
                       {"selected_packages": ["gopls"]}, {"selected_packages": []}, {"installed_mode": False}):
            with self.subTest(change=change):
                expected = {**before, **change}
                self.policy.replace(expected)
                loaded = Policy(self.policy.directory)
                self.assertEqual(loaded.snapshot(), expected)
                self.assertEqual(loaded.events(), history)

    def test_invalid_installed_settings_preserve_saved_policy(self):
        before = self.policy.snapshot()
        for field, bad in (("installed_mode", 1), ("installed_mode", "yes"), ("installed_mode", None),
                           ("selected_packages", "gh"), ("selected_packages", None), ("selected_packages", [False]),
                           ("selected_packages", ["gh", "unknown"]), ("selected_packages", ["/nix/store/tool"]),
                           ("selected_packages", ["github:owner/repo"]),
                           ("hide_language_server_denials", "yes"), ("hide_language_server_denials", None),
                           ("hide_language_server_denials", 0)):
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                self.policy.replace({**before, field: bad})
            self.assertEqual(self.policy.snapshot(), before)
            self.assertEqual(Policy(self.policy.directory).snapshot(), before)

    def test_unsupported_platform_selection_preserves_permissions(self):
        before = self.policy.snapshot()
        with patch("packages.SYSTEM", "aarch64-linux"):
            for selection in (["sourcekit-lsp"], ["swift", "gh"]):
                with self.subTest(selection=selection), self.assertRaises(ValueError):
                    self.policy.replace({**before, "selected_packages": selection})
                self.assertEqual(self.policy.snapshot(), before)
                self.assertEqual(Policy(self.policy.directory).snapshot(), before)

    def test_saved_launches_keep_five_settings_without_installation_choices(self):
        launch = {"source": str(self.folder.resolve()), "mode": "container", "desktop": False, "gpu": "none",
                  "agent": "omp"}
        self.policy.replace({**self.policy.snapshot(), "selected_packages": ["ssh"], "auto_start": launch})
        self.policy.record_launch(launch)
        self.assertEqual(json.loads((self.policy.directory / "last-launch.json").read_text()), launch)
        for extra in ({"installed_mode": True}, {"selected_packages": ["ssh"]}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self.policy.record_launch({**launch, **extra})
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self.policy.replace({**self.policy.snapshot(), "auto_start": {**launch, **extra}})
        self.assertEqual(Policy(self.policy.directory).snapshot()["auto_start"], launch)

    def test_rejected_update_keeps_last_permission_set(self):
        value = self.policy.snapshot()
        value["folders"] = [{"path": str(self.folder), "write": False}]
        self.policy.replace(value)
        value["folders"][0]["write"] = "yes"
        with self.assertRaises(ValueError):
            self.policy.replace(value)
        self.assertFalse(self.policy.snapshot()["folders"][0]["write"])
        self.assertEqual(Policy(self.root / "state").snapshot(), self.policy.snapshot())

    def test_state_and_symlink_folders_never_granted(self):
        link = self.root / "link"
        link.symlink_to(self.folder, target_is_directory=True)
        for target in (self.policy.directory, link, Path("/proc")):
            value = self.policy.snapshot()
            value["folders"] = [{"path": str(target), "write": True}]
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.policy.replace(value)

    def test_program_name_lookup_cannot_admit_non_nix_host_code(self):
        binary = self.root / "host-program"
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)
        value = self.policy.snapshot()
        value["programs"] = ["host-program"]
        with patch.dict("os.environ", {"PATH": str(self.root)}), self.assertRaises(ValueError):
            self.policy.replace(value)
        self.assertEqual(self.policy.snapshot()["programs"], [])

    def test_denials_aggregate_and_persist(self):
        self.policy.deny("website", "https://example.com", "not allowed")
        self.policy.deny("website", "https://example.com", "internet disabled")
        row = Policy(self.root / "state").events()[0]
        self.assertEqual((row["count"], row["reason"]), (2, "internet disabled"))
        self.assertEqual(len(json.loads((self.policy.directory / "denied.json").read_text())), 1)

    def test_history_save_failure_keeps_events_and_recovers(self):
        blocked = self.policy.directory / ".denied.json.tmp"
        blocked.mkdir()
        self.policy.deny("website", "https://blocked.example", "not allowed")
        self.policy.deny("website", "https://blocked.example", "internet disabled")
        row = self.policy.events()[0]
        self.assertEqual((row["target"], row["count"]), ("https://blocked.example", 2))
        blocked.rmdir()
        self.policy.deny("website", "https://blocked.example", "still disabled")
        recovered = Policy(self.policy.directory).events()[0]
        self.assertEqual((recovered["target"], recovered["count"], recovered["reason"]),
                         ("https://blocked.example", 3, "still disabled"))
        self.assertEqual(self.policy.history_error, "")

    def test_permission_save_failure_does_not_change_effective_permissions(self):
        before = self.policy.snapshot()
        self.policy.replace(before)
        (self.policy.directory / ".policy.json.tmp").mkdir()
        value = self.policy.snapshot()
        value["internet"] = not before["internet"]
        with self.assertRaises(OSError):
            self.policy.replace(value)
        self.assertEqual(self.policy.snapshot(), before)
        self.assertEqual(Policy(self.policy.directory).snapshot(), before)

    def test_host_credentials_require_allowed_https_origin(self):
        value = self.policy.snapshot()
        value["websites"] = ["http://example.com"]
        value["credential_origins"] = ["http://example.com"]
        with self.assertRaises(ValueError):
            self.policy.replace(value)
        value["credential_origins"] = ["https://other.example.com"]
        with self.assertRaises(ValueError):
            self.policy.replace(value)

    def test_default_grants_are_seeded_once_and_removed_grants_stay_removed(self):
        value = self.policy.snapshot()
        self.assertTrue(value["internet"])
        self.assertIn({"path": HOST_WORKSPACE, "write": True}, value["folders"])
        self.assertEqual(HOST_WORKSPACE, str(Path("/tmp").resolve() / "omp-manager"))
        self.assertIn("https://stackoverflow.com", value["websites"])
        self.assertIn("https://github.com", value["websites"])
        for removed in ("https://en.wikipedia.org", "https://www.youtube.com", "https://www.amazon.com"):
            self.assertNotIn(removed, value["websites"])
        value.update(folders=[], websites=[], internet=False)
        self.policy.replace(value)
        loaded = Policy(self.policy.directory).snapshot()
        self.assertEqual(loaded["folders"], [])
        self.assertEqual(loaded["websites"], [])
        self.assertFalse(loaded["internet"])

    def test_dependency_grants_require_their_site(self):
        value = self.policy.snapshot()
        value.update(websites=["https://github.com"], dependencies={"https://github.com": ["https://assets.test"]},
                     all_dependencies=["https://github.com"], header_dependencies=["https://github.com"])
        self.policy.replace(value)
        self.assertEqual(Policy(self.policy.directory).snapshot()["dependencies"],
                         {"https://github.com": ["https://assets.test"]})
        for field in ("dependencies", "all_dependencies", "header_dependencies"):
            orphan = self.policy.snapshot()
            orphan["websites"] = []
            for other in ("dependencies", "all_dependencies", "header_dependencies"):
                if other != field:
                    orphan[other] = {} if other == "dependencies" else []
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.policy.replace(orphan)

    def test_auto_approve_defaults_and_validation(self):
        self.assertEqual(self.policy.snapshot()["auto_approve"],
                         {"enabled": True, "sites": ["anthropic.com", "chatgpt.com", "google.com"]})
        value = self.policy.snapshot()
        value["auto_approve"] = {"enabled": False, "sites": ["https://EXAMPLE.com/x", " OpenAI "]}
        self.policy.replace(value)
        self.assertEqual(Policy(self.policy.directory).snapshot()["auto_approve"],
                         {"enabled": False, "sites": ["example.com", "openai"]})
        for bad in ({"enabled": "yes", "sites": []}, {"enabled": True}, {"enabled": True, "sites": ["a b"]},
                    {"enabled": True, "sites": [5]}, {"enabled": True, "sites": [""]}):
            value["auto_approve"] = bad
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.policy.replace(value)

    def test_newly_allowed_websites_leave_denied_history(self):
        self.policy.deny("website", "http://clients2.google.com", "denied")
        self.policy.deny("website", "https://evil.test", "denied")
        self.policy.deny("program", "gh", "denied")
        value = self.policy.snapshot()
        value["websites"].append("https://www.google.com")
        self.policy.replace(value)
        self.assertEqual([row["target"] for row in Policy(self.policy.directory).events()], ["gh", "https://evil.test"])

    def test_offline_denials_survive_permission_changes(self):
        value = self.policy.snapshot()
        value["internet"] = False
        self.policy.replace(value)
        self.policy.deny("website", "https://github.com", "Internet is disabled")
        self.policy.replace(value)
        self.assertEqual([row["target"] for row in Policy(self.policy.directory).events()], ["https://github.com"])

    def test_allow_all_network_defaults_off_and_must_be_boolean(self):
        value = self.policy.snapshot()
        self.assertFalse(value["allow_all_network"])
        value["allow_all_network"] = True
        self.policy.replace(value)
        self.assertTrue(Policy(self.policy.directory).snapshot()["allow_all_network"])
        value["allow_all_network"] = "yes"
        with self.assertRaises(ValueError):
            self.policy.replace(value)

    def test_folder_write_default_and_auto_start_persist_and_validate(self):
        value = self.policy.snapshot()
        self.assertEqual((value["folder_write_default"], value["auto_start"]), (False, None))
        launch = {"source": "/src/ombp", "mode": "container", "desktop": True, "gpu": "amd", "agent": "omsp"}
        value.update(folder_write_default=True, auto_start=launch)
        self.policy.replace(value)
        saved = Policy(self.policy.directory).snapshot()
        self.assertEqual((saved["folder_write_default"], saved["auto_start"]), (True, launch))
        self.policy.replace({**value, "auto_start": {**launch, "source": "~/ombp"}})
        self.assertEqual(self.policy.snapshot()["auto_start"]["source"], str(Path.home() / "ombp"))
        older = {key: launch[key] for key in ("source", "mode", "desktop", "gpu")}
        self.policy.replace({**value, "auto_start": older})
        self.assertEqual(self.policy.snapshot()["auto_start"]["agent"], "omp")
        for bad in ({**launch, "mode": "root"}, {**launch, "source": " "}, {**launch, "source": 5},
                    {**launch, "extra": 1}, {**launch, "gpu": "intel"}, {**launch, "agent": "x"}, "yes"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.policy.replace({**value, "auto_start": bad})
        with self.assertRaises(ValueError):
            self.policy.replace({**value, "folder_write_default": "yes"})

    def test_default_workspace_grant_is_canonical_and_never_follows_its_final_component(self):
        alias = self.root / "tmp-alias"
        system = self.root / "system-tmp"
        system.mkdir()
        alias.symlink_to(system, target_is_directory=True)
        # Like macOS /tmp -> /private/tmp: only the system alias parent is resolved.
        workspace = host_workspace(alias)
        self.assertEqual(workspace, system.resolve() / "omp-manager")
        with patch("policy.HOST_WORKSPACE", str(workspace)):
            seeded = Policy(self.root / "seeded").snapshot()["folders"]
            self.assertIn({"path": str(workspace), "write": True}, seeded)
            self.assertEqual(stat.S_IMODE(workspace.stat().st_mode), 0o700)
            workspace.rmdir()
            target = self.root / "elsewhere"
            target.mkdir()
            workspace.symlink_to(target, target_is_directory=True)
            with self.assertRaises((OSError, ValueError)):
                Policy(self.root / "refused")
            self.assertFalse((self.root / "refused" / "policy.json").exists())
            self.assertEqual(list(target.iterdir()), [])

    def test_transient_socket_directory_is_private_short_and_never_granted(self):
        directory = self.policy.transient_directory()
        self.assertEqual(directory, self.policy.transient_directory())
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual(directory, directory.resolve())
        # Room for a socket name below macOS's 104-byte sun_path limit.
        self.assertLess(len(str(directory / "broker.sock")), 104)
        self.assertIn(str(directory), self.policy.private_paths)
        self.assertIn(str((Path.home() / ".local/share/ombp-lima").resolve()), self.policy.private_paths)
        value = self.policy.snapshot()
        value["folders"] = [{"path": str(directory), "write": False}]
        with self.assertRaisesRegex(ValueError, "cannot be shared"):
            self.policy.replace(value)
        directory.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private directory"):
            self.policy.transient_directory()
        directory.rmdir()
        self.assertNotEqual(Policy(self.root / "other").transient, self.policy.transient)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin Unix socket pathname limit")
    def test_long_tmpdir_does_not_prevent_controller_socket_connections(self):
        long_tmp = self.root / ("nested-build-directory-" * 7)
        long_tmp.mkdir()
        with patch("policy.tempfile.gettempdir", return_value=str(long_tmp)):
            policy = Policy(self.root / "long-tmp-state")
        directory = policy.transient_directory()
        address = directory / "broker.sock"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(address))
                listener.listen(1)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(str(address))
                    peer, _ = listener.accept()
                    with peer:
                        client.sendall(b"connected")
                        self.assertEqual(peer.recv(9), b"connected")
        finally:
            address.unlink(missing_ok=True)
            directory.rmdir()

    def test_recorded_launch_persists_and_never_escalates_automatic_start(self):
        self.assertIsNone(self.policy.last_launch())
        isolated = {"source": str(self.folder), "mode": "container", "desktop": True, "gpu": "none", "agent": "omp"}
        unrestricted = {**isolated, "mode": "normal", "agent": "omsp"}
        self.policy.record_launch(isolated)
        self.assertIsNone(self.policy.snapshot()["auto_start"])
        self.assertEqual(Policy(self.policy.directory).last_launch(), isolated)
        value = self.policy.snapshot()
        value["auto_start"] = isolated
        self.policy.replace(value)
        self.policy.record_launch(unrestricted)
        self.assertEqual(self.policy.last_launch(), unrestricted)
        # An unrestricted run never silently turns isolated automatic start into unrestricted.
        self.assertEqual(self.policy.snapshot()["auto_start"], isolated)
        self.policy.record_launch({**isolated, "gpu": "amd"})
        self.assertEqual(Policy(self.policy.directory).snapshot()["auto_start"], {**isolated, "gpu": "amd"})
        for bad in ({**isolated, "mode": "root"}, None, "settings"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.policy.record_launch(bad)
        (self.policy.directory / "last-launch.json").write_text(json.dumps({**isolated, "extra": 1}))
        with self.assertRaisesRegex(ValueError, "last-launch.json"):
            self.policy.last_launch()

    def test_forget_removes_only_approved_rows(self):
        self.policy.deny("website", "https://a.test", "denied", "https://site.test")
        self.policy.deny("website", "https://a.test", "denied")
        self.policy.deny("program", "gh", "denied")
        self.policy.forget([{"kind": "website", "target": "https://a.test", "site": "https://site.test"},
                            {"kind": "program", "target": "gh"}])
        self.assertEqual([(row["kind"], row["target"], row.get("site")) for row in Policy(self.policy.directory).events()],
                         [("website", "https://a.test", None)])
        with self.assertRaises(ValueError):
            self.policy.forget({"kind": "website"})

    def test_clear_history_persists_without_changing_permissions_and_fails_atomically(self):
        self.policy.deny("folder", "/private", "not shared")
        before = self.policy.snapshot()
        (self.policy.directory / ".denied.json.tmp").mkdir()
        with self.assertRaises(OSError):
            self.policy.clear_history()
        self.assertEqual(self.policy.events()[0]["target"], "/private")
        (self.policy.directory / ".denied.json.tmp").rmdir()
        self.policy.clear_history()
        self.assertEqual(Policy(self.policy.directory).events(), [])
        self.assertEqual(self.policy.snapshot(), before)
        self.policy.deny("folder", "/private", "not shared")
        self.assertEqual(self.policy.events()[0]["count"], 1)



if __name__ == "__main__":
    unittest.main()
