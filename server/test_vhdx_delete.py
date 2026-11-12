import contextlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("vhdx_delete", HERE / "vhdx_delete.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


@unittest.skipUnless(os.name == "posix", "requires Linux/POSIX APIs")
class OrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vhdx-orchestration-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.image = self.root / "scratch.vhdx"
        self.image.write_bytes(b"not a real VHDX; all external calls are mocked")
        self.info = self.image.stat()
        self.marker_dir = self.root / "markers-parent" / "operations"
        self.marker_dir.mkdir(parents=True)
        self.events = []
        self.state = {"pid": None, "mounted": False, "guard": False}
        self.guard = mock.Mock(unsafe=True)
        self.guard.verified = True
        self.guard.device = self.info.st_dev
        self.guard.inode = self.info.st_ino
        self.guard.size = self.info.st_size
        self.guard.assert_still_exclusive.side_effect = self.guard_check

    def guard_check(self):
        self.assertTrue(self.state["guard"], "guard released while operation is active")
        self.events.append("guard-check")

    @contextlib.contextmanager
    def held_guard(self, image):
        self.assertEqual(image, str(self.image))
        self.state["guard"] = True
        self.events.append("guard-acquire")
        try:
            yield self.guard
        finally:
            self.assertFalse(self.state["mounted"], "guard released while mounted")
            self.assertIsNone(self.state["pid"], "guard released while NBD connected")
            self.events.append("guard-release")
            self.state["guard"] = False

    def fake_run(self, args, *, pass_fds=(), timeout=30.0):
        self.assertTrue(self.state["guard"])
        cmd = args[0]
        if cmd == "qemu-img":
            self.events.append("backing-check")
            return subprocess.CompletedProcess(args, 0, stdout='[{"format":"vhdx"}]', stderr="")
        if cmd == "qemu-nbd" and "--connect" in args:
            self.events.append("connect")
            self.assertEqual(len(pass_fds), 1)
            self.assertEqual(args[-1], f"/proc/self/fd/{pass_fds[0]}")
            self.assertEqual(os.fstat(pass_fds[0]).st_ino, self.info.st_ino)
            self.state["pid"] = 4321
        elif cmd == "qemu-nbd" and "--disconnect" in args:
            self.events.append("disconnect")
            self.assertFalse(self.state["mounted"])
            self.state["pid"] = None
        elif cmd == "blkid":
            self.events.append("identify")
            return subprocess.CompletedProcess(args, 0, stdout="ntfs\n", stderr="")
        elif cmd == "ntfsinfo":
            self.events.append("clean-check")
        elif cmd == "ntfsls":
            self.events.append("hibernation-check")
            return subprocess.CompletedProcess(args, 0, stdout="\u0024RECYCLE.BIN\nSampleFolder\n", stderr="")
        elif cmd == "ntfs-3g.probe":
            self.events.append("probe")
        elif cmd == "ntfs-3g":
            self.events.append("mount")
            self.assertIn("norecover,nodev,nosuid,noexec", args)
            self.assertNotIn("force", args)
            self.assertNotIn("remove_hiberfile", args)
            self.state["mounted"] = True
        elif cmd == sys.executable:
            self.events.append("delete")
            self.assertTrue(self.state["mounted"])
            self.assertEqual(args[-2:], [r"folder\item.txt", "file"])
            self.assertIn("--", args)
        elif cmd == "sync":
            self.events.append("sync")
        elif cmd == "umount":
            self.events.append("unmount")
            self.state["mounted"] = False
        else:
            self.fail(f"Unexpected command: {args}")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    @contextlib.contextmanager
    def fixture(self):
        original_mkdtemp = tempfile.mkdtemp
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(mod.os, "geteuid", return_value=0))
            stack.enter_context(mock.patch.object(mod, "acquire_verified_guard", side_effect=self.held_guard))
            stack.enter_context(mock.patch.object(mod, "_check_local_writers", side_effect=lambda guard, fd: guard.assert_still_exclusive()))
            stack.enter_context(mock.patch.object(mod, "_private_namespace", side_effect=lambda: self.events.append("namespace")))
            store_type = mod.MarkerStore
            stack.enter_context(mock.patch.object(mod, "MarkerStore", side_effect=lambda _: store_type(self.marker_dir, expected_owner=os.getuid())))
            stack.enter_context(mock.patch.object(mod, "_nbd_allocation_lock", side_effect=contextlib.nullcontext))
            stack.enter_context(mock.patch.object(mod, "_ensure_nbd_module"))
            stack.enter_context(mock.patch.object(mod, "_available_nbd", return_value="/dev/nbd7"))
            stack.enter_context(mock.patch.object(mod, "_wait_for_partition", return_value="/dev/nbd7p2"))
            stack.enter_context(mock.patch.object(mod, "_nbd_pid", side_effect=lambda _: self.state["pid"]))
            stack.enter_context(mock.patch.object(mod, "_process_start_ticks", return_value=9876))
            stack.enter_context(mock.patch.object(mod, "_is_mountpoint", side_effect=lambda _: self.state["mounted"]))
            stack.enter_context(mock.patch.object(mod.tempfile, "mkdtemp", side_effect=lambda **kw: original_mkdtemp(prefix=kw["prefix"], dir=str(self.root))))
            stack.enter_context(mock.patch.object(mod, "_run", side_effect=self.fake_run))
            stack.enter_context(mock.patch.object(mod, "_run_guarded_command", side_effect=lambda guard, args, **kw: self.fake_run(args, **kw)))
            stack.enter_context(mock.patch.object(mod, "_run_cleanup_command", side_effect=lambda guard, state, args, **kw: self.fake_run(args, **kw)))
            stack.enter_context(mock.patch.object(mod, "_run_guarded_delete", side_effect=lambda guard, helper, root, path, kind: self.fake_run([sys.executable, helper, "--", root, path, kind])))
            yield

    def invoke(self):
        mod.delete_vhdx(str(self.image), 2, r"folder\item.txt", "file")

    def test_guard_unavailable_fails_before_touching_image(self):
        with mock.patch.object(mod.os, "geteuid", return_value=0), \
             mock.patch.dict(sys.modules, {"smb_guard": None}), \
             mock.patch.object(mod, "_private_namespace") as namespace, \
             mock.patch.object(mod, "_run") as run:
            with self.assertRaisesRegex(mod.SafetyError, "guard"):
                mod.delete_vhdx(str(self.image), 2, "item", "file")
            namespace.assert_not_called()
            run.assert_not_called()
        self.assertEqual(self.image.read_bytes(), b"not a real VHDX; all external calls are mocked")

    def test_full_mock_path_keeps_guard_until_unmounted_and_disconnected(self):
        with self.fixture(): self.invoke()
        self.assertLess(self.events.index("guard-acquire"), self.events.index("connect"))
        self.assertLess(self.events.index("connect"), self.events.index("mount"))
        self.assertLess(self.events.index("mount"), self.events.index("delete"))
        self.assertLess(self.events.index("delete"), self.events.index("sync"))
        self.assertLess(self.events.index("sync"), self.events.index("unmount"))
        self.assertLess(self.events.index("unmount"), self.events.index("disconnect"))
        self.assertLess(self.events.index("disconnect"), self.events.index("guard-release"))

    def test_mismatched_guard_identity_fails_before_namespace(self):
        self.guard.inode += 1
        with self.fixture():
            with self.assertRaisesRegex(mod.SafetyError, "same file"): self.invoke()
        self.assertNotIn("namespace", self.events)
        self.assertNotIn("connect", self.events)

    def test_non_ntfs_partition_never_mounts(self):
        original = self.fake_run
        def wrong_type(args, **kwargs):
            if args[0] == "blkid": return subprocess.CompletedProcess(args, 0, stdout="ext4\n", stderr="")
            return original(args, **kwargs)
        with self.fixture(), mock.patch.object(mod, "_run_guarded_command", side_effect=lambda guard,args,**kw: wrong_type(args,**kw)):
            with self.assertRaisesRegex(mod.SafetyError, "not NTFS"): self.invoke()
        self.assertNotIn("mount", self.events)
        self.assertNotIn("delete", self.events)
        self.assertIn("disconnect", self.events)

    def test_backing_chain_rejected_before_writable_attach(self):
        original=self.fake_run
        def with_parent(args, **kwargs):
            if args[0]=="qemu-img": return subprocess.CompletedProcess(args,0,stdout='[{"format":"vhdx","backing-filename":"parent.vhdx"}]',stderr="")
            return original(args, **kwargs)
        with self.fixture(), mock.patch.object(mod,"_run_guarded_command",side_effect=lambda guard,args,**kw: with_parent(args,**kw)):
            with self.assertRaisesRegex(mod.SafetyError,"backing"): self.invoke()
        self.assertNotIn("connect",self.events)
        self.assertNotIn("delete",self.events)

    def test_unparseable_backing_info_rejected(self):
        with mock.patch.object(mod,"_run_guarded_command",return_value=subprocess.CompletedProcess([],0,stdout="not-json",stderr="")):
            with self.assertRaisesRegex(mod.SafetyError,"parse"): mod._reject_backing_chain(self.guard,42)

    def test_dirty_check_failure_never_mounts_or_deletes(self):
        original=self.fake_run
        def dirty(args, **kwargs):
            if args[0]=="ntfsinfo": raise mod.SafetyError("Volume is scheduled for check")
            return original(args, **kwargs)
        with self.fixture(), mock.patch.object(mod, "_run_guarded_command", side_effect=lambda guard,args,**kw: dirty(args,**kw)):
            with self.assertRaisesRegex(mod.SafetyError, "scheduled for check"): self.invoke()
        self.assertNotIn("mount", self.events)
        self.assertNotIn("delete", self.events)
        self.assertIn("disconnect", self.events)

    def test_possible_hibernation_never_mounts_or_deletes(self):
        original=self.fake_run
        def hibernated(args, **kwargs):
            if args[0]=="ntfsls": return subprocess.CompletedProcess(args,0,stdout="SampleFolder\nHIBERFIL.SYS\n",stderr="")
            return original(args, **kwargs)
        with self.fixture(), mock.patch.object(mod, "_run_guarded_command", side_effect=lambda guard,args,**kw: hibernated(args,**kw)):
            with self.assertRaisesRegex(mod.SafetyError, "hiberfil.sys"): self.invoke()
        self.assertNotIn("mount",self.events)
        self.assertNotIn("delete",self.events)
        self.assertIn("disconnect",self.events)

    def test_guard_loss_before_delete_prevents_mutation_and_cleans_up(self):
        calls = 0
        def lose_guard():
            nonlocal calls
            calls += 1
            if calls == 5: raise mod.SafetyError("SMB guard lost")
            self.guard_check()
        self.guard.assert_still_exclusive.side_effect = lose_guard
        with self.fixture():
            with self.assertRaisesRegex(mod.SafetyError, "guard lost"): self.invoke()
        self.assertNotIn("delete", self.events)
        self.assertIn("unmount", self.events)
        self.assertIn("disconnect", self.events)
        self.assertTrue((self.marker_dir / f"{self.info.st_dev}-{self.info.st_ino}.json").exists())

    def test_unmount_failure_retries_without_releasing_guard_or_disconnecting(self):
        original = self.fake_run
        attempts = 0
        def fail_once(args, **kwargs):
            nonlocal attempts
            if args[0] == "umount":
                attempts += 1
                if attempts == 1:
                    self.events.append("unmount-failed")
                    raise mod.SafetyError("temporary unmount failure")
            return original(args, **kwargs)
        with self.fixture(), mock.patch.object(mod, "_run_cleanup_command", side_effect=lambda guard,state,args,**kw: fail_once(args,**kw)), mock.patch.object(mod.time, "sleep"):
            self.invoke()
        self.assertEqual(attempts, 2)
        self.assertLess(self.events.index("unmount-failed"), self.events.index("unmount"))
        self.assertLess(self.events.index("unmount"), self.events.index("disconnect"))
        self.assertLess(self.events.index("disconnect"), self.events.index("guard-release"))

    def test_status_is_clear_only_without_marker_or_lock(self):
        from operation_state import MarkerStore
        with mock.patch.object(mod, "MarkerStore", side_effect=lambda _: MarkerStore(self.marker_dir, expected_owner=os.getuid())), mock.patch.object(mod, "configure_guard"), mock.patch.object(mod, "acquire_verified_guard", side_effect=self.held_guard):
            self.assertTrue(mod.status_vhdx(str(self.image)).startswith("CLEAR:"))
            self.assertEqual(mod.main(["--status", "--expected-config-digest", "a"*64, "--", str(self.image)]), 0)
            fd, info = mod._open_and_lock(str(self.image), exclusive=True)
            try:
                with self.assertRaisesRegex(mod.SafetyError, "busy"): mod.status_vhdx(str(self.image))
                with MarkerStore(self.marker_dir, expected_owner=os.getuid()) as store:
                    marker=store.create(info, str(self.image));marker.close()
            finally:
                os.close(fd)
            with self.assertRaisesRegex(mod.SafetyError, "UNRESOLVED"): mod.status_vhdx(str(self.image))
            self.assertEqual(mod.main(["--status", "--expected-config-digest", "a"*64, "--", str(self.image)]), 1)

    def test_guard_release_failure_retains_marker(self):
        @contextlib.contextmanager
        def broken_release(image):
            with self.held_guard(image) as guard:
                yield guard
            raise RuntimeError("simulated guard close failure")
        with self.fixture(), mock.patch.object(mod, "acquire_verified_guard", side_effect=broken_release):
            with self.assertRaisesRegex(mod.SafetyError, "marker retained"): self.invoke()
        self.assertTrue((self.marker_dir / f"{self.info.st_dev}-{self.info.st_ino}.json").exists())

    def test_helper_requires_live_guard_before_file_unlink(self):
        folder=self.root / "fixture"
        folder.mkdir(); victim=folder / "victim.txt";victim.write_text("data")
        guard=mock.Mock(unsafe=True)
        mod._run_guarded_delete(guard, str(HERE / "delete_inside_mount.py"), str(folder), "victim.txt", "file")
        self.assertFalse(victim.exists())
        self.assertGreaterEqual(guard.assert_still_exclusive.call_count, 3)

    def test_guard_loss_prevents_helper_unlink(self):
        folder=self.root / "fixture"
        folder.mkdir(); victim=folder / "victim.txt";victim.write_text("data")
        guard=mock.Mock(unsafe=True)
        guard.assert_still_exclusive.side_effect=[None,None,RuntimeError("session dropped")]
        with self.assertRaisesRegex(mod.SafetyError, "guard was lost"):
            mod._run_guarded_delete(guard, str(HERE / "delete_inside_mount.py"), str(folder), "victim.txt", "file")
        self.assertTrue(victim.exists())

    @unittest.skipUnless("dir_fd" in __import__("inspect").signature(__import__("shutil").rmtree).parameters, "requires rmtree(dir_fd=...)")
    def test_guard_loss_stops_recursive_subprocess_with_remaining_items(self):
        root=self.root / "fixture";root.mkdir();tree=root / "folder";tree.mkdir()
        for n in range(12): (tree / f"{n:02d}").write_text("data")
        guard=mock.Mock(unsafe=True);count=0
        def check():
            nonlocal count
            count+=1
            if count>=8: raise RuntimeError("session lost")
        guard.assert_still_exclusive.side_effect=check
        with self.assertRaises(mod.GuardLost):
            mod._run_guarded_delete(guard,str(HERE / "delete_inside_mount.py"),str(root),"folder","dir")
        self.assertTrue(tree.exists())
        self.assertGreater(len(list(tree.iterdir())),0)

    def test_signal_policy_ignores_hangup_and_converts_termination(self):
        import signal
        original = signal.getsignal(signal.SIGHUP)
        with mod._controlled_signals():
            self.assertEqual(signal.getsignal(signal.SIGHUP), signal.SIG_IGN)
            with self.assertRaises(mod.StopRequested): signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        self.assertEqual(signal.getsignal(signal.SIGHUP), original)

    def test_guard_loss_during_cleanup_still_unmounts_disconnects_and_retains_marker(self):
        original=self.fake_run
        def lose_during_unmount(guard,state,args,**kwargs):
            if args[0]=="umount": state["guard_lost"]=mod.GuardLost("guard lost during cleanup")
            return original(args,**kwargs)
        with self.fixture(), mock.patch.object(mod,"_run_cleanup_command",side_effect=lose_during_unmount):
            with self.assertRaisesRegex(mod.GuardLost,"during cleanup"): self.invoke()
        self.assertIn("unmount",self.events)
        self.assertIn("disconnect",self.events)
        self.assertTrue((self.marker_dir / f"{self.info.st_dev}-{self.info.st_ino}.json").exists())

    def test_vhd_status_supported_but_vhd_delete_rejected(self):
        from operation_state import MarkerStore
        vhd=self.root / "test.vhd";vhd.write_bytes(b"scratch")
        with mock.patch.object(mod,"MarkerStore",side_effect=lambda _: MarkerStore(self.marker_dir,expected_owner=os.getuid())):
            self.assertTrue(mod.status_vhdx(str(vhd)).startswith("CLEAR:"))
        with self.assertRaisesRegex(mod.SafetyError,"vhdx"):
            mod.delete_vhdx(str(vhd),1,"file","file")

    def test_cleanup_guard_loss_does_not_interrupt_urgent_cleanup_command(self):
        completed=self.root / "cleanup-completed"
        guard=mock.Mock(unsafe=True)
        guard.assert_still_exclusive.side_effect=[None,RuntimeError("session dropped")]
        state={"guard_lost":None}
        command=[sys.executable,"-c","import pathlib,sys,time;time.sleep(.1);pathlib.Path(sys.argv[1]).write_text('done')",str(completed)]
        mod._run_cleanup_command(guard,state,command,timeout=4)
        self.assertEqual(completed.read_text(),"done")
        self.assertIsInstance(state["guard_lost"],mod.GuardLost)

    def test_guard_loss_terminates_writable_child_before_late_side_effect(self):
        changed=self.root / "must-not-exist"
        guard=mock.Mock(unsafe=True)
        guard.assert_still_exclusive.side_effect=[None,RuntimeError("session dropped")]
        command=[sys.executable,"-c","import pathlib,sys,time;time.sleep(3);pathlib.Path(sys.argv[1]).write_text('bad')",str(changed)]
        with self.assertRaises(mod.GuardLost): mod._run_guarded_command(guard,command,timeout=6)
        self.assertFalse(changed.exists())

    def test_partition_poll_checks_guard(self):
        guard=mock.Mock(unsafe=True)
        guard.assert_still_exclusive.side_effect=RuntimeError("session dropped")
        with self.assertRaises(mod.GuardLost): mod._wait_for_partition(guard,"/dev/nonexistent",1,timeout=1)

    def test_nbd_pid_reuse_is_never_disconnected(self):
        self.state["guard"]=True;self.state["pid"]=4321
        state={"guard_lost":None}
        with mock.patch.object(mod,"_nbd_pid",return_value=4321), \
             mock.patch.object(mod,"_process_start_ticks",return_value=9999), \
             mock.patch.object(mod,"_run_cleanup_command") as command:
            with self.assertRaisesRegex(mod.SafetyError,"ownership"):
                mod._cleanup_once(self.guard,state,"/dev/nbd7",4321,1111,None,False,True)
            command.assert_not_called()

    def test_local_holder_check_allows_only_own_and_guarded_smbd(self):
        self.state["guard"] = True
        fake=subprocess.CompletedProcess(["fuser"],0,stdout=f"{os.getpid()} 12345",stderr="")
        with mock.patch.object(mod.subprocess,"run",return_value=fake), mock.patch.object(mod.os,"readlink",return_value="/usr/sbin/smbd"):
            mod._check_local_writers(self.guard,42)
        self.assertGreaterEqual(self.guard.assert_still_exclusive.call_count,2)

    def test_local_holder_check_rejects_other_or_unknown_holders(self):
        self.state["guard"] = True
        fake=subprocess.CompletedProcess(["fuser"],0,stdout=f"{os.getpid()} 12345",stderr="")
        with mock.patch.object(mod.subprocess,"run",return_value=fake), mock.patch.object(mod.os,"readlink",return_value="/usr/bin/python3"):
            with self.assertRaisesRegex(mod.SafetyError,"Another local process"):
                mod._check_local_writers(self.guard,42)
        fake.stdout="12345"
        with mock.patch.object(mod.subprocess,"run",return_value=fake):
            with self.assertRaisesRegex(mod.SafetyError,"could not see this process"):
                mod._check_local_writers(self.guard,42)

    def test_mountpoint_detection_parses_mountinfo_and_escapes(self):
        sample=("1 0 8:1 / / rw - ext4 /dev/sda rw\n"
                "2 1 0:7 / /run/private\\040mount rw - fuseblk /dev/nbd0p1 rw\n")
        with mock.patch.object(mod.Path, "read_text", return_value=sample):
            self.assertTrue(mod._is_mountpoint("/run/private mount"))
            self.assertFalse(mod._is_mountpoint("/run/not-mounted"))
        with mock.patch.object(mod.Path, "read_text", return_value=""):
            with self.assertRaisesRegex(mod.SafetyError,"no mountinfo"): mod._is_mountpoint("/tmp/m")
        with mock.patch.object(mod.Path, "read_text", return_value="not-a-valid-mountinfo-entry"):
            with self.assertRaisesRegex(mod.SafetyError,"malformed"): mod._is_mountpoint("/tmp/m")
        with mock.patch.object(mod.Path, "read_text", side_effect=PermissionError("blocked")):
            with self.assertRaisesRegex(mod.SafetyError,"Cannot inspect"): mod._is_mountpoint("/tmp/m")

    def test_mountpoint_detection_real_namespace(self):
        self.assertTrue(mod._is_mountpoint("/"))
        self.assertFalse(mod._is_mountpoint(str(self.root)))

    def test_hangup_ignored_and_termination_runs_cleanup(self):
        import signal
        finished=self.root / "signal-cleanup"
        script=("import pathlib,sys,time;sys.path.insert(0,sys.argv[1]);"
                "from vhdx_delete import _controlled_signals,StopRequested\n"
                "try:\n"
                " with _controlled_signals():\n"
                "  print('READY',flush=True);time.sleep(10)\n"
                "except StopRequested:\n"
                " pathlib.Path(sys.argv[2]).write_text('cleaned')\n")
        child=subprocess.Popen([sys.executable,"-c",script,str(HERE),str(finished)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(),"READY")
            child.send_signal(signal.SIGHUP)
            self.assertIsNone(child.poll(),"hangup ended the process")
            child.send_signal(signal.SIGTERM)
            _,stderr=child.communicate(timeout=5)
            self.assertEqual(child.returncode,0,stderr)
            self.assertEqual(finished.read_text(),"cleaned")
        finally:
            if child.poll() is None:
                child.kill();child.wait()

    def test_rejects_invalid_target_before_guard(self):
        with mock.patch.object(mod.os, "geteuid", return_value=0), mock.patch.object(mod, "acquire_verified_guard") as guard:
            with self.assertRaises(mod.DeleteError): mod.delete_vhdx(str(self.image), 2, "../escape", "file")
            guard.assert_not_called()


if __name__ == "__main__": unittest.main()















