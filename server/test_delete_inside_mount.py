import importlib.util
import inspect
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("delete_inside_mount", Path(__file__).with_name("delete_inside_mount.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


@unittest.skipUnless(os.name == "posix" and getattr(shutil.rmtree, "avoids_symlink_attacks", False), "requires POSIX fd-safe rmtree")
class DeleteInsideMountTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vhdx-delete-primitive-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "mounted"
        self.root.mkdir()
        self.outside = Path(self.tmp.name) / "outside"
        self.outside.mkdir()
        (self.outside / "keep.txt").write_text("never delete")

    def remove(self, relative, expected="file", root=None):
        return mod.delete_inside_mount(str(root if root is not None else self.root), relative, expected)

    def test_removes_only_selected_file_and_accepts_windows_separators(self):
        (self.root / "nested").mkdir()
        (self.root / "nested" / "target.txt").write_text("target")
        (self.root / "nested" / "keep.txt").write_text("keep")
        self.remove(r"nested\target.txt")
        self.assertFalse((self.root / "nested" / "target.txt").exists())
        self.assertEqual((self.root / "nested" / "keep.txt").read_text(), "keep")

    @unittest.skipUnless("dir_fd" in inspect.signature(shutil.rmtree).parameters, "requires rmtree(dir_fd=...)")
    def test_recursive_folder_does_not_follow_links_inside_tree(self):
        folder = self.root / "folder"
        (folder / "nested").mkdir(parents=True)
        (folder / "nested" / "file").write_text("data")
        os.symlink(self.outside, folder / "external-directory")
        os.symlink(self.outside / "keep.txt", folder / "external-file")
        self.remove("folder", "dir")
        self.assertFalse(folder.exists())
        self.assertEqual((self.outside / "keep.txt").read_text(), "never delete")

    def test_rejects_root_traversal_ads_and_bad_components(self):
        for path in ["", ".", "..", "/", "\\", "../outside/keep.txt", r"..\outside\keep.txt", "folder/../file", r"folder\..\file", "/absolute", r"\absolute", r"C:\file", "file:stream", "a//b", "a/", "x\nother", "\x00"]:
            with self.subTest(path=path), self.assertRaises(mod.DeleteError):
                self.remove(path)
        self.assertTrue((self.outside / "keep.txt").exists())

    def test_rejects_symlink_ancestor(self):
        os.symlink(self.outside, self.root / "link")
        with self.assertRaises(mod.DeleteError):
            self.remove("link/keep.txt")
        self.assertTrue((self.outside / "keep.txt").exists())

    def test_rejects_symlink_target_for_both_expected_types(self):
        os.symlink(self.outside / "keep.txt", self.root / "file-link")
        os.symlink(self.outside, self.root / "dir-link")
        for name, kind in [("file-link", "file"), ("dir-link", "dir")]:
            with self.subTest(name=name), self.assertRaises(mod.DeleteError):
                self.remove(name, kind)
        self.assertTrue((self.outside / "keep.txt").exists())

    def test_rejects_symlink_mount_root(self):
        link = Path(self.tmp.name) / "mount-link"
        os.symlink(self.root, link)
        (self.root / "keep.txt").write_text("keep")
        with self.assertRaises(mod.DeleteError):
            self.remove("keep.txt", root=link)
        self.assertTrue((self.root / "keep.txt").exists())

    def test_type_mismatch_does_not_delete(self):
        (self.root / "file").write_text("data")
        (self.root / "folder").mkdir()
        with self.assertRaises(mod.DeleteError): self.remove("file", "dir")
        with self.assertRaises(mod.DeleteError): self.remove("folder", "file")
        self.assertTrue((self.root / "file").exists())
        self.assertTrue((self.root / "folder").is_dir())

    def test_rejects_when_safe_rmtree_unavailable(self):
        (self.root / "folder").mkdir()
        (self.root / "folder" / "keep").write_text("keep")
        with mock.patch.object(mod.shutil.rmtree, "avoids_symlink_attacks", False):
            with self.assertRaises(mod.DeleteError): self.remove("folder", "dir")
        self.assertEqual((self.root / "folder" / "keep").read_text(), "keep")

    def test_rejects_when_rmtree_dir_fd_unavailable(self):
        (self.root / "folder").mkdir()
        (self.root / "folder" / "keep").write_text("keep")
        with mock.patch.object(mod.inspect, "signature", return_value=inspect.Signature()):
            with self.assertRaises(mod.DeleteError): self.remove("folder", "dir")
        self.assertEqual((self.root / "folder" / "keep").read_text(), "keep")

    def test_missing_target_and_bad_kind_leave_siblings(self):
        (self.root / "keep").write_text("keep")
        with self.assertRaises(mod.DeleteError): self.remove("missing")
        with self.assertRaises(mod.DeleteError): self.remove("keep", "device")
        self.assertEqual((self.root / "keep").read_text(), "keep")

    def test_system_root_is_not_allowed(self):
        with self.assertRaises(mod.DeleteError): self.remove("file", root=Path("/"))
        with self.assertRaises(mod.DeleteError): self.remove("file", root=Path("//"))

    @unittest.skipUnless("dir_fd" in inspect.signature(shutil.rmtree).parameters, "requires rmtree(dir_fd=...)")
    def test_guard_callback_runs_before_every_recursive_mutation(self):
        (self.root / "tree" / "child").mkdir(parents=True)
        (self.root / "tree" / "one").write_text("1")
        (self.root / "tree" / "child" / "two").write_text("2")
        calls=[]
        mod.delete_inside_mount(str(self.root), "tree", "dir", lambda: calls.append("guard"))
        self.assertFalse((self.root / "tree").exists())
        self.assertGreaterEqual(len(calls),4) # two files, nested dir, root dir

    @unittest.skipUnless("dir_fd" in inspect.signature(shutil.rmtree).parameters, "requires rmtree(dir_fd=...)")
    def test_guard_rejection_stops_remaining_recursive_mutations(self):
        (self.root / "tree").mkdir()
        for n in range(3): (self.root / "tree" / str(n)).write_text("data")
        calls=[]
        def guard():
            calls.append(1)
            if len(calls)==2: raise mod.DeleteError("guard lost")
        with self.assertRaisesRegex(mod.DeleteError, "guard lost"):
            mod.delete_inside_mount(str(self.root), "tree", "dir", guard)
        self.assertEqual(len(list((self.root / "tree").iterdir())),2)

    def test_requires_absolute_mount_root(self):
        with self.assertRaises(mod.DeleteError): self.remove("file", root=Path("relative"))


if __name__ == "__main__": unittest.main()




