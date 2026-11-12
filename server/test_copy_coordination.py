import importlib.machinery
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
import io
from contextlib import redirect_stdout
from unittest.mock import patch

loader=importlib.machinery.SourceFileLoader('vhdx_copy',str(Path(__file__).with_name('vhdx-copy')))
spec=importlib.util.spec_from_loader(loader.name,loader)
helper=importlib.util.module_from_spec(spec);loader.exec_module(helper)

@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0,'Linux root-owned fixture required')
class CoordinationTests(unittest.TestCase):
 def setUp(self):
  # /tmp is world-writable and is correctly rejected as a share ancestor.
  self.tmp=tempfile.TemporaryDirectory(dir='/run');self.root=Path(self.tmp.name)
  self.ops=self.root/'.vhdx-handoff'/'operations';self.ops.mkdir(parents=True)
  self.image=self.root/'test.vhdx';self.image.write_bytes(b'fixture')
  self.patch=patch.object(helper,'MEDIA_ROOT',str(self.root));self.patch.start()
 def tearDown(self):self.patch.stop();self.tmp.cleanup()
 def test_shared_lock_blocks_exclusive_until_copy_releases(self):
  import fcntl
  with helper.coordinated_image(str(self.image)) as f:
   self.assertEqual(f.read(),b'fixture')
   with open(self.image,'rb') as other:
    with self.assertRaises(BlockingIOError):fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
  with open(self.image,'rb') as other:fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
 def test_existing_exclusive_lock_blocks_copy(self):
  import fcntl
  with open(self.image,'rb') as other:
   fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
   with self.assertRaisesRegex(RuntimeError,'busy'):
    with helper.coordinated_image(str(self.image)):pass
 def test_stale_marker_blocks_even_if_symlink(self):
  s=self.image.stat();marker=self.ops/f'{s.st_dev}-{s.st_ino}.json'
  marker.symlink_to(self.root/'missing')
  with self.assertRaisesRegex(RuntimeError,'incomplete'):
   with helper.coordinated_image(str(self.image)):pass
 def test_missing_or_unsafe_directory_fails_closed(self):
  os.chmod(self.ops,0o777)
  with self.assertRaisesRegex(RuntimeError,'unsafe'):
   with helper.coordinated_image(str(self.image)):pass
  os.chmod(self.ops,0o755);self.ops.rmdir()
  with self.assertRaisesRegex(RuntimeError,'unavailable'):
   with helper.coordinated_image(str(self.image)):pass
 def test_writable_media_parent_is_rejected(self):
  os.chmod(self.root,0o777)
  try:
   with self.assertRaisesRegex(RuntimeError,'unsafe'):
    with helper.coordinated_image(str(self.image)):pass
  finally:os.chmod(self.root,0o700)
 def test_images_outside_configured_root_are_rejected(self):
  with tempfile.TemporaryDirectory() as other_root:
   other=Path(other_root)/'image.raw';other.write_bytes(b'abc')
   with self.assertRaisesRegex(ValueError,'configured share root'):
    with helper.coordinated_image(str(other)):pass
 def test_directory_is_rejected(self):
  with self.assertRaises(ValueError):
   with helper.coordinated_image(str(self.root)):pass
 def test_status_rejects_unresolved_marker_and_outside_image(self):
  with patch.object(helper,'load_root',return_value=str(self.root)), patch.object(helper.sys,'argv',['vhdx-copy','--status','--',str(self.image)]):
   out=io.StringIO()
   with redirect_stdout(out): helper.main()
   self.assertIn('CLEAR:',out.getvalue())
   info=self.image.stat(); (self.ops/f'{info.st_dev}-{info.st_ino}.json').write_text('{}')
   with self.assertRaisesRegex(RuntimeError,'incomplete'): helper.main()
  with patch.object(helper,'load_root',return_value=str(self.root)), patch.object(helper.sys,'argv',['vhdx-copy','--status','--','/outside.vhdx']):
   with self.assertRaisesRegex(ValueError,'configured share root'): helper.main()
if __name__=='__main__':unittest.main()
