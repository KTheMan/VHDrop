import builtins
import io
import importlib.machinery
import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).with_name('vhdx-copy')
loader = importlib.machinery.SourceFileLoader('vhdx_copy', str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)


class CopyTests(unittest.TestCase):
 def setUp(self):
  self.tmp = tempfile.TemporaryDirectory()
  self.root = pathlib.Path(self.tmp.name)
  self.dest = self.root / 'dest'
  self.dest.mkdir()

 def tearDown(self):
  self.tmp.cleanup()

 def test_file_source_replaces_only_corresponding_file(self):
  src = self.root / 'game.bin'
  src.write_bytes(b'fresh\x00data')
  (self.dest / 'game.bin').write_bytes(b'old')
  (self.dest / 'keep.txt').write_text('untouched')
  files, dirs, total, _ = helper.copy_tree(src, self.dest)
  self.assertEqual((files, dirs, total), (1, 0, 10))
  self.assertEqual((self.dest / 'game.bin').read_bytes(), b'fresh\x00data')
  self.assertEqual((self.dest / 'keep.txt').read_text(), 'untouched')
  self.assertFalse(list(self.dest.glob('.vhdx-copy-*')))

 def test_directory_source_merges_contents_and_keeps_extra(self):
  src = self.root / 'source'
  (src / 'nested').mkdir(parents=True)
  (src / 'nested' / 'item').write_bytes(b'abc')
  (src / 'empty').mkdir()
  (self.dest / 'extra').write_bytes(b'keep')
  files, dirs, total, _ = helper.copy_tree(src, self.dest)
  self.assertEqual((files, dirs, total), (1, 2, 3))
  self.assertEqual((self.dest / 'nested' / 'item').read_bytes(), b'abc')
  self.assertEqual((self.dest / 'extra').read_bytes(), b'keep')
  self.assertFalse((self.dest / 'source').exists())

 def test_existing_directory_conflict_does_not_delete_it(self):
  src = self.root / 'entry'
  src.write_text('new')
  (self.dest / 'entry').mkdir()
  with self.assertRaises(ValueError): helper.copy_tree(src, self.dest)
  self.assertTrue((self.dest / 'entry').is_dir())

 def test_failed_replacement_retains_old_destination_and_cleans_temporary(self):
  src = self.root / 'entry'
  src.write_bytes(b'new')
  target = self.dest / 'entry'
  target.write_bytes(b'old')
  with patch.object(helper.os, 'replace', side_effect=OSError('replace failed')):
   with self.assertRaises(OSError): helper.copy_tree(src, self.dest)
  self.assertEqual(target.read_bytes(), b'old')
  self.assertFalse(list(self.dest.glob('.vhdx-copy-*')))

 def test_failed_hash_readback_preserves_destination(self):
  src = self.root / 'entry'
  src.write_bytes(b'new')
  target = self.dest / 'entry'
  target.write_bytes(b'old')
  real_open = builtins.open
  def bad_readback(path, mode='r', *args, **kwargs):
   if mode == 'rb' and pathlib.Path(path).name.startswith('.vhdx-copy-'):
    return io.BytesIO(b'corrupted')
   return real_open(path, mode, *args, **kwargs)
  with patch('builtins.open', side_effect=bad_readback):
   with self.assertRaisesRegex(IOError, 'Hash mismatch'):
    helper.copy_tree(src, self.dest)
  self.assertEqual(target.read_bytes(), b'old')
  self.assertFalse(list(self.dest.glob('.vhdx-copy-*')))
 def test_missing_source_rejected(self):
  with self.assertRaises(ValueError): helper.copy_tree(self.root / 'missing', self.dest)

if __name__ == '__main__': unittest.main()

