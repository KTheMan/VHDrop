import importlib.util
from pathlib import Path, PurePosixPath
import os
import tempfile
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('smb_guard',Path(__file__).with_name('smb_guard.py'))
g=importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

class FakeRemote:
 def __init__(self): self.closed=False
 def close(self): self.closed=True
class FakeClient:
 def __init__(self): self.reset=False
 def reset_connection_cache(self,**kwargs): self.reset=True

@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0, 'root-owned Linux fixture required')
class GuardTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir='/run'); self.root=Path(self.temp.name)
  self.folder=self.root/'Projects';self.folder.mkdir();self.image=self.folder/'fixture.vhdx';self.image.write_bytes(b'safe test image')
  self.root_patch=mock.patch.object(g,'LOCAL_ROOT',self.root);self.root_patch.start()
  self.mapping=mock.patch.object(g,'_mapping_check');self.mapping.start()
  self.remote=FakeRemote();self.client=FakeClient()
  self.connect=mock.patch.object(g,'_connect',return_value=(self.remote,{},self.client));self.connect.start()
  self.info_patch=mock.patch.object(g,'_same_handle_info',side_effect=lambda _:(os.stat(self.image).st_ino,os.stat(self.image).st_size));self.info=self.info_patch.start()
 def tearDown(self):
  self.info_patch.stop();self.connect.stop();self.mapping.stop();self.root_patch.stop();self.temp.cleanup()
 def test_guard_lifetime_and_identity(self):
  with g.acquire_verified_guard(str(self.image)) as guard:
   self.assertTrue(guard.verified);self.assertEqual(guard.inode,self.image.stat().st_ino)
   guard.assert_still_exclusive();self.assertFalse(self.remote.closed)
  self.assertFalse(guard.verified);self.assertTrue(self.remote.closed);self.assertTrue(self.client.reset)
  with self.assertRaises(RuntimeError):guard.assert_still_exclusive()
 def test_replacement_is_detected(self):
  with g.acquire_verified_guard(str(self.image)) as guard:
   backup=self.folder/'old.vhdx';self.image.rename(backup);self.image.write_bytes(b'new')
   with self.assertRaises(RuntimeError):guard.assert_still_exclusive()
   self.assertFalse(guard.verified)
 def test_smb_mismatch_fails_and_closes(self):
  self.info.side_effect=lambda _:(self.image.stat().st_ino+1,self.image.stat().st_size)
  with self.assertRaisesRegex(RuntimeError,'identity or size'): 
   with g.acquire_verified_guard(str(self.image)):pass
  self.assertTrue(self.remote.closed);self.assertTrue(self.client.reset)
 def test_rejects_outside_dotdot_and_symlink(self):
  with self.assertRaises(ValueError):g._checked_local(str(self.root.parent/'outside.vhdx'))
  with self.assertRaises(ValueError):g._checked_local(str(self.folder/'..'/'fixture.vhdx'))
  (self.root/'link').symlink_to(self.folder,target_is_directory=True)
  with self.assertRaises(OSError):g._checked_local(str(self.root/'link'/'fixture.vhdx'))
 def test_mapping_mismatch_is_rejected(self):
  self.mapping.stop()
  info=os.stat(self.image)
  with mock.patch.object(g,'GUEST_ROOT',PurePosixPath('/srv/share')), mock.patch.object(g,'SMB_SHARE','share'), mock.patch.object(g,'CONTAINER_ID','123'):
   with mock.patch.object(g,'_pct',return_value='/wrong/share'):
    with self.assertRaisesRegex(RuntimeError,'share path changed'):g._mapping_check(Path('Projects/fixture.vhdx'),info)
   with mock.patch.object(g,'_pct',side_effect=['/srv/share','999:999']):
    with self.assertRaisesRegex(RuntimeError,'identities differ'):g._mapping_check(Path('Projects/fixture.vhdx'),info)
   marker=self.root/'.vhdx-handoff'/'operations'; marker.mkdir(parents=True)
   with mock.patch.object(g,'_pct',side_effect=['/srv/share',f'{info.st_dev}:{info.st_ino}','999:999']):
    with self.assertRaisesRegex(RuntimeError,'coordination directory identities differ'):g._mapping_check(Path('Projects/fixture.vhdx'),info)
 def test_local_samba_checks_export_and_host_identity(self):
  self.mapping.stop()
  marker=self.root/'.vhdx-handoff'/'operations';marker.mkdir(parents=True)
  info=os.stat(self.image); marker_info=os.stat(marker)
  with mock.patch.object(g,'GUEST_ROOT',PurePosixPath(str(self.root))), mock.patch.object(g,'SMB_SHARE','share'), mock.patch.object(g,'CONTAINER_ID',''):
   with mock.patch.object(g,'_pct',side_effect=[str(self.root),f'{info.st_dev}:{info.st_ino}',f'{marker_info.st_dev}:{marker_info.st_ino}']):
    g._mapping_check(Path('Projects/fixture.vhdx'),info)
   with mock.patch.object(g,'_pct',side_effect=['/wrong',f'{info.st_dev}:{info.st_ino}']):
    with self.assertRaisesRegex(RuntimeError,'share path changed'):g._mapping_check(Path('Projects/fixture.vhdx'),info)
 def test_local_and_lxc_commands_do_not_use_shell(self):
  result=mock.Mock(returncode=0,stdout='value\n',stderr='')
  with mock.patch.object(g.subprocess,'run',return_value=result) as run:
   with mock.patch.object(g,'CONTAINER_ID',''):
    self.assertEqual(g._pct('stat','--','/test path'),'value')
    self.assertEqual(run.call_args.args[0],['stat','--','/test path'])
   with mock.patch.object(g,'CONTAINER_ID','123'):
    g._pct('stat','--','/test path')
    self.assertEqual(run.call_args.args[0],['pct','exec','123','--','stat','--','/test path'])
 def test_session_nonce_binds_the_actual_share_and_cleans_up(self):
  import io
  marker=self.root/'.vhdx-handoff'/'operations';marker.mkdir(parents=True)
  class Client:
   def __init__(self, wrong=False): self.wrong=wrong
   def open_file(self,unc,**kwargs):
    name=unc.split('\\')[-1]
    return io.BytesIO(b'wrong server' if self.wrong else (marker/name).read_bytes())
  with mock.patch.object(g,'SMB_ROOT',r'\\server\share'):
   g._verify_session_mapping(Client(),{})
   self.assertEqual(list(marker.iterdir()),[])
   with self.assertRaisesRegex(RuntimeError,'identity probe differ'):
    g._verify_session_mapping(Client(True),{})
   self.assertEqual(list(marker.iterdir()),[])
 def test_session_nonce_rejects_writable_coordination_dir(self):
  marker=self.root/'.vhdx-handoff'/'operations';marker.mkdir(parents=True);marker.chmod(0o777)
  with mock.patch.object(g,'SMB_ROOT',r'\\server\share'):
   with self.assertRaisesRegex(RuntimeError,'Untrusted coordination'):
    g._verify_session_mapping(mock.Mock(),{})
 def test_closed_remote_failure_invalidates_guard(self):
  with g.acquire_verified_guard(str(self.image)) as guard:
   self.info.side_effect=OSError('session lost')
   with self.assertRaises(OSError):guard.assert_still_exclusive()
   self.assertFalse(guard.verified)

if __name__=='__main__':unittest.main()


