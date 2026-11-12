import json
import hashlib
import base64
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile
from unittest import mock

import host_config
import setup_copy
import setup_guard


class GuardConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.config = {
            'local_root': str(self.root), 'guest_root': '/srv/share',
            'smb_host': 'nas.example', 'smb_share': 'share', 'container_id': '123',
            'guest_username': 'guest', 'guest_smb_acknowledged': True,
        }

    def tearDown(self): self.tmp.cleanup()

    def test_explicit_mapping_is_accepted(self):
        self.assertEqual(host_config.parse(self.config), self.config)

    def test_colocated_samba_requires_exact_same_root(self):
        local = {**self.config, 'container_id': '', 'guest_root': str(self.root)}
        self.assertEqual(host_config.parse(local), local)
        with self.assertRaisesRegex(ValueError, 'identical'):
            host_config.parse({**local, 'guest_root': '/different/share'})

    def test_unacknowledged_guest_or_unknown_secret_fails_closed(self):
        for changes in ({'guest_smb_acknowledged': False}, {'password': 'not-a-real-secret'}):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError): host_config.parse({**self.config, **changes})

    def test_bad_topology_values_are_rejected(self):
        for changes in ({'local_root': '/'}, {'guest_root': '/srv/../escape'},
                        {'smb_host': 'host;cmd'}, {'smb_share': '../bad'},
                        {'container_id': '123;cmd'}, {'guest_username': 'x/y'}):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError): host_config.parse({**self.config, **changes})

    def test_missing_or_symlink_config_is_rejected(self):
        with self.assertRaises((ValueError, OSError)):
            host_config.load(self.root / 'missing.json')
        target = self.root / 'target.json'
        target.write_text(json.dumps(self.config), encoding='utf-8')
        link = self.root / 'guard.json'
        try: link.symlink_to(target)
        except (OSError, NotImplementedError): self.skipTest('symlinks unavailable')
        with self.assertRaises((ValueError, OSError)): host_config.load(link)


class InstallerIntegrityTests(unittest.TestCase):
    def test_unsupported_python_fails_before_install_changes(self):
        with mock.patch.object(setup_copy.sys, 'version_info', (3, 14, 0)), \
             mock.patch.object(setup_copy, 'marker_check') as marker, \
             mock.patch.object(setup_copy, 'install_dir') as destination, \
             mock.patch.object(setup_copy.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, '3.10 through 3.13'):
                setup_copy.install(Path('/unused'))
            marker.assert_not_called(); destination.assert_not_called(); run.assert_not_called()

    def test_install_uses_versioned_venv_without_touching_legacy(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / 'install'
            legacy = dest / 'venv'; legacy.mkdir(parents=True)
            sentinel = legacy / 'sentinel'; sentinel.write_text('preserve')
            with mock.patch.object(setup_copy.sys, 'version_info', (3, 11, 0)), \
                 mock.patch.object(setup_copy, 'marker_check'), \
                 mock.patch.object(setup_copy, 'install_dir', return_value=dest), \
                 mock.patch.object(setup_copy, 'check'), \
                 mock.patch.object(setup_copy.subprocess, 'run') as run:
                setup_copy.install(Path('/example'))
            self.assertEqual(sentinel.read_text(), 'preserve')
            commands = [call.args[0] for call in run.call_args_list if len(call.args[0]) >= 3 and call.args[0][1:3] == ['-m', 'venv']]
            self.assertEqual(len(commands), 1)
            self.assertIn('venv-3.11', str(commands[0][-1]))
            self.assertIn('venv-3.11/bin/python', (dest/'bin'/'vhdx-copy').read_text())
            self.assertIn('venv-3.11/bin/python', (dest/'bin'/'vhdx-handoff-check').read_text())
            self.assertNotIn('venv/bin/python', (dest/'bin'/'vhdx-copy').read_text())
            python = dest / 'venv-3.11' / 'bin' / 'python'
            python.parent.mkdir(parents=True); python.write_text('fixture'); python.chmod(0o700)
            with mock.patch.object(setup_copy.sys, 'version_info', (3, 11, 0)), \
                 mock.patch.object(setup_copy, 'marker_check'), \
                 mock.patch.object(setup_copy, 'install_dir', return_value=dest), \
                 mock.patch.object(setup_copy.subprocess, 'run', return_value=mock.Mock(returncode=0)) as checked:
                setup_copy.check(Path('/example'))
                self.assertEqual(checked.call_args.args[0][0], str(python))

    def test_embedded_helper_digest_matches_source(self):
        helper = Path(__file__).with_name('vhdx-copy')
        self.assertEqual(hashlib.sha256(helper.read_bytes()).hexdigest(), setup_copy.HELPER_SHA256)

    @unittest.skipUnless(os.name == 'posix', 'requires Unix ownership and mode')
    def test_file_integrity_rejects_writable_or_symlink_files(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'helper'
            path.write_bytes(b'expected')
            path.chmod(0o600)
            self.assertEqual(setup_copy.protected_bytes(path), b'expected')
            path.chmod(0o666)
            with self.assertRaisesRegex(ValueError, 'unsafe ownership'):
                setup_copy.protected_bytes(path)
            path.chmod(0o600)
            link = Path(td) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError): setup_copy.protected_bytes(link)

    @unittest.skipUnless(os.name == 'posix', 'requires Unix symlinks')
    def test_atomic_install_replaces_link_not_its_target(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            victim = root / 'unrelated'; victim.write_bytes(b'preserve')
            link = root / 'launcher'; link.symlink_to(victim)
            setup_copy.atomic_write(link, b'new launcher', 0o700)
            self.assertEqual(victim.read_bytes(), b'preserve')
            self.assertFalse(link.is_symlink())
            self.assertEqual(link.read_bytes(), b'new launcher')

    @unittest.skipUnless(os.name == 'posix', 'requires Unix symlinks')
    def test_install_directory_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); target = root / 'other'; target.mkdir()
            link = root / 'bin'; link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'safely owned'):
                setup_copy.ensure_owned_dir(link)

    def test_guard_bundle_hashes_match_sources(self):
        server = Path(__file__).parent
        for name, expected in setup_guard.EXPECTED.items():
            path = server / ('vendor-wheels' if name.endswith('.whl') else '') / name
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected, name)

    def test_wheel_traversal_rejected(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as z: z.writestr('../escape', b'x')
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(ValueError, 'Unsafe wheel'):
                setup_guard.extract_wheel(archive.getvalue(), Path(td))


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() == 0,
                     'requires a root-owned disposable Linux fixture')
class MarkerSetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/run')
        self.root = Path(self.tmp.name).resolve()
    def tearDown(self): self.tmp.cleanup()

    def test_prepare_only_creates_bounded_coordination_directories(self):
        root = setup_copy.canonical_root(str(self.root))
        setup_copy.marker_check(root, create=True)
        marker = root / '.vhdx-handoff' / 'operations'
        self.assertTrue(marker.is_dir())
        self.assertEqual(marker.stat().st_uid, 0)
        setup_copy.marker_check(root)

    def test_symlink_or_writable_marker_is_refused(self):
        marker = self.root / '.vhdx-handoff'
        marker.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError): setup_copy.marker_check(self.root)
        marker.unlink()
        setup_copy.marker_check(self.root, create=True)
        operations = marker / 'operations'
        operations.chmod(0o777)
        with self.assertRaisesRegex(ValueError, 'root-owned'): setup_copy.marker_check(self.root)

    def test_guard_install_is_root_owned_and_never_overwrites(self):
        share = self.root / 'share'; share.mkdir()
        server = Path(__file__).parent
        files = {name: base64.b64encode((server / ('vendor-wheels' if name.endswith('.whl') else '') / name).read_bytes()).decode('ascii')
                 for name in setup_guard.EXPECTED}
        config = {'local_root': str(share), 'guest_root': '/srv/share', 'smb_host': 'nas.example',
                  'smb_share': 'share', 'container_id': '123', 'guest_username': 'guest', 'guest_smb_acknowledged': True}
        install = self.root / 'opt' / 'helper'; install.parent.mkdir()
        config_dir = self.root / 'etc' / 'guard'; config_dir.parent.mkdir()
        with mock.patch.object(setup_guard, 'INSTALL', install), mock.patch.object(setup_guard, 'CONFIG', config_dir), mock.patch.object(setup_guard, 'dependencies'):
            setup_guard.install({'config': config, 'files': files})
            self.assertEqual((config_dir / 'guard.json').stat().st_mode & 0o777, 0o600)
            self.assertTrue((install / 'vendor' / 'smbclient').is_dir())
            with self.assertRaisesRegex(ValueError, 'not overwritten'):
                setup_guard.install({'config': config, 'files': files})


if __name__ == '__main__': unittest.main()
