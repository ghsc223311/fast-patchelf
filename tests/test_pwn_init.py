import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pwn_init', ROOT / 'pwn_init.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class LibcLookupTests(unittest.TestCase):
    def test_multiple_matches_require_selection_and_filter_arch(self):
        matches = [{'id': 'libc6_2.39-0ubuntu8.9_amd64'},
                   {'id': 'libc6_2.39-0ubuntu8.8_amd64'},
                   {'id': 'libc6_2.39-0ubuntu8.9_i386'}]
        arch = {'machine': 62}
        with self.assertRaises(tool.PrepError):
            tool.select_match(matches, None, arch)
        selected = tool.select_match(matches, matches[0]['id'], arch)
        self.assertEqual(selected, matches[0])
        with self.assertRaises(tool.PrepError):
            tool.select_match(matches, 'not-a-candidate', arch)

    def test_api_array_and_pagination(self):
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'[{"id":"libc6_test_amd64"}]'
        with patch.object(tool.urllib.request, 'urlopen', return_value=response) as request:
            self.assertEqual(tool.query_libc({'symbols': {'puts': 'abc'}})[0]['id'], 'libc6_test_amd64')
            self.assertEqual(json.loads(request.call_args[0][0].data), {'symbols': {'puts': 'abc'}})
        response.__enter__.return_value.read.return_value = b'{"results":[],"total":20,"has_more":true}'
        with patch.object(tool.urllib.request, 'urlopen', return_value=response):
            with self.assertRaises(tool.PrepError):
                tool.query_libc({'symbols': {}})

    def test_invalid_leak_and_conflicts(self):
        for values in (['puts=nope'], ['puts=123', 'puts=456']):
            with self.assertRaises(tool.PrepError):
                tool.parse_leaks(values)
        self.assertEqual(tool.parse_leaks(['puts=0xABC', 'puts=abc']), {'puts': 'abc'})

    def test_leaks_from_different_mappings_rejected(self):
        symbols = ('  1: 0000000000001230 1 FUNC GLOBAL DEFAULT 1 puts@@GLIBC_2.2.5\n'
                   '  2: 0000000000002460 1 FUNC GLOBAL DEFAULT 1 printf@@GLIBC_2.2.5\n')
        with patch.object(tool, 'run', return_value=symbols):
            tool.verify_leaks(Path('unused'), {'puts': '71230', 'printf': '72460'})
            with self.assertRaises(tool.PrepError):
                tool.verify_leaks(Path('unused'), {'puts': '71230', 'printf': '82460'})


@unittest.skipUnless(sys.platform == 'linux' and all(shutil.which(x) for x in
                     ('gcc', 'readelf', 'patchelf', 'bash')), 'requires Linux compiler and ELF tools')
class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pwn test ' 中文 ")
        self.work = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        source = self.work / 'hello.c'
        source.write_text('#include <stdio.h>\nint main(void) { puts("ELF_OK"); return 0; }\n')
        self.binary = self.work / 'hello'
        subprocess.run(['gcc', str(source), '-o', str(self.binary)], check=True)
        self.original = self.binary.read_bytes()
        self.arch = tool.elf_info(self.binary)
        self.libc, self.loader, _ = tool.local_pair(self.binary, self.arch)

    def invoke(self, *args, success=True):
        result = subprocess.run(['bash', str(ROOT / 'pwn-init.sh'), str(self.binary), *map(str, args)],
                                cwd=self.work, text=True, capture_output=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        self.assertEqual(self.binary.read_bytes(), self.original)
        return result

    def test_default_patch_exec_and_template(self):
        self.invoke('--host', "host'@BIN_PATH@", '--port', '31337')
        output = self.work / 'hello_patched'
        result = subprocess.run([str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'ELF_OK\n')
        manifest = json.loads((self.work / 'hello_patched.pwn.json').read_text())
        self.assertEqual(manifest['libc'], str(self.libc))
        self.assertEqual(manifest['input_sha256'], hashlib.sha256(self.original).hexdigest())
        script = (self.work / 'exp.py').read_text()
        tree = ast.parse(script)
        values = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body
                  if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                  and node.targets[0].id in ('BIN_PATH', 'LIBC_PATH', 'LD_PATH')}
        self.assertEqual(values['BIN_PATH'], str(output))
        self.assertEqual(values['LIBC_PATH'], str(self.libc))
        self.assertIn("host'@BIN_PATH@", script)
        self.invoke(success=False)
        self.assertEqual(json.loads((self.work / 'hello_patched.pwn.json').read_text()), manifest)

    def test_existing_exp_preserved_before_patch(self):
        (self.work / 'exp.py').write_text('KEEP\n')
        self.invoke(success=False)
        self.assertEqual((self.work / 'exp.py').read_text(), 'KEEP\n')
        self.assertFalse((self.work / 'hello_patched').exists())

    def test_generated_template_runs_with_pwntools(self):
        if importlib.util.find_spec('pwn') is None:
            self.skipTest('pwntools not installed')
        self.invoke()
        result = subprocess.run([sys.executable, str(self.work / 'exp.py')], cwd=self.work,
                                input='', text=True, capture_output=True, timeout=20,
                                env={**os.environ, 'TERM': 'xterm', 'PWNLIB_NOTERM': '1'})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('ELF_OK', result.stdout)

    def test_explicit_pair(self):
        self.invoke('--libc', self.libc, '--ld', self.loader)
        self.assertEqual(subprocess.check_output([str(self.work / 'hello_patched')]), b'ELF_OK\n')

    def test_adjacent_libc_without_loader_stops(self):
        shutil.copy2(self.libc, self.work / 'libc.so.6')
        self.invoke(success=False)
        self.assertFalse((self.work / 'exp.py').exists())

    def test_adjacent_pair(self):
        shutil.copy2(self.libc, self.work / 'libc.so.6')
        shutil.copy2(self.loader, self.work / self.loader.name)
        self.invoke()
        result = subprocess.run([str(self.work / 'hello_patched')], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wrong_arch(self):
        fake = self.work / 'wrong-libc.so'
        data = bytearray(self.libc.read_bytes())
        data[18:20] = b'\xb7\x00'  # AArch64 machine ID in an otherwise real DSO
        fake.write_bytes(data)
        self.invoke('--libc', fake, '--ld', self.loader, success=False)
        self.assertFalse((self.work / 'exp.py').exists())

    def test_static_rejected(self):
        result = subprocess.run(['gcc', '-static', str(self.work / 'hello.c'), '-o', str(self.binary)],
                                capture_output=True)
        if result.returncode:
            self.skipTest('static development libc not installed')
        self.original = self.binary.read_bytes()
        self.invoke(success=False)
        self.assertFalse((self.work / 'hello_patched').exists())

    def test_version_cache_and_leak_identity(self):
        root = self.work / 'aio'
        version = '2.39-0test1_' + {62: 'amd64', 3: 'i386', 183: 'arm64', 40: 'armhf'}[self.arch['machine']]
        package = root / 'libs' / version / 'triplet'
        package.mkdir(parents=True)
        shutil.copy2(self.libc, package / 'libc.so.6')
        shutil.copy2(self.loader, package / self.loader.name)
        args = tool.parser().parse_args([str(self.binary), '--version', version, '--aio-dir', str(root),
                                        '-o', str(self.work / 'vpatched'), '--exp', str(self.work / 'vexp.py')])
        tool.prepare(args)
        self.assertEqual(subprocess.check_output([str(self.work / 'vpatched')]), b'ELF_OK\n')
        args.version = None
        args.leak = ['puts=0']
        args.output = str(self.work / 'leakpatched')
        args.exp = str(self.work / 'leakexp.py')
        with patch.object(tool, 'query_libc', return_value=[{'id': 'libc6_' + version, 'buildid': 'bad'}]):
            with self.assertRaisesRegex(tool.PrepError, 'Build ID'):
                tool.prepare(args)
        self.assertFalse((self.work / 'leakpatched').exists())

    def test_failed_patch_cleans_up(self):
        original_run = tool.run

        def broken_run(argv, **kwargs):
            if '--set-interpreter' in argv:
                raise tool.PrepError('simulated patch failure')
            return original_run(argv, **kwargs)

        args = tool.parser().parse_args([str(self.binary), '-o', str(self.work / 'failed'),
                                        '--exp', str(self.work / 'failed.py')])
        with patch.object(tool, 'run', side_effect=broken_run):
            with self.assertRaises(tool.PrepError):
                tool.prepare(args)
        self.assertFalse((self.work / 'failed').exists())
        self.assertFalse(list(self.work.glob('.pwn-init-*')))

    def test_missing_glibc_requirement_stops(self):
        args = tool.parser().parse_args([str(self.binary), '-o', str(self.work / 'oldlibc'),
                                        '--exp', str(self.work / 'oldlibc.py')])
        with patch.object(tool, 'defined_versions', return_value=set()):
            with self.assertRaisesRegex(tool.PrepError, 'GLIBC_'):
                tool.prepare(args)
        self.assertFalse((self.work / 'oldlibc').exists())

    def test_cache_miss_invokes_aio_in_correct_directory(self):
        root = self.work / 'download-root'
        root.mkdir()
        version = '2.39-0test1_' + {62: 'amd64', 3: 'i386', 183: 'arm64', 40: 'armhf'}[self.arch['machine']]
        original_run = tool.run

        def fake_download(argv, cwd=None):
            if argv[0] == 'fake-glibc-aio':
                self.assertEqual(Path(cwd), root)
                self.assertEqual(argv[1:], ['download', version])
                destination = root / 'libs' / version / 'triplet'
                destination.mkdir(parents=True)
                shutil.copy2(self.libc, destination / 'libc.so.6')
                shutil.copy2(self.loader, destination / self.loader.name)
                return 'downloaded\n'
            return original_run(argv, cwd=cwd)

        with patch.object(tool, 'aio_command', return_value=['fake-glibc-aio']), \
                patch.object(tool, 'run', side_effect=fake_download):
            libc, loader = tool.package_pair(version, root, self.arch)
        self.assertTrue(libc.is_file() and loader.is_file())


@unittest.skipUnless(sys.platform == 'linux' and os.environ.get('PWN_TEST_AIO_DIR'),
                     'set PWN_TEST_AIO_DIR for cached Ubuntu 2.39-0ubuntu8.9 tests')
class CachedUbuntuTests(unittest.TestCase):
    def test_amd64_and_i386_real_packages(self):
        for arch, compiler_flag in [('amd64', '-m64'), ('i386', '-m32')]:
            with self.subTest(arch=arch), tempfile.TemporaryDirectory(prefix='pwn-cached-') as temp:
                work = Path(temp)
                source = work / 'hello.c'
                source.write_text('#include <stdio.h>\nint main(void){puts("CACHED_OK");return 0;}\n')
                binary = work / 'hello'
                subprocess.run(['gcc', compiler_flag, str(source), '-o', str(binary)], check=True)
                result = subprocess.run(['bash', str(ROOT / 'pwn-init.sh'), str(binary),
                                         '--version', '2.39-0ubuntu8.9_' + arch,
                                         '--aio-dir', os.environ['PWN_TEST_AIO_DIR']],
                                        cwd=work, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(subprocess.check_output([str(work / 'hello_patched')]), b'CACHED_OK\n')
                self.assertEqual(tool.elf_info(work / 'hello_patched')['bits'], 64 if arch == 'amd64' else 32)

    @unittest.skipUnless(os.environ.get('PWN_TEST_LIVE') == '1' and shutil.which('gdb'),
                         'set PWN_TEST_LIVE=1 to query libc.rip with actual GDB addresses')
    def test_gdb_addresses_to_live_libc_rip(self):
        with tempfile.TemporaryDirectory(prefix='pwn-live-') as temp:
            work = Path(temp)
            source = work / 'hello.c'
            source.write_text('#include <stdio.h>\nint main(void){puts("LIVE_OK");return 0;}\n')
            binary = work / 'hello'
            subprocess.run(['gcc', '-g', str(source), '-o', str(binary)], check=True)
            args = tool.parser().parse_args([str(binary), '--version', '2.39-0ubuntu8.9_amd64',
                                            '--aio-dir', os.environ['PWN_TEST_AIO_DIR'],
                                            '-o', str(work / 'probe'), '--exp', str(work / 'probe.py')])
            tool.prepare(args)
            command = ['gdb', '-nx', '-q', '-batch', '-ex', 'set debuginfod enabled off', '-ex', 'start']
            for name in ('printf', 'puts', 'fgets', 'fputs'):
                command.extend(['-ex', f'p/x (void *) {name}'])
            command.append(str(work / 'probe'))
            output = subprocess.check_output(command, text=True, stderr=subprocess.STDOUT,
                                             timeout=30, env={**os.environ, 'LC_ALL': 'C'})
            addresses = tool.re.findall(r'^\$\d+ = (0x[0-9a-f]+)$', output, tool.re.MULTILINE)
            self.assertEqual(len(addresses), 4, output)
            argv = ['bash', str(ROOT / 'pwn-init.sh'), str(binary),
                    '--aio-dir', os.environ['PWN_TEST_AIO_DIR'],
                    '--select', 'libc6_2.39-0ubuntu8.9_amd64']
            for name, address in zip(('printf', 'puts', 'fgets', 'fputs'), addresses):
                argv.extend(['--leak', name + '=' + address])
            result = subprocess.run(argv, cwd=work, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(subprocess.check_output([str(work / 'hello_patched')]), b'LIVE_OK\n')


if __name__ == '__main__':
    unittest.main()
