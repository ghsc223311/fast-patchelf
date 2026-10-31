#!/usr/bin/env python3
"""Prepare a CTF ELF without executing it; stdlib only, Python >= 3.9."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request


class PrepError(Exception):
    pass


def info(message):
    print('[*] ' + message, flush=True)


def run(argv, cwd=None):
    result = subprocess.run([str(x) for x in argv], cwd=cwd, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={**os.environ, 'LC_ALL': 'C'})
    if result.returncode:
        raise PrepError(f'{argv[0]} 執行失敗：{result.stderr.strip() or result.stdout.strip()}')
    return result.stdout


def elf_info(path):
    try:
        with open(path, 'rb') as stream:
            head = stream.read(20)
    except OSError as exc:
        raise PrepError(f'無法讀取 {path}: {exc}') from exc
    if len(head) < 20 or head[:4] != b'\x7fELF' or head[4] not in (1, 2) or head[5] not in (1, 2):
        raise PrepError(f'不是有效的 ELF：{path}')
    byteorder = '<' if head[5] == 1 else '>'
    kind, machine = struct.unpack(byteorder + 'HH', head[16:20])
    return {'bits': 32 if head[4] == 1 else 64, 'endian': head[5],
            'machine': machine, 'type': kind}


def same_arch(a, b):
    return all(a[key] == b[key] for key in ('bits', 'endian', 'machine'))


def buildid(path):
    found = re.search(r'Build ID:\s*(\w+)', run(['readelf', '-n', path]))
    return found.group(1) if found else None


def required_versions(path):
    """Only libc's version-needs records, not libstdc++ or other DSOs."""
    active = False
    versions = set()
    for line in run(['readelf', '-V', path]).splitlines():
        file_match = re.search(r'File:\s*(\S+)', line)
        if file_match:
            active = is_libc_name(file_match.group(1))
        if active:
            versions.update(re.findall(r'Name:\s*(GLIBC_[\w.]+)', line))
    return versions


def defined_versions(path):
    section = run(['readelf', '-V', path]).split('Version definition section', 1)
    if len(section) != 2:
        return set()
    section = section[1].split('Version needs section', 1)[0]
    return set(re.findall(r'Name:\s*(GLIBC_[\w.]+)', section))


def is_libc_name(name):
    return bool(re.fullmatch(r'libc(?:\.so\.6|-[\d.]+\.so)', Path(name).name))


def unique_files(paths, arch):
    found = set()
    for path in paths:
        if path.is_file():
            resolved = path.resolve()
            try:
                if same_arch(elf_info(resolved), arch):
                    found.add(resolved)
            except PrepError:
                continue
    return sorted(found)


def one(paths, description):
    if len(paths) != 1:
        listing = '\n  '.join(str(x) for x in paths)
        raise PrepError(f'{description}：找到 {len(paths)} 個候選。請明確指定路徑。\n  {listing}')
    return paths[0]


def find_libc(directory, arch, recursive=False):
    paths = directory.rglob('libc*.so*') if recursive else directory.glob('libc*.so*')
    return unique_files((p for p in paths if is_libc_name(p.name)), arch)


def find_loader(directory, arch, recursive=False):
    paths = directory.rglob('ld*.so*') if recursive else directory.glob('ld*.so*')
    return unique_files((p for p in paths if re.fullmatch(
        r'(?:ld-linux[^/]*\.so(?:\.\d+)?|ld-[\d.]+\.so)', p.name)), arch)


def aio_root(explicit):
    if explicit:
        root = Path(explicit).expanduser().resolve()
        if not root.is_dir():
            raise PrepError(f'glibc-aio 目錄不存在：{root}')
        return root
    for name in ('glibc-all-in-one-v2', 'glibc-all-in-one'):
        root = Path.home() / name
        if root.is_dir():
            return root.resolve()
    raise PrepError('找不到 glibc-all-in-one；請用 --aio-dir 指定，或直接提供 --libc 和 --ld。')


def aio_command(root):
    executable = shutil.which('glibc-aio')
    if executable:
        return [executable]
    # v2 checkout may be installed in a different virtualenv; use its source.
    if (root / 'glibc_aio/cli/main.py').is_file():
        return [sys.executable, '-c',
                'from glibc_aio.cli.main import main; main()']
    raise PrepError('找不到 glibc-aio v2。請依 README 安裝，或提供已有的 libc／ld。')


def package_pair(version, root, arch):
    if not re.fullmatch(r'\d+\.\d+-[A-Za-z0-9.+~:-]+_(?:amd64|i386|arm64|armhf)', version):
        raise PrepError('--version 必須是完整套件 ID，例如 2.39-0ubuntu8.9_amd64。')
    expected = {62: 'amd64', 3: 'i386', 183: 'arm64', 40: 'armhf'}.get(arch['machine'])
    if expected and not version.endswith('_' + expected):
        raise PrepError(f'套件架構與 ELF 不符，ELF 需要 {expected}。')
    directory = root / 'libs' / version
    if not directory.is_dir():
        info(f'下載 libc 與 loader：{version}')
        output = run(aio_command(root) + ['download', version], cwd=root)
        if output.strip():
            print(output.strip())
    if not directory.is_dir():
        raise PrepError(f'下載後仍找不到 {directory}；請確認 glibc-aio 的輸出目錄。')
    return (one(find_libc(directory, arch, True), '套件 libc'),
            one(find_loader(directory, arch, True), '套件 loader'))


def parse_leaks(items):
    symbols = {}
    for item in items:
        match = re.fullmatch(r'([A-Za-z_][A-Za-z_0-9]*)=((?:0x)?[0-9a-fA-F]+)', item)
        if not match:
            raise PrepError('--leak 格式為 puts=0x7ffff7e5fbe0（十六進位）。')
        name, value = match.groups()
        normalized = format(int(value, 16), 'x')
        if name in symbols and symbols[name] != normalized:
            raise PrepError(f'同一符號 {name} 提供了不同地址。')
        symbols[name] = normalized
    return symbols


def verify_leaks(libc, symbols):
    offsets = {}
    ifuncs = set()
    for line in run(['readelf', '--dyn-syms', '--wide', libc]).splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].endswith(':'):
            continue
        name = fields[7].split('@', 1)[0]
        if name in symbols and fields[6] != 'UND':
            offsets[name] = int(fields[1], 16)
            if fields[3] in ('IFUNC', 'OS_SPECIFIC'):
                ifuncs.add(name)
    bases = set()
    for name, address in symbols.items():
        if name not in offsets:
            raise PrepError(f'下載 libc 不含洩漏符號：{name}')
        if name in ifuncs:
            raise PrepError(f'{name} 是 IFUNC，解析後地址不能直接與符號偏移比對；請換普通函式。')
        value = int(address, 16)
        if value & 0xfff != offsets[name] & 0xfff:
            raise PrepError(f'{name} 的洩漏末 12 位與選定 libc 不符。')
        if value >= 0x1000:
            base = value - offsets[name]
            if base < 0 or base % 0x1000:
                raise PrepError(f'{name} 無法對應合法 libc 基址。')
            bases.add(base)
    if len(bases) > 1:
        raise PrepError('這些洩漏地址計算出的 libc 基址不一致；請使用同一次程序映射的符號地址。')


def query_libc(payload):
    request = urllib.request.Request('https://libc.rip/api/find',
                                     data=json.dumps(payload).encode(),
                                     headers={'Content-Type': 'application/json',
                                              'User-Agent': 'pwn-init/1.0'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.load(response)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise PrepError(f'libc.rip 查詢失敗：{exc}。可改用 --version 或 --libc／--ld。') from exc
    if isinstance(data, dict):
        if data.get('has_more') or data.get('total', 0) > len(data.get('results', [])):
            raise PrepError('libc.rip 候選超過單頁；請增加 --leak 符號縮小範圍。')
        data = data.get('results')
    if not isinstance(data, list) or not all(isinstance(x, dict) and isinstance(x.get('id'), str) for x in data):
        raise PrepError('libc.rip 回傳格式不符預期。')
    return data


def select_match(matches, selected, arch):
    suffix = {62: '_amd64', 3: '_i386', 183: '_arm64', 40: '_armhf'}.get(arch['machine'])
    matches = [x for x in matches if not suffix or x['id'].endswith(suffix)]
    matches = sorted({x['id']: x for x in matches}.values(), key=lambda x: x['id'])
    if not matches:
        raise PrepError('libc.rip 沒有符合此架構的候選；請核對洩漏地址。')
    info('libc.rip 候選：\n  ' + '\n  '.join(x['id'] for x in matches))
    if selected:
        return one([x for x in matches if x['id'] == selected], '--select ID')
    if len(matches) != 1:
        raise PrepError('有多個 libc 候選；請增加 --leak，或用 --select 完整ID 選擇後重跑。')
    return matches[0]


def local_pair(binary, arch, explicit_libc=None, explicit_ld=None):
    if explicit_libc:
        libc = Path(explicit_libc).expanduser().resolve(strict=True)
        loader = Path(explicit_ld).expanduser().resolve(strict=True) if explicit_ld else one(
            find_loader(libc.parent, arch), 'libc 同目錄的 loader；可用 --ld 指定')
        return libc, loader, 'explicit'
    adjacent = find_libc(binary.parent, arch)
    if adjacent:
        libc = one(adjacent, 'ELF 同目錄的 libc；可用 --libc 指定')
        return libc, one(find_loader(libc.parent, arch), '同目錄的 loader；請補上 --libc 和 --ld'), 'adjacent'
    interp = run(['patchelf', '--print-interpreter', binary]).strip()
    loader = Path(interp)
    if not loader.is_file():
        raise PrepError(f'ELF 的本機 loader 不存在：{interp}。請指定 --version 或 --libc／--ld。')
    loader = loader.resolve()
    triplet = {62: 'x86_64-linux-gnu', 3: 'i386-linux-gnu',
               183: 'aarch64-linux-gnu', 40: 'arm-linux-gnueabihf'}.get(arch['machine'])
    dirs = [loader.parent]
    if triplet:
        dirs += [Path('/lib') / triplet, Path('/usr/lib') / triplet]
    dirs += [Path('/lib64' if arch['bits'] == 64 else '/lib32'), Path('/lib'), Path('/usr/lib')]
    for directory in dirs:
        candidates = unique_files([directory / 'libc.so.6'], arch)
        if candidates:
            info('使用本機 libc；這不代表遠端題目的 libc 版本。')
            return candidates[0], loader, 'system'
    raise PrepError('無法定位本機 glibc，請提供 --libc 和 --ld。')


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def prepare(args):
    for tool in ('readelf', 'patchelf'):
        if not shutil.which(tool):
            raise PrepError(f'缺少 {tool}，Ubuntu：sudo apt install binutils patchelf')
    if args.ld and not args.libc:
        raise PrepError('--ld 必須與 --libc 一起使用。')
    if args.select and not args.leak:
        raise PrepError('--select 必須與 --leak 一起使用。')
    binary = Path(args.binary).expanduser().resolve(strict=True)
    arch = elf_info(binary)
    if arch['type'] not in (2, 3):
        raise PrepError('輸入必須是可執行 ELF 或 PIE。')
    output = Path(args.output or (binary.name + '_patched')).expanduser().absolute()
    exp = Path(args.exp).expanduser().absolute()
    manifest = Path(str(output) + '.pwn.json')
    outputs = [output, exp, manifest]
    if len({p.resolve() for p in outputs}) != 3:
        raise PrepError('輸出 ELF、exp.py 和紀錄檔路徑不能相同。')
    for path in outputs:
        if os.path.lexists(path):
            raise PrepError(f'輸出已存在，保留原檔：{path}。請用 -o／--exp 選擇新檔名。')
        if not path.parent.is_dir():
            raise PrepError(f'輸出目錄不存在：{path.parent}')
    needed = run(['patchelf', '--print-needed', binary]).splitlines()
    libc_needed = [name for name in needed if is_libc_name(name)]
    if len(libc_needed) != 1:
        raise PrepError('需要恰好一個 libc 動態依賴；不支援靜態 ELF、musl 或自訂 libc 名稱。')
    run(['patchelf', '--print-interpreter', binary])  # reject DSOs/static before network
    match = None
    if args.leak:
        match = select_match(query_libc({'symbols': parse_leaks(args.leak)}), args.select, arch)
        version = match['id'].removeprefix('libc6_')
        libc, loader = package_pair(version, aio_root(args.aio_dir), arch)
        source = 'libc.rip:' + match['id']
        if not match.get('buildid') and not match.get('sha256'):
            raise PrepError('libc.rip 未提供 Build ID 或 SHA256，無法驗證下載套件。請明確指定 --version。')
        if match.get('buildid') and buildid(libc) != match['buildid']:
            raise PrepError('下載 libc 的 Build ID 與 libc.rip 候選不符，停止修補。')
        if match.get('sha256') and sha256(libc) != match['sha256']:
            raise PrepError('下載 libc 的 SHA256 與 libc.rip 候選不符，停止修補。')
        verify_leaks(libc, parse_leaks(args.leak))
    elif args.version:
        libc, loader = package_pair(args.version, aio_root(args.aio_dir), arch)
        source = 'version:' + args.version
    else:
        libc, loader, source = local_pair(binary, arch, args.libc, args.ld)
    for path in (libc, loader):
        if not same_arch(elf_info(path), arch):
            raise PrepError(f'ELF、libc、loader 架構不一致：{path}')
    # Resolve before passing to patchelf so every embedded path is absolute.
    libc, loader = libc.resolve(), loader.resolve()
    required = required_versions(binary)
    missing = required - defined_versions(libc)
    if missing:
        raise PrepError('選定 libc 缺少 ELF 所需版本：' + ', '.join(sorted(missing)))
    info(f"ELF: {arch['bits']} 位元，machine={arch['machine']}")
    info(f'libc: {libc}\n    Build ID: {buildid(libc) or "unknown"}')
    info(f'loader: {loader}')
    old_rpath = run(['patchelf', '--print-rpath', binary]).strip()
    # An existing relative $ORIGIN is meaningful only beside the original ELF.
    if old_rpath and output.parent.resolve() != binary.parent:
        raise PrepError('原 ELF 含 RPATH，請將修補副本放在原 ELF 同目錄，以保留相對路徑語意。')
    rpath = str(libc.parent) + (':' + old_rpath if old_rpath else '')
    if any(c in str(libc.parent) for c in (':', '\n', '\r', '$')):
        raise PrepError('libc 目錄不能含冒號、換行或 $（動態載入器的路徑語法限制）。')
    template = (Path(__file__).parent / 'templates/exp.py.tmpl').read_text(encoding='utf-8')
    replacements = {'BIN_PATH': repr(str(output)), 'LIBC_PATH': repr(str(libc)),
                    'LD_PATH': repr(str(loader)), 'HOST': repr(args.host), 'PORT': str(args.port)}
    script = re.sub(r'@(BIN_PATH|LIBC_PATH|LD_PATH|HOST|PORT)@',
                    lambda m: replacements[m.group(1)], template)
    compile(script, str(exp), 'exec')
    created = []
    try:
        with tempfile.TemporaryDirectory(prefix='.pwn-init-', dir=output.parent) as staging:
            staged = Path(staging) / 'binary'
            shutil.copy2(binary, staged)
            staged.chmod(staged.stat().st_mode | 0o700)
            run(['patchelf', '--set-interpreter', loader, '--replace-needed', libc_needed[0],
                 libc, '--force-rpath', '--set-rpath', rpath, staged])
            if run(['patchelf', '--print-interpreter', staged]).strip() != str(loader):
                raise PrepError('修補後 interpreter 驗證失敗。')
            if str(libc) not in run(['patchelf', '--print-needed', staged]).splitlines():
                raise PrepError('修補後 libc 依賴驗證失敗。')
            metadata = {'input': str(binary), 'output': str(output), 'exp': str(exp),
                        'libc': str(libc), 'loader': str(loader), 'source': source,
                        'arch': arch, 'libc_buildid': buildid(libc),
                        'required_glibc': sorted(required), 'input_sha256': sha256(binary),
                        'output_sha256': sha256(staged), 'libc_sha256': sha256(libc),
                        'loader_sha256': sha256(loader), 'rpath': rpath}
            # Exclusive publication: even concurrent invocations cannot overwrite files.
            with output.open('xb') as stream, staged.open('rb') as source_stream:
                created.append(output)
                shutil.copyfileobj(source_stream, stream)
            shutil.copymode(staged, output)
            with exp.open('x', encoding='utf-8', newline='\n') as stream:
                created.append(exp)
                stream.write(script)
            exp.chmod(exp.stat().st_mode | 0o700)
            with manifest.open('x', encoding='utf-8', newline='\n') as stream:
                created.append(manifest)
                json.dump(metadata, stream, indent=2, ensure_ascii=False)
                stream.write('\n')
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise
    info(f'完成：{output}\n    範本：{exp}\n    紀錄：{manifest}')
    info('未執行題目；可用 python3 exp.py 啟動本機，或加 REMOTE HOST=... PORT=...。')


def parser():
    result = argparse.ArgumentParser(description='CTF ELF 預處理：選 libc、修補副本、生成 exp.py。')
    result.add_argument('binary', help='題目 ELF 路徑')
    group = result.add_mutually_exclusive_group()
    group.add_argument('--libc', help='題目提供的 libc 路徑；同目錄需有 loader 或加 --ld')
    group.add_argument('--version', help='glibc-aio 完整套件 ID，例如 2.39-0ubuntu8.9_amd64')
    group.add_argument('--leak', action='append', default=[], metavar='SYMBOL=HEX', help='libc.rip 查詢，可重複')
    result.add_argument('--ld', help='與 --libc 配對的 loader 路徑')
    result.add_argument('--select', metavar='ID', help='明確選擇 libc.rip 回傳的完整 ID')
    result.add_argument('--aio-dir', default=os.environ.get('GLIBC_AIO_DIR'), help='glibc-all-in-one-v2 目錄')
    result.add_argument('-o', '--output', help='修補 ELF 路徑，預設當前目錄 <原檔名>_patched')
    result.add_argument('--exp', default='exp.py', help='範本輸出路徑，預設當前目錄 exp.py')
    result.add_argument('--host', default='', help='填入 exp.py 的遠端主機')
    result.add_argument('--port', type=int, default=0, help='填入 exp.py 的遠端埠號')
    return result


def main():
    args = parser().parse_args()
    try:
        if sys.platform != 'linux':
            raise PrepError('請在 WSL Ubuntu 或 Linux 中執行 bash pwn-init.sh。')
        if not 0 <= args.port <= 65535:
            raise PrepError('--port 必須介於 1 到 65535，或保留 0 待填。')
        prepare(args)
        return 0
    except (PrepError, OSError, ValueError) as exc:
        print(f'[-] {exc}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('\n[-] 已取消。', file=sys.stderr)
        return 130


if __name__ == '__main__':
    sys.exit(main())
