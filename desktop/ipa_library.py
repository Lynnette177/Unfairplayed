"""Local IPA inventory and cached metadata; archives are never modified."""
import datetime
import fcntl
import functools
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import struct
import subprocess
import tempfile
import zipfile


def library_store():
    return Path.home() / 'Library/Application Support/Unfairplayed/ipa-library.json'


def cache_directory():
    return Path.home() / 'Library/Caches/Unfairplayed/IPALibrary'


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix='.ipa-', delete=False) as f:
        json.dump(value, f, ensure_ascii=False)
        temporary = Path(f.name)
    temporary.replace(path)


def registered_paths():
    try:
        values = json.loads(library_store().read_text())
        return [Path(p) for p in values if isinstance(p, str)] if isinstance(values, list) else []
    except (OSError, ValueError):
        return []


def add_paths(paths):
    items = [Path(p).expanduser().resolve() for p in paths]
    if any(p.suffix.lower() != '.ipa' or not p.is_file() for p in items):
        raise ValueError('请选择存在的 IPA 文件')
    path = library_store()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_suffix('.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        values = list(dict.fromkeys([str(p) for p in items] + [str(p) for p in registered_paths()]))
        write_json(path, values)


def encryption_state(stream, length):
    """Read only the main Mach-O headers, including all universal slices."""
    def read_at(offset, count):
        if offset < 0 or offset + count > length:
            raise ValueError('truncated Mach-O')
        stream.seek(offset)
        data = stream.read(count)
        if len(data) != count:
            raise ValueError('truncated Mach-O')
        return data

    def inspect(offset, depth=0):
        if depth > 1:
            raise ValueError('nested universal binary')
        magic = read_at(offset, 4)
        fat = {b'\xca\xfe\xba\xbe': ('>', False), b'\xbe\xba\xfe\xca': ('<', False),
               b'\xca\xfe\xba\xbf': ('>', True), b'\xbf\xba\xfe\xca': ('<', True)}
        if magic in fat:
            endian, wide = fat[magic]
            count = struct.unpack(endian + 'I', read_at(offset + 4, 4))[0]
            if not 0 < count <= 32:
                raise ValueError('invalid universal header')
            states = []
            size = 32 if wide else 20
            for index in range(count):
                header = read_at(offset + 8 + size * index, size)
                child = struct.unpack_from(endian + ('Q' if wide else 'I'), header, 8)[0]
                states.append(inspect(offset + child, depth + 1))
            return any(states)
        thin = {b'\xcf\xfa\xed\xfe': ('<', 32), b'\xce\xfa\xed\xfe': ('<', 28),
                b'\xfe\xed\xfa\xcf': ('>', 32), b'\xfe\xed\xfa\xce': ('>', 28)}
        if magic not in thin:
            raise ValueError('not a Mach-O')
        endian, size = thin[magic]
        header = read_at(offset, size)
        count, command_bytes = struct.unpack_from(endian + 'II', header, 16)
        if count > 65536 or command_bytes > 4 * 1024 * 1024:
            raise ValueError('invalid load commands')
        commands = read_at(offset + size, command_bytes)
        position = 0
        for _ in range(count):
            if position + 8 > len(commands):
                raise ValueError('invalid load commands')
            command, command_size = struct.unpack_from(endian + 'II', commands, position)
            if command_size < 8 or position + command_size > len(commands):
                raise ValueError('invalid load command')
            if command in (0x21, 0x2c):
                if command_size < 20:
                    raise ValueError('invalid encryption command')
                if struct.unpack_from(endian + 'I', commands, position + 16)[0] != 0:
                    return True
            position += command_size
        return False

    try:
        return 'encrypted' if inspect(0) else 'decrypted'
    except (OSError, ValueError, struct.error):
        return 'unknown'


@functools.lru_cache(maxsize=1)
def pngcrush_path():
    try:
        result = subprocess.run(['xcrun', '--find', 'pngcrush'], capture_output=True, text=True, timeout=5)
        return result.stdout.strip() if result.returncode == 0 else ''
    except (OSError, subprocess.TimeoutExpired):
        return ''


def extract_icon(archive, prefix, info, destination):
    names = set(archive.namelist())
    bases = []
    for key in ('CFBundleIcons', 'CFBundleIcons~ipad'):
        primary = info.get(key, {}).get('CFBundlePrimaryIcon', {})
        bases += primary.get('CFBundleIconFiles', [])
    bases += info.get('CFBundleIconFiles', [])
    if info.get('CFBundleIconFile'):
        bases.append(info['CFBundleIconFile'])
    candidates = []
    for name in names:
        relative = name[len(prefix):] if name.startswith(prefix) else ''
        if relative and '/' not in relative and name.lower().endswith('.png'):
            if any(relative.startswith(str(base).removesuffix('.png')) for base in bases) or relative.lower().startswith('appicon'):
                candidates.append(name)
    candidates.sort(key=lambda n: (archive.getinfo(n).file_size, '@3x' in n, '@2x' in n), reverse=True)
    candidates += [n for n in ('iTunesArtwork@2x', 'iTunesArtwork') if n in names]
    for name in candidates:
        entry = archive.getinfo(name)
        if not 0 < entry.file_size <= 8 * 1024 * 1024:
            continue
        data = archive.read(entry)
        if not data.startswith((b'\x89PNG\r\n\x1a\n', b'\xff\xd8')):
            continue
        destination.write_bytes(data)
        if data.startswith(b'\x89PNG') and b'CgBI' in data[:80]:
            tool = pngcrush_path()
            if tool:
                converted = destination.with_suffix('.converted.png')
                try:
                    result = subprocess.run([tool, '-q', '-revert-iphone-optimizations', str(destination), str(converted)],
                                            capture_output=True, timeout=10)
                    if result.returncode == 0 and converted.is_file():
                        converted.replace(destination)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                finally:
                    converted.unlink(missing_ok=True)
        return str(destination)
    return ''


def inspect_ipa(path):
    path = path.expanduser().resolve()
    stat = path.stat()
    key = hashlib.sha256(str(path).encode()).hexdigest()[:24]
    stamp = [stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_ino]
    cache = cache_directory(); cache.mkdir(parents=True, exist_ok=True)
    metadata_path = cache / (key + '.json')
    try:
        old = json.loads(metadata_path.read_text())
        if old.get('schema') == 1 and old.get('stamp') == stamp and (not old['item'].get('icon') or Path(old['item']['icon']).is_file()):
            return old['item']
    except (OSError, ValueError, KeyError, TypeError):
        pass
    item = {'id': str(path), 'path': str(path), 'name': path.stem, 'bundle': '', 'version': '',
            'size': stat.st_size, 'modified': stat.st_mtime, 'icon': '', 'kind': 'downloaded',
            'state': 'unknown', 'error': '', 'partial': '-PARTIAL' in path.stem.upper(), 'signed': 'signed' in path.stem}
    try:
        with zipfile.ZipFile(path) as archive:
            roots = [n for n in archive.namelist() if re.fullmatch(r'Payload/[^/]+\.app/Info\.plist', n)]
            if len(roots) != 1:
                raise ValueError('IPA 需包含一个主 App')
            entry = archive.getinfo(roots[0])
            if entry.file_size > 4 * 1024 * 1024:
                raise ValueError('Info.plist 超过读取上限')
            info = plistlib.loads(archive.read(entry))
            prefix = roots[0][:-len('Info.plist')]
            item.update(name=str(info.get('CFBundleDisplayName') or info.get('CFBundleName') or path.stem),
                        bundle=str(info.get('CFBundleIdentifier') or ''), version=str(info.get('CFBundleShortVersionString') or ''))
            executable = info.get('CFBundleExecutable', '')
            if executable and PurePosixPath(executable).name == executable:
                binary = archive.getinfo(prefix + executable)
                with archive.open(binary) as stream:
                    item['state'] = encryption_state(stream, binary.file_size)
            item['kind'] = 'decrypted' if item['state'] == 'decrypted' and not item['partial'] else 'downloaded'
            item['icon'] = extract_icon(archive, prefix, info, cache / (key + '.png'))
    except Exception as error:
        # One damaged archive must not hide the rest of the library.
        item['error'] = str(error)
    write_json(metadata_path, {'schema': 1, 'stamp': stamp, 'item': item})
    return item


def discovered_paths(directory):
    for folder, directories, files in os.walk(directory, followlinks=False):
        directories[:] = [name for name in directories if not name.lower().endswith('.app') and
                           not (Path(folder) == directory and name == 'debug')]
        for name in files:
            if name.lower().endswith('.ipa'):
                yield Path(folder) / name


def inventory(root):
    downloads = Path.home() / 'Downloads'
    output = downloads / 'Unfairplayed-Output'
    paths = set(registered_paths())
    if downloads.is_dir():
        paths.update(p for p in downloads.iterdir() if p.suffix.lower() == '.ipa')
    for directory in (output, root / 'iOS/out'):
        if directory.is_dir():
            paths.update(discovered_paths(directory))
    result = []
    for path in paths:
        try:
            if path.is_file():
                result.append(inspect_ipa(path))
        except OSError:
            continue
    unique = {item['path']: item for item in result}
    return sorted(unique.values(), key=lambda item: item['modified'], reverse=True)
