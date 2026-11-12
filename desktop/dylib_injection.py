"""Inject into an extracted installation copy, before signing. No input is modified."""
from pathlib import Path
import hashlib
import plistlib
import shutil
import struct

import signing

DIRECTORY = 'UnfairplayedDylibs'
RUNTIME_NAMES = ('libsubstrate.dylib', 'libhooker.dylib', 'libblackjack.dylib')
RUNTIME_HASHES = {
    'libsubstrate.dylib': 'ddb437812d23e898de98ac7692d59edfb667d625a4663b619e6e9efe31e06e82',
    'libhooker.dylib': '854571b8277ae12922b18f5cc08a3db87ba9bf5546f5730b3ada6c7d40091838',
    'libblackjack.dylib': 'b4405a500a47983ee89d51d81349655d5f99295ff92092ee8f306673acd9e1d7',
}
LOAD_COMMANDS = (12, 0x80000018, 0x8000001f, 0x80000023)
ARM64 = 0x0100000c


def slices(data):
    """Bounded thin/FAT32/FAT64 parser; require real 64-bit slice headers."""
    formats = {b'\xca\xfe\xba\xbe': ('>', False), b'\xbe\xba\xfe\xca': ('<', False),
               b'\xca\xfe\xba\xbf': ('>', True), b'\xbf\xba\xfe\xca': ('<', True)}
    magic = bytes(data[:4])
    if magic == b'\xcf\xfa\xed\xfe':
        entries = [(0, len(data), None)]
    elif magic in formats:
        endian, wide = formats[magic]
        if len(data) < 8:
            raise ValueError('Mach-O FAT 头不完整')
        count = struct.unpack_from(endian + 'I', data, 4)[0]
        stride = 32 if wide else 20
        table_end = 8 + count * stride
        if not count or count > 32 or table_end > len(data):
            raise ValueError('Mach-O FAT 架构表无效')
        entries = []
        for i in range(count):
            values = struct.unpack_from(endian + ('IIQQII' if wide else 'IIIII'), data, 8 + i * stride)
            cpu, subtype, off, size, align = values[:5]
            if off < table_end or size < 32 or off > len(data) or size > len(data) - off or align > 30 or off % (1 << align):
                raise ValueError('Mach-O FAT 切片范围无效')
            if any(off < other + length and other < off + size for other, length, _ in entries):
                raise ValueError('Mach-O FAT 切片重叠')
            entries.append((off, size, (cpu, subtype)))
    else:
        raise ValueError('只支持 64 位 iOS Mach-O，文件格式无效')
    result = []
    identities = set()
    for off, size, identity in entries:
        if size < 32 or data[off:off + 4] != b'\xcf\xfa\xed\xfe':
            raise ValueError('含不支持的 Mach-O 切片（需要 64 位）')
        _, cpu, subtype, kind, count, command_size, _, _ = struct.unpack_from('<8I', data, off)
        if identity and identity != (cpu, subtype):
            raise ValueError('FAT 架构与内部 Mach-O 不一致')
        if (cpu, subtype) in identities or command_size > size - 32 or count > command_size // 8:
            raise ValueError('Mach-O 加载命令范围或架构重复')
        identities.add((cpu, subtype))
        pos = off + 32
        commands = []
        for _ in range(count):
            if pos + 8 > off + 32 + command_size:
                raise ValueError('Mach-O 加载命令被截断')
            cmd, length = struct.unpack_from('<II', data, pos)
            if length < 8 or length % 8 or length > off + 32 + command_size - pos:
                raise ValueError('Mach-O 加载命令长度无效')
            commands.append((cmd, pos, length))
            pos += length
        if pos != off + 32 + command_size:
            raise ValueError('Mach-O 加载命令总长度不匹配')
        result.append(dict(offset=off, size=size, cpu=cpu, subtype=subtype, kind=kind,
                           count=count, command_size=command_size, commands=commands))
    return result


def dylib_names(data, item, include_id=False):
    result = []
    for cmd, pos, length in item['commands']:
        if cmd not in LOAD_COMMANDS and not (include_id and cmd == 13):
            continue
        if length < 24:
            raise ValueError('dylib 加载命令不完整')
        name_off = struct.unpack_from('<I', data, pos + 8)[0]
        if name_off < 24 or name_off >= length or b'\0' not in data[pos + name_off:pos + length]:
            raise ValueError('dylib 路径无效')
        result.append(data[pos + name_off:pos + length].split(b'\0', 1)[0].decode('utf-8'))
    return result


def validate_ios(data, kind):
    items = slices(data)
    if not any(i['cpu'] == ARM64 for i in items) or any(i['cpu'] != ARM64 or i['kind'] != kind for i in items):
        raise ValueError('需要 iOS arm64 / arm64e 的' + ('动态库' if kind == 6 else '主程序'))
    for item in items:
        for cmd, pos, length in item['commands']:
            if cmd == 0x32:
                if length < 24 or struct.unpack_from('<I', data, pos + 8)[0] != 2:
                    raise ValueError('动态库必须为 iOS 真机版本，不能使用 macOS / 模拟器版本')
            if cmd in (0x24, 0x2f, 0x30):
                raise ValueError('动态库不适用于 iOS 真机')
            if cmd in (0x21, 0x2c):
                if length < 20 or struct.unpack_from('<I', data, pos + 16)[0]:
                    raise ValueError('不能注入尚未脱壳的文件')
    return items


def first_payload_offset(data, item):
    """Do not overwrite even zero-valued section or linkedit data as padding."""
    offsets = []
    for cmd, pos, length in item['commands']:
        if cmd == 0x19:
            if length < 72:
                raise ValueError('Mach-O 段命令不完整')
            fileoff, filesize = struct.unpack_from('<QQ', data, pos + 40)
            if filesize and fileoff:
                offsets.append(fileoff)
            count = struct.unpack_from('<I', data, pos + 64)[0]
            if count > (length - 72) // 80:
                raise ValueError('Mach-O 节表不完整')
            for j in range(count):
                section = pos + 72 + j * 80
                size = struct.unpack_from('<Q', data, section + 40)[0]
                offset = struct.unpack_from('<I', data, section + 48)[0]
                flags = struct.unpack_from('<I', data, section + 64)[0] & 0xff
                if size and flags not in (1, 12, 18):
                    offsets.append(offset)
        elif cmd in (0x1d, 0x1e, 0x26, 0x29, 0x2b, 0x2e, 0x80000033, 0x80000034):
            if length < 16:
                raise ValueError('Mach-O 数据命令不完整')
            offset, size = struct.unpack_from('<II', data, pos + 8)
            if size:
                offsets.append(offset)
        elif cmd == 2:
            if length < 24:
                raise ValueError('Mach-O 符号表不完整')
            symoff, nsyms, stroff, strsize = struct.unpack_from('<4I', data, pos + 8)
            if nsyms:
                offsets.append(symoff)
            if strsize:
                offsets.append(stroff)
        elif cmd == 0x80000028:
            if length < 24:
                raise ValueError('Mach-O 入口命令不完整')
            entry = struct.unpack_from('<Q', data, pos + 8)[0]
            if entry:
                offsets.append(entry)
        elif cmd in (0x22, 0x80000022):
            if length < 48:
                raise ValueError('Mach-O dyld 信息不完整')
            values = struct.unpack_from('<10I', data, pos + 8)
            offsets += [offset for offset, size in zip(values[::2], values[1::2]) if size]
    if not offsets:
        raise ValueError('无法确认主程序的 Mach-O 头部剩余空间')
    return min(offsets)


def add_load_commands(binary, names):
    data = bytearray(Path(binary).read_bytes())
    for item in validate_ios(data, 2):
        existing = dylib_names(data, item)
        commands = bytearray()
        for name in names:
            if name in existing:
                continue
            encoded = name.encode('utf-8') + b'\0'
            size = (24 + len(encoded) + 7) & ~7
            commands += struct.pack('<6I', 12, size, 24, 2, 0, 0) + encoded + bytes(size - 24 - len(encoded))
            existing.append(name)
        start = item['offset'] + 32 + item['command_size']
        bound = item['offset'] + min(first_payload_offset(data, item), item['size'])
        if start + len(commands) > bound or any(data[start:start + len(commands)]):
            raise ValueError('主程序 Mach-O 头部空间不足，不能安全注入；安装已停止，原 IPA 未修改')
        data[start:start + len(commands)] = commands
        added = sum(1 for _ in parse_command_bytes(commands))
        struct.pack_into('<II', data, item['offset'] + 16, item['count'] + added, item['command_size'] + len(commands))
    # Verify the entire modified image before a single write, including FAT slices.
    validate_ios(data, 2)
    Path(binary).write_bytes(data)


def parse_command_bytes(data):
    pos = 0
    while pos < len(data):
        yield pos
        pos += struct.unpack_from('<I', data, pos + 4)[0]


def inject(app, paths, substrate=True, compatibility='modern'):
    if compatibility not in ('modern', 'legacy'):
        raise ValueError('注入兼容模式无效')
    if not paths:
        return None
    app = Path(app)
    info = plistlib.loads((app / 'Info.plist').read_bytes())
    executable = info['CFBundleExecutable']
    if not isinstance(executable, str) or Path(executable).name != executable:
        raise ValueError('主程序路径无效')
    binary = app / executable
    if binary.is_symlink():
        raise ValueError('主程序不能是符号链接')
    main = validate_ios(binary.read_bytes(), 2)
    selected = []
    names = set(n.casefold() for n in RUNTIME_NAMES) if substrate else set()
    for value in paths:
        path = Path(value).expanduser().resolve()
        if not path.is_file() or path.suffix.lower() != '.dylib' or any(ord(c) < 32 for c in path.name):
            raise ValueError('找不到有效 dylib：' + str(path))
        if path.name.casefold() in names:
            raise ValueError('动态库文件名重复或与 Hook 兼容库冲突：' + path.name)
        names.add(path.name.casefold())
        image = validate_ios(path.read_bytes(), 6)
        main_types = {i['subtype'] & 0xffffff for i in main}
        library_types = {i['subtype'] & 0xffffff for i in image}
        if any(t not in library_types and not (t == 2 and 0 in library_types) for t in main_types):
            raise ValueError('动态库架构与主程序不匹配：' + path.name)
        selected.append(path)
    destination = app / DIRECTORY
    if destination.exists() or destination.is_symlink():
        raise ValueError('IPA 已有 Unfairplayed 注入目录，请选择未注入的脱壳原包')
    print('==> Injecting custom dylibs before signing', flush=True)
    destination.mkdir()
    for path in selected:
        shutil.copyfile(path, destination / path.name)
    if substrate:
        for name in RUNTIME_NAMES:
            source = Path(__file__).with_name('InjectionRuntime') / name
            if hashlib.sha256(source.read_bytes()).hexdigest() != RUNTIME_HASHES[name]:
                raise ValueError('内置 Hook 兼容库校验失败：' + name)
            target = destination / name
            if compatibility == 'modern':
                signing.run(['xcrun', 'lipo', source, '-thin', 'arm64', '-output', target], quiet=True)
            else:
                shutil.copyfile(source, target)
    copied = sorted(destination.glob('*.dylib'))
    installed_names = {p.name for p in copied}
    for target in copied:
        target.chmod(0o755)
        image = target.read_bytes()
        deps = {name for item in validate_ios(image, 6) for name in dylib_names(image, item)}
        args = ['xcrun', 'install_name_tool', '-id', '@executable_path/' + DIRECTORY + '/' + target.name]
        for old in sorted(deps):
            name = old.rsplit('/', 1)[-1]
            if name == 'CydiaSubstrate' and substrate:
                name = 'libsubstrate.dylib'
            if name in installed_names:
                args += ['-change', old, '@loader_path/' + name]
            elif name in (*RUNTIME_NAMES, 'CydiaSubstrate') or old.startswith(('/Library/', '/var/jb/', '@executable_path/iPatchDylibs/')):
                raise ValueError('缺少动态库依赖：' + old + '。请添加依赖或勾选 Hook 兼容库')
        signing.run(args + [target], quiet=True)
    loads = ['@executable_path/' + DIRECTORY + '/' + p.name for p in selected]
    if substrate:
        loads.insert(0, '@executable_path/' + DIRECTORY + '/libsubstrate.dylib')
    add_load_commands(binary, loads)
    result = {'compatibility': compatibility, 'substrate': substrate, 'libraries': [
        {'name': path.name, 'sourceSHA256': hashlib.sha256(path.read_bytes()).hexdigest()} for path in selected],
        'injected': [{'name': p.name, 'sha256BeforeSigning': hashlib.sha256(p.read_bytes()).hexdigest(),
                      'architectures': [i['subtype'] & 0xffffff for i in slices(p.read_bytes())]} for p in copied]}
    print('==> Injected ' + str(len(selected)) + ' custom dylib(s); Hook runtime: ' +
          (compatibility if substrate else 'disabled'), flush=True)
    return result
