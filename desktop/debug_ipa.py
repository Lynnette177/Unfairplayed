#!/usr/bin/env python3
"""Create a separately signed, debuggable copy of an already decrypted IPA."""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import plistlib
import posixpath
import urllib.parse
import re
import shutil
import sys
import tempfile
import urllib.request
import uuid
import datetime

import signing
import device_connection
import dylib_injection
from frida_env import find_frida


def validate_archive(path):
    import zipfile
    with zipfile.ZipFile(path) as archive:
        links = {}
        for entry in archive.infolist():
            p = PurePosixPath(entry.filename)
            if p.is_absolute() or '..' in p.parts or '\\' in entry.filename:
                raise ValueError('IPA 含不安全的归档路径')
            if entry.external_attr >> 16 & 0o170000 == 0o120000:
                target = archive.read(entry).decode()
                if PurePosixPath(target).is_absolute() or '\\' in target:
                    raise ValueError('IPA 含指向包外的符号链接')
                links[str(p)] = target
        for entry in archive.infolist():
            p = PurePosixPath(entry.filename)
            if any(str(parent) in links for parent in p.parents):
                raise ValueError('IPA 归档不能通过符号链接写入文件')
        for name, target in links.items():
            pending = list(PurePosixPath(name).parent.parts) + list(PurePosixPath(target).parts)
            parts = []
            hops = 0
            while pending:
                part = pending.pop(0)
                if part == '..':
                    if not parts:
                        raise ValueError('IPA 含指向包外的符号链接')
                    parts.pop()
                elif part != '.':
                    parts.append(part)
                    current = '/'.join(parts)
                    if current in links:
                        hops += 1
                        if hops > len(links):
                            raise ValueError('IPA 含循环符号链接')
                        parts.pop()
                        pending = list(PurePosixPath(links[current]).parts) + pending


def prepare_frida(selected=''):
    tool = find_frida(selected)
    if not tool:
        raise ValueError('没有找到 frida 命令，请安装 frida-tools，或取消准备 Frida 支持')
    version = signing.run([tool, '--version'], quiet=True, timeout=15).decode().strip()
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('无法读取本机 Frida 版本')
    cache = Path.home() / '.cache/frida'
    cache.mkdir(parents=True, exist_ok=True)
    gadget = cache / 'gadget-ios.dylib'
    stamp = cache / 'unfairplayed-gadget-version'
    if not gadget.exists() or not stamp.exists() or stamp.read_text().strip() != version:
        print('==> Preparing Frida Gadget ' + version, flush=True)
        api = 'https://api.github.com/repos/frida/frida/releases/tags/' + version
        request = urllib.request.Request(api, headers={'User-Agent': 'Unfairplayed-Desktop'})
        with urllib.request.urlopen(request, timeout=30) as response:
            release = json.load(response)
        name = f'frida-gadget-{version}-ios-universal.dylib.xz'
        asset = next((a for a in release.get('assets', []) if a.get('name') == name), None)
        if not asset or not asset['browser_download_url'].startswith('https://github.com/frida/frida/releases/download/'):
            raise ValueError('官方发布中没有找到与本机 Frida 匹配的 iOS Gadget')
        with urllib.request.urlopen(asset['browser_download_url'], timeout=60) as response:
            compressed = response.read()
        digest = asset.get('digest') or ''
        if digest.startswith('sha256:') and hashlib.sha256(compressed).hexdigest() != digest.split(':', 1)[1]:
            raise ValueError('Frida Gadget 下载校验失败')
        data = lzma.decompress(compressed)
        if data[:4] not in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf', b'\xcf\xfa\xed\xfe'):
            raise ValueError('下载的 Frida Gadget 不是有效 Mach-O')
        with tempfile.NamedTemporaryFile(dir=cache, prefix='gadget-', delete=False) as f:
            f.write(data); temporary = Path(f.name)
        temporary.replace(gadget)
        stamp.write_text(version + '\n')
    return tool


HISTORY_LIMIT = 10


def write_bundle_history(values):
    path = Path.home() / 'Library/Application Support/Unfairplayed/debug-bundles.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix='.debug-bundles-', delete=False) as f:
        json.dump(values[:HISTORY_LIMIT], f, ensure_ascii=False, indent=2)
        temporary = Path(f.name)
    temporary.replace(path)


def bundle_history():
    path = Path.home() / 'Library/Application Support/Unfairplayed/debug-bundles.json'
    try:
        values = json.loads(path.read_text())
        if not isinstance(values, list):
            return []
        result = []
        seen = set()
        for item in values:
            if isinstance(item, dict) and signing.valid_bundle(item.get('bundle', '')) and item['bundle'] not in seen:
                seen.add(item['bundle'])
                result.append(item)
            if len(result) == HISTORY_LIMIT:
                break
        if result != values:
            write_bundle_history(result)
        return result
    except (OSError, ValueError, TypeError):
        return []


def last_session():
    path = Path.home() / 'Library/Application Support/Unfairplayed/last-debug-session.json'
    try:
        session_path = Path(json.loads(path.read_text())['session'])
        value = json.loads(session_path.read_text())
        if signing.valid_bundle(value.get('bundle', '')) and Path(value['ipa']).is_file() and Path(value['app']).is_dir():
            return value
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def remember_session(session):
    path = Path.home() / 'Library/Application Support/Unfairplayed/last-debug-session.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix='.last-session-', delete=False) as f:
        json.dump({'session': session['session']}, f)
        temporary = Path(f.name)
    temporary.replace(path)


def remember_bundle(session):
    values = [v for v in bundle_history() if v['bundle'] != session['bundle']]
    values.insert(0, {k: session.get(k, '') for k in ('bundle', 'originalBundle', 'name', 'signer')})
    write_bundle_history(values)


def create_bundle(root, bundle, signer_id, device='', name=''):
    if not signing.valid_bundle(bundle):
        raise ValueError('Bundle ID 格式错误，例如 dev.example.debug')
    if signer_id.startswith('xcode:'):
        if not device:
            raise ValueError('申请开发签名前，请先连接并选择目标 iPhone 或 iPad')
        signing.provision_xcode(root, signer_id.partition(':')[2], bundle, device)
        source = 'xcode'
    elif signer_id.startswith('imported:'):
        if not any(s['id'] == signer_id for s in signing.imported_signers()):
            raise ValueError('请选择可用的导入证书')
        source = 'local'
    else:
        raise ValueError('请选择签名身份')
    item = {'bundle': bundle, 'name': name.strip() or bundle, 'signer': signer_id, 'originalBundle': ''}
    remember_bundle(item)
    print('FPD_BUNDLE_READY=' + json.dumps(dict(item, source=source), ensure_ascii=False), flush=True)
    return item


def credential_for(root, signer_id, bundle, device, debug):
    if signer_id.startswith('imported:'):
        return signing.resolve_imported(root, signer_id, device, debug)
    if signer_id.startswith('xcode:'):
        return signing.provision_xcode(root, signer_id.partition(':')[2], bundle, device)
    raise ValueError('请选择 Xcode 团队或导入的签名证书')


def prepare_extensions(root, app, original, bundle, signer_id, device, debug, keep_extensions):
    extensions = sorted([p for p in app.rglob('*') if p.is_dir() and not p.is_symlink()
                         and p.suffix in ('.appex', '.app')], key=lambda p: len(p.parts), reverse=True)
    if not keep_extensions:
        for extension in extensions:
            print('==> Excluding extension from installation copy: ' + str(extension.relative_to(app)), flush=True)
            shutil.rmtree(extension)
        for name in ('PlugIns', 'Watch', 'AppClips'):
            folder = app / name
            if folder.is_dir() and not any(folder.iterdir()):
                folder.rmdir()
        return
    for extension in extensions:
        nested_info = plistlib.loads((extension / 'Info.plist').read_bytes())
        nested_original = nested_info['CFBundleIdentifier']
        if nested_original.startswith(original + '.'):
            nested_bundle = bundle + nested_original[len(original):]
        else:
            nested_bundle = bundle + '.extension' + hashlib.sha256(nested_original.encode()).hexdigest()[:8]
        try:
            credential = credential_for(root, signer_id, nested_bundle, device, debug)
        except signing.ProvisioningError as error:
            raise signing.ProvisioningError('应用扩展 ' + extension.stem + ' 需要独立签名（' + nested_bundle +
                '）。可关闭「保留应用扩展」仅安装主 App。\n' + str(error), error.reason, nested_bundle) from error
        signing.sign_app(extension, credential, nested_bundle, debug)


def install_debug(root, ipa, signer_id, device, mode, custom, frida=False, debug=True, frida_path='', keep_extensions=False,
                  dylibs=None, injection_substrate=True, injection_compatibility='modern'):
    ipa = Path(ipa).expanduser().resolve()
    if not ipa.is_file():
        raise ValueError('找不到已脱壳的 IPA')
    validate_archive(ipa)
    print('==> Verifying decrypted input', flush=True)
    signing.run(['/bin/bash', root / 'verify_ipa.sh', ipa])
    if signer_id.startswith('imported:'):
        # Reject unauthorized debug entitlements before unpacking or installing.
        signing.resolve_imported(root, signer_id, device, debug)
    team = signer_id.partition(':')[2] if signer_id.startswith('xcode:') else next(
        s['team'] for s in signing.imported_signers() if s['id'] == signer_id)
    output = Path.home() / 'Downloads/Unfairplayed-Output/debug'
    output.mkdir(parents=True, exist_ok=True)
    job = output / (datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    job.mkdir()
    print('==> Preparing debug copy', flush=True)
    signing.run(['/usr/bin/ditto', '-x', '-k', ipa, job], quiet=True)
    apps = list((job / 'Payload').glob('*.app'))
    if len(apps) != 1:
        raise ValueError('IPA 必须包含一个主 App')
    app = apps[0]
    info = plistlib.loads((app / 'Info.plist').read_bytes())
    original = info['CFBundleIdentifier']
    bundle = signing.debug_bundle(original, mode, custom, team)
    if mode == 'new':
        info['CFBundleDisplayName'] = info.get('CFBundleDisplayName', info.get('CFBundleName', app.stem)) + (' Debug' if debug else ' Signed')
        (app / 'Info.plist').write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
    injection = dylib_injection.inject(app, dylibs or [], injection_substrate, injection_compatibility)
    # Resolve the main identity first: helper reuse never needs extension IDs.
    credential = credential_for(root, signer_id, bundle, device, debug)
    prepare_extensions(root, app, original, bundle, signer_id, device, debug, keep_extensions)
    print('==> Signing debug app', flush=True)
    signing.sign_app(app, credential, bundle, debug)
    signed_ipa = job / (app.stem + ('-debug-signed.ipa' if debug else '-signed.ipa'))
    signing.run(['/usr/bin/ditto', '-c', '-k', '--keepParent', job / 'Payload', signed_ipa], quiet=True)
    frida_tool = prepare_frida(frida_path) if frida and debug else (frida_path or '')
    session = {'device': device, 'bundle': bundle, 'originalBundle': original, 'ipa': str(signed_ipa),
               'app': str(app), 'executable': info['CFBundleExecutable'], 'signer': signer_id,
               'frida': frida_tool or '', 'debuggable': debug, 'injection': injection,
               'name': info.get('CFBundleDisplayName', info.get('CFBundleName', app.stem))}
    manifest = job / 'debug-session.json'
    session['session'] = str(manifest)
    manifest.write_text(json.dumps(session, ensure_ascii=False, indent=2)); manifest.chmod(0o600)
    print('==> Installing debug app', flush=True)
    signing.run(['xcrun', 'devicectl', 'device', 'install', 'app', '--device', device, app])
    remember_bundle(session)
    remember_session(session)
    print('FPD_DEBUG_READY=' + json.dumps(session, ensure_ascii=False), flush=True)
    return session


def load_session(path):
    session = json.loads(Path(path).read_text())
    if not signing.valid_bundle(session.get('bundle', '')) or not re.fullmatch(r'[A-Za-z0-9-]+', session.get('device', '')):
        raise ValueError('调试会话无效')
    if session.get('debuggable') is not True:
        raise ValueError('此应用未启用调试权限')
    return session


def remote_path(value):
    path = urllib.parse.unquote(urllib.parse.urlsplit(value).path)
    path = posixpath.normpath(path)
    return path[len('/private'):] if path.startswith('/private/var/') else path


def running_target_pid(session):
    """Resolve the installed bundle before matching its main process, never by name alone."""
    with tempfile.TemporaryDirectory(prefix='unfairplayed-process-') as folder:
        apps_path = Path(folder) / 'apps.json'
        signing.run(['xcrun', 'devicectl', 'device', 'info', 'apps', '--device', session['device'],
                     '--bundle-id', session['bundle'], '--timeout', '20', '--json-output', apps_path], quiet=True)
        apps = json.loads(apps_path.read_text()).get('result', {}).get('apps', [])
        app = next((a for a in apps if a.get('bundleIdentifier') == session['bundle']), None)
        if not app or not app.get('url'):
            raise ValueError('目标调试 App 未安装或无法取得安装位置，请检查当前调试会话')
        executable = remote_path(app['url']).rstrip('/') + '/' + session['executable']
        processes_path = Path(folder) / 'processes.json'
        signing.run(['xcrun', 'devicectl', 'device', 'info', 'processes', '--device', session['device'],
                     '--timeout', '20', '--json-output', processes_path], quiet=True)
        processes = json.loads(processes_path.read_text()).get('result', {}).get('runningProcesses')
        if not isinstance(processes, list):
            raise ValueError('无法确认目标 App 的运行状态，请重试')
        matches = [p for p in processes if remote_path(p.get('executable', '')) == executable]
        if not matches:
            return None
        pid = matches[0].get('processIdentifier')
        if len(matches) != 1 or not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            raise ValueError('目标 App 的进程信息无效，请重试')
        return pid


def launch_target(session, session_path, stopped=False, restart=True):
    folder = Path(session_path).parent
    launch = folder / ('debug-launch.json' if stopped else 'frida-launch.json')
    args = ['xcrun', 'devicectl', 'device', 'process', 'launch', '--device', session['device'],
            '--timeout', '20', '--json-output', launch]
    if stopped:
        if restart:
            args.append('--terminate-existing')
        args.append('--start-stopped')
    args.append(session['bundle'])
    print('==> ' + ('Launching suspended app for LLDB' if stopped else 'Launching app before Frida attachment'), flush=True)
    signing.run(args)
    result = json.loads(launch.read_text())
    pid = result.get('result', {}).get('process', {}).get('processIdentifier')
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise ValueError('未能取得调试进程 PID，请检查设备上的证书信任状态')
    return pid


def attach(session_path, tool, frida_path='', frida_spawn=False, lldb_launch=False):
    session = load_session(session_path)
    if tool == 'frida':
        device_connection.require_wired(session['device'])
        frida = prepare_frida(frida_path or session.get('frida', ''))
        if frida_spawn:
            args = [frida, '-D', session['device'], '-f', session['bundle']]
        else:
            pid = running_target_pid(session)
            if pid is None:
                pid = launch_target(session, session_path)
            else:
                print('==> App already running; attaching without restarting (PID ' + str(pid) + ')', flush=True)
            print('==> Attaching Frida to PID ' + str(pid), flush=True)
            args = [frida, '-D', session['device'], '-p', str(pid)]
        return os.execv(frida, args)
    folder = Path(session_path).parent
    pid = None if lldb_launch else running_target_pid(session)
    if pid is None:
        pid = launch_target(session, session_path, stopped=True, restart=lldb_launch)
    else:
        print('==> App already running; attaching LLDB without restarting (PID ' + str(pid) + ')', flush=True)
    script = folder / 'debug-session.lldb'
    executable = Path(session['app']) / session['executable']
    script.write_text('device select ' + session['device'] + '\n' +
                      'target create ' + json.dumps(str(executable), ensure_ascii=False) + '\n' +
                      'device process attach --pid ' + str(pid) + '\n')
    os.execv('/usr/bin/xcrun', ['xcrun', 'lldb', '-s', str(script)])


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='command', required=True)
    install = sub.add_parser('install')
    install.add_argument('--root', type=Path, required=True); install.add_argument('--ipa', type=Path, required=True)
    install.add_argument('--signer', required=True); install.add_argument('--device', required=True)
    install.add_argument('--mode', choices=['reuse', 'new', 'custom', 'helper'], default='new')
    install.add_argument('--bundle', default=''); install.add_argument('--frida', action='store_true')
    install.add_argument('--no-debug', action='store_true')
    install.add_argument('--keep-extensions', action='store_true')
    install.add_argument('--dylib', action='append', default=[])
    install.add_argument('--no-injection-substrate', action='store_true')
    install.add_argument('--injection-compatibility', choices=['modern', 'legacy'], default='modern')
    install.add_argument('--frida-path', default='')
    create = sub.add_parser('create-bundle')
    create.add_argument('--root', type=Path, required=True); create.add_argument('--bundle', required=True)
    create.add_argument('--signer', required=True); create.add_argument('--device', default=''); create.add_argument('--name', default='')
    helper = sub.add_parser('sign-helper')
    helper.add_argument('--root', type=Path, required=True); helper.add_argument('--app', type=Path, required=True)
    helper.add_argument('--signer', required=True); helper.add_argument('--device', required=True); helper.add_argument('--bundle', required=True)
    debugger = sub.add_parser('attach'); debugger.add_argument('--session', required=True); debugger.add_argument('--tool', choices=['lldb', 'frida'], required=True)
    debugger.add_argument('--frida-path', default='')
    debugger.add_argument('--frida-spawn', action='store_true', help='Use native Frida spawn instead of CoreDevice launch and PID attach')
    debugger.add_argument('--lldb-launch', action='store_true', help='Restart suspended before LLDB attachment instead of reusing the running process')
    a = p.parse_args()
    if a.command == 'attach':
        attach(a.session, a.tool, a.frida_path, a.frida_spawn, a.lldb_launch)
    elif a.command == 'create-bundle':
        create_bundle(a.root.resolve(), a.bundle.strip(), a.signer, a.device, a.name)
    elif a.command == 'sign-helper':
        credential = signing.resolve_imported(a.root.resolve(), a.signer, a.device, False)
        signing.sign_app(a.app, credential, a.bundle, False, embedded_payload=True)
        print('==> Imported identity signed Unfairplayed successfully', flush=True)
    else:
        install_debug(a.root.resolve(), a.ipa, a.signer, a.device, a.mode, a.bundle, a.frida, not a.no_debug, a.frida_path,
                      a.keep_extensions, a.dylib, not a.no_injection_substrate, a.injection_compatibility)


if __name__ == '__main__':
    try:
        main()
    except signing.ProvisioningError as error:
        print('FPD_BUNDLE_ACTION=' + json.dumps({'reason': error.reason, 'message': str(error), 'bundle': error.bundle}, ensure_ascii=False), flush=True)
        sys.exit(79)
    except Exception as error:
        print('错误：' + str(error), file=sys.stderr, flush=True)
        sys.exit(1)
