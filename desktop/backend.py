#!/usr/bin/env python3
"""Local, dependency-free adapter for the Unfairplayed desktop application."""
import argparse
import contextlib
import datetime
import fcntl
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import uuid

import signing
import ipa_library
import frida_env
import device_connection
from debug_ipa import bundle_history, last_session


def output_directory():
    return Path.home() / 'Downloads' / 'Unfairplayed-Output'


def read_config(root):
    path = root / '.unfairplayed.env'
    values = {}
    if path.exists():
        for line in path.read_text().splitlines():
            key, sep, value = line.partition('=')
            if sep and key in ('TEAM_ID', 'DEVICE', 'UNFAIRPLAYED_BUNDLE_ID', 'SKIP_TRUST_PROMPT',
                              'HELPER_SIGNER_ID', 'DEBUG_SIGNER_ID', 'DEBUG_BUNDLE_MODE',
                              'DEBUG_CUSTOM_BUNDLE_ID', 'AUTO_DEBUG', 'DEBUG_FRIDA', 'DEBUG_ENABLED', 'KEEP_EXTENSIONS', 'FRIDA_PATH', 'FRIDA_MODE', 'LLDB_MODE', 'INJECTION_ENABLED', 'INJECTION_DYLIBS', 'INJECTION_SUBSTRATE', 'INJECTION_COMPATIBILITY'):
                values[key] = value
    return values


def save_config(root, team, bundle, device, settings=None):
    if not re.fullmatch(r'[A-Z0-9]{10}', team):
        raise ValueError('Team ID 必须为 10 位大写字母或数字')
    if not re.fullmatch(r'[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+){2,}', bundle):
        raise ValueError('请填写独立的辅助 App Bundle ID，例如 dev.yourname.unfairplayed')
    if device and not re.fullmatch(r'[A-Za-z0-9-]+', device):
        raise ValueError('设备标识格式错误')
    values = read_config(root)
    values.update(TEAM_ID=team, UNFAIRPLAYED_BUNDLE_ID=bundle, DEVICE=device)
    if settings:
        for key in ('HELPER_SIGNER_ID', 'DEBUG_SIGNER_ID'):
            value = settings.get(key, '')
            if value and not re.fullmatch(r'(xcode:[A-Z0-9]{10}|imported:[a-f0-9]{24})', value):
                raise ValueError('签名身份无效')
        if settings.get('DEBUG_BUNDLE_MODE', 'new') not in ('reuse', 'new', 'custom', 'helper'):
            raise ValueError('调试版 Bundle ID 模式无效')
        custom = settings.get('DEBUG_CUSTOM_BUNDLE_ID', '')
        if settings.get('DEBUG_BUNDLE_MODE') == 'custom' and custom and not signing.valid_bundle(custom):
            raise ValueError('自定义 Bundle ID 无效')
        if any('\n' in str(v) or '\r' in str(v) for v in settings.values()):
            raise ValueError('配置包含无效换行符')
        if settings.get('FRIDA_MODE', 'attach') not in ('attach', 'spawn'):
            raise ValueError('Frida 启动方式无效')
        if settings.get('LLDB_MODE', 'attach') not in ('attach', 'launch'):
            raise ValueError('LLDB 启动方式无效')
        if settings.get('INJECTION_COMPATIBILITY', 'modern') not in ('modern', 'legacy'):
            raise ValueError('注入兼容模式无效')
        dylibs = json.loads(settings.get('INJECTION_DYLIBS', '[]'))
        if not isinstance(dylibs, list) or len(dylibs) > 64 or any(not isinstance(p, str) or not Path(p).is_absolute() for p in dylibs):
            raise ValueError('注入动态库路径无效')
        frida_path = settings.get('FRIDA_PATH', '')
        if frida_path and not Path(frida_path).is_absolute():
            raise ValueError('Frida 路径必须为绝对路径')
        values.update(settings)
    fd, name = tempfile.mkstemp(prefix='.unfairplayed.env.', dir=root)
    try:
        with os.fdopen(fd, 'w') as f:
            for key, value in values.items():
                f.write(f'{key}={value}\n')
        os.replace(name, root / '.unfairplayed.env')
    finally:
        if os.path.exists(name):
            os.unlink(name)


def capture(args, timeout=20):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def ipatool():
    path = shutil.which('ipatool')
    if not path:
        raise ValueError('尚未安装 ipatool，请在终端运行 brew install ipatool')
    return path


def json_records(text):
    result = []
    for line in text.splitlines():
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                result.append(item)
        except ValueError:
            pass
    return result


def devices():
    fd, path = tempfile.mkstemp(suffix='.json')
    os.close(fd)
    try:
        p = capture(['xcrun', 'devicectl', 'list', 'devices', '--json-output', path])
        if p.returncode:
            raise ValueError(p.stderr or p.stdout)
        data = json.loads(Path(path).read_text())
        result = []
        wired = device_connection.wired_devices()
        for d in data.get('result', {}).get('devices', []):
            props = d.get('properties', {})
            h = props.get('hardware') or d.get('hardwareProperties', {})
            c = props.get('connection') or d.get('connectionProperties', {})
            s = props.get('state') or d.get('deviceProperties', {})
            if h.get('reality') != 'physical' or h.get('deviceType') not in ('iPhone', 'iPad'):
                continue
            result.append({'id': h.get('udid') or d['identifier'],
                           'name': s.get('name', h.get('deviceType')),
                           'state': c.get('state', c.get('tunnelState', 'unknown')),
                           'developerMode': s.get('developerModeStatus'),
                           'wired': device_connection.normalize_udid(h.get('udid') or d['identifier']) in wired})
        return result
    finally:
        Path(path).unlink(missing_ok=True)


def development_teams(root):
    """Use Xcode's team cache, then unexpired profiles; never infer from a cert CN."""
    found = {}
    preferred = None

    def visit(value):
        if isinstance(value, dict):
            team_id = value.get('teamID')
            if isinstance(team_id, str) and re.fullmatch('[A-Z0-9]{10}', team_id):
                found[team_id] = {'id': team_id, 'name': value.get('teamName', team_id), 'source': 'Xcode'}
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    try:
        p = capture(['/usr/bin/defaults', 'export', 'com.apple.dt.Xcode', '-'], 5)
        if p.returncode == 0:
            prefs = plistlib.loads(p.stdout.encode())
            preferred = prefs.get('IDEProvisioningTeamManagerLastSelectedTeamID')
            visit(prefs.get('IDEProvisioningTeamByIdentifier', {}))
    except (ValueError, subprocess.TimeoutExpired):
        pass
    folders = [Path.home() / 'Library/Developer/Xcode/UserData/Provisioning Profiles',
               Path.home() / 'Library/MobileDevice/Provisioning Profiles']
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    for folder in folders:
        for profile in folder.glob('*.mobileprovision'):
            try:
                p = capture(['/usr/bin/security', 'cms', '-D', '-i', str(profile)], 5)
                if p.returncode:
                    continue
                data = plistlib.loads(p.stdout.encode())
                expiry = data.get('ExpirationDate')
                if not expiry or expiry <= now:
                    continue
                for team_id in data.get('TeamIdentifier', []):
                    if re.fullmatch('[A-Z0-9]{10}', team_id):
                        found.setdefault(team_id, {'id': team_id, 'name': data.get('TeamName', team_id), 'source': '描述文件'})
            except (ValueError, subprocess.TimeoutExpired):
                continue
    configured = read_config(root).get('TEAM_ID')
    if configured and not read_config(root).get('HELPER_SIGNER_ID', '').startswith('imported:') and re.fullmatch('[A-Z0-9]{10}', configured):
        found.setdefault(configured, {'id': configured, 'name': '当前配置的团队', 'source': '本地配置'})
    return sorted(found.values(), key=lambda d: (d['id'] != configured, d['id'] != preferred, d['name']))


def status(root):
    teams = development_teams(root)
    result = {'config': read_config(root), 'ipatool': shutil.which('ipatool'),
              'devices': [], 'teams': teams, 'signers': signing.signer_choices(teams),
              'loggedIn': False, 'errors': [], 'fridaEnvironments': frida_env.environments(), 'debugBundleHistory': bundle_history(), 'localAppIDs': signing.local_app_ids(), 'lastDebugSession': last_session()}
    selected_frida = result['config'].get('FRIDA_PATH', '')
    try:
        result['fridaPath'] = frida_env.find_frida(selected_frida) or ''
        result['fridaVersion'] = frida_env.version(result['fridaPath'])
    except ValueError as error:
        result['fridaPath'] = selected_frida
        result['fridaVersion'] = ''
        result['errors'].append(str(error))
    try:
        result['devices'] = devices()
    except Exception as e:
        result['errors'].append(str(e))
    try:
        if result['ipatool']:
            result['loggedIn'] = capture([ipatool(), '--non-interactive', '--format', 'json', 'auth', 'info'], 10).returncode == 0
    except Exception as e:
        result['errors'].append(str(e))
    return result


def search(term, country):
    """Public catalog search works before ipatool's account login."""
    if not term.strip():
        raise ValueError('请输入应用名称或 Bundle ID')
    if not re.fullmatch('[a-z]{2}', country):
        raise ValueError('无效商店区域')
    lookup = bool(re.fullmatch(r'[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+){2,}', term.strip()))
    query = {'country': country, 'entity': 'software', 'limit': 35}
    query['bundleId' if lookup else 'term'] = term.strip()
    url = 'https://itunes.apple.com/' + ('lookup' if lookup else 'search') + '?' + urllib.parse.urlencode(query)
    req = urllib.request.Request(url, headers={'User-Agent': 'Unfairplayed/1.0'})
    with urllib.request.urlopen(req, timeout=25) as response:
        items = json.load(response).get('results', [])
    return [{'id': str(d['trackId']), 'bundle': d['bundleId'], 'name': d['trackName'],
             'artist': d.get('artistName', ''), 'version': d.get('version', ''),
             'price': d.get('formattedPrice', ''), 'artwork': d.get('artworkUrl100', ''),
             'storeURL': d.get('trackViewUrl', '')}
            for d in items if all(k in d for k in ('trackId', 'bundleId', 'trackName'))]


@contextlib.contextmanager
def job_lock(root):
    with (root / '.unfairplayed.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('已有 Unfairplayed 任务在运行，请等待它结束') from None
        yield


def run_job(args, root):
    """Own a process group so Stop cancels xcodebuild/tee/devicectl too."""
    with job_lock(root):
        child = subprocess.Popen(args, cwd=root, stdin=subprocess.DEVNULL, start_new_session=True)
        stopped = False

        def stop(_sig, _frame):
            nonlocal stopped
            stopped = True
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

        previous = signal.signal(signal.SIGTERM, stop)
        previous_int = signal.signal(signal.SIGINT, stop)
        try:
            while True:
                try:
                    code = child.wait(timeout=.25)
                    break
                except subprocess.TimeoutExpired:
                    if stopped:
                        try:
                            child.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            os.killpg(child.pid, signal.SIGKILL)
                        child.wait()
                        code = 130
                        break
            if stopped:
                # The group leader may exit before one of its descendants.
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            return 130 if stopped else code
        finally:
            signal.signal(signal.SIGTERM, previous)
            signal.signal(signal.SIGINT, previous_int)


def require_device(root, wanted=None):
    if wanted is None:
        wanted = read_config(root).get('DEVICE')
    available = [d for d in devices() if d['state'] not in ('unavailable', 'unknown')]
    if wanted:
        available = [d for d in available if d['id'] == wanted]
    if len(available) != 1:
        raise ValueError('请连接并解锁目标 iPhone，信任这台 Mac，然后在设置中选择设备')
    return available[0]['id']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('status')
    p = sub.add_parser('library'); p.add_argument('--add', action='append', default=[])
    sub.add_parser('usb-status')
    p = sub.add_parser('frida-info'); p.add_argument('--path', default='')
    p = sub.add_parser('search')
    p.add_argument('term'); p.add_argument('--country', default='cn')
    p = sub.add_parser('configure')
    p.add_argument('--team', required=True); p.add_argument('--bundle', required=True); p.add_argument('--device', default='')
    p.add_argument('--helper-signer', default=''); p.add_argument('--debug-signer', default='')
    p.add_argument('--debug-mode', choices=['reuse', 'new', 'custom', 'helper'], default='helper')
    p.add_argument('--debug-bundle', default=''); p.add_argument('--auto-debug', action='store_true'); p.add_argument('--debug-frida', action='store_true')
    p.add_argument('--no-debug', action='store_true')
    p.add_argument('--keep-extensions', action='store_true')
    p.add_argument('--dylib', action='append', default=[])
    p.add_argument('--no-injection-substrate', action='store_true')
    p.add_argument('--injection-compatibility', choices=['modern', 'legacy'], default='modern')
    p.add_argument('--frida-path', default='')
    p.add_argument('--frida-mode', choices=['attach', 'spawn'], default='attach')
    p.add_argument('--lldb-mode', choices=['attach', 'launch'], default='attach')
    p.add_argument('--injection-enabled', action='store_true')
    p = sub.add_parser('import-signing'); p.add_argument('--folder', required=True)
    p = sub.add_parser('debug-install')
    p.add_argument('--ipa', type=Path, required=True); p.add_argument('--signer', required=True)
    p.add_argument('--device', default=''); p.add_argument('--mode', choices=['reuse', 'new', 'custom', 'helper'], default='helper')
    p.add_argument('--bundle', default=''); p.add_argument('--frida', action='store_true')
    p.add_argument('--no-debug', action='store_true')
    p.add_argument('--keep-extensions', action='store_true')
    p.add_argument('--dylib', action='append', default=[])
    p.add_argument('--no-injection-substrate', action='store_true')
    p.add_argument('--injection-compatibility', choices=['modern', 'legacy'], default='modern')
    p.add_argument('--frida-path', default='')
    p = sub.add_parser('create-bundle')
    p.add_argument('--bundle', required=True); p.add_argument('--signer', required=True)
    p.add_argument('--device', default=''); p.add_argument('--name', default='')
    p = sub.add_parser('open-debugger')
    p.add_argument('--session', type=Path, required=True); p.add_argument('--tool', choices=['lldb', 'frida'], required=True)
    p.add_argument('--frida-path', default='')
    p.add_argument('--frida-mode', choices=['attach', 'spawn'])
    p.add_argument('--lldb-mode', choices=['attach', 'launch'])
    sub.add_parser('build'); sub.add_parser('install'); sub.add_parser('login'); sub.add_parser('open-xcode')
    p = sub.add_parser('decrypt')
    p.add_argument('ipa', type=Path)
    p.add_argument('--trusted', action='store_true', help=argparse.SUPPRESS)
    p = sub.add_parser('resume-export')
    p.add_argument('--device', required=True); p.add_argument('--bundle', required=True); p.add_argument('--name', required=True)
    p = sub.add_parser('uninstall-helper')
    p.add_argument('--device', required=True); p.add_argument('--bundle', required=True)
    p = sub.add_parser('verify'); p.add_argument('ipa', type=Path)
    p = sub.add_parser('download')
    p.add_argument('bundle'); p.add_argument('--app-id', required=True)
    p.add_argument('--purchase', action='store_true'); p.add_argument('--platform', choices=['iphone', 'ipad'], default='iphone')
    a = parser.parse_args()
    root = a.root.expanduser().resolve()
    if not (root / 'fpdecrypt.sh').is_file():
        raise ValueError('找不到 Unfairplayed 运行资源，请重新运行 build_desktop.sh')
    if a.command == 'status':
        print(json.dumps(status(root), ensure_ascii=False))
    elif a.command == 'library':
        if a.add:
            ipa_library.add_paths(a.add)
        print(json.dumps(ipa_library.inventory(root), ensure_ascii=False))
    elif a.command == 'usb-status':
        print(json.dumps({'wiredDevices': sorted(device_connection.wired_devices())}))
    elif a.command == 'frida-info':
        path = frida_env.find_frida(a.path) or ''
        print(json.dumps({'path': path, 'version': frida_env.version(path)}))
    elif a.command == 'search':
        print(json.dumps(search(a.term, a.country), ensure_ascii=False))
    elif a.command == 'configure':
        with job_lock(root):
            save_config(root, a.team.strip(), a.bundle.strip(), a.device.strip(), {
                'HELPER_SIGNER_ID': a.helper_signer, 'DEBUG_SIGNER_ID': a.debug_signer,
                'DEBUG_BUNDLE_MODE': a.debug_mode, 'DEBUG_CUSTOM_BUNDLE_ID': a.debug_bundle,
                'AUTO_DEBUG': str(int(a.auto_debug)), 'DEBUG_FRIDA': str(int(a.debug_frida)), 'DEBUG_ENABLED': str(int(not a.no_debug)), 'KEEP_EXTENSIONS': str(int(a.keep_extensions)), 'FRIDA_PATH': a.frida_path, 'FRIDA_MODE': a.frida_mode, 'LLDB_MODE': a.lldb_mode,
                'INJECTION_ENABLED': str(int(a.injection_enabled)), 'INJECTION_DYLIBS': json.dumps(a.dylib, ensure_ascii=False),
                'INJECTION_SUBSTRATE': str(int(not a.no_injection_substrate)), 'INJECTION_COMPATIBILITY': a.injection_compatibility})
        print('配置已保存')
    elif a.command == 'import-signing':
        request = json.load(sys.stdin)
        with job_lock(root):
            result = signing.import_folder(root, a.folder, request.get('password', ''))
        print(json.dumps(result, ensure_ascii=False))
    elif a.command == 'debug-install':
        device = require_device(root, a.device or None)
        bundle = read_config(root).get('UNFAIRPLAYED_BUNDLE_ID', 'dev.unfairplayed.helper') if a.mode == 'helper' else a.bundle
        args = [sys.executable, '-B', '-u', str(Path(__file__).with_name('debug_ipa.py')), 'install',
                '--root', str(root), '--ipa', str(a.ipa.resolve()), '--signer', a.signer,
                '--device', device, '--mode', a.mode, '--bundle', bundle, '--frida-path', a.frida_path]
        for path in a.dylib:
            args += ['--dylib', path]
        args += ['--injection-compatibility', a.injection_compatibility]
        if a.no_injection_substrate:
            args.append('--no-injection-substrate')
        if a.frida:
            args.append('--frida')
        if a.keep_extensions:
            args.append('--keep-extensions')
        if a.no_debug:
            args.append('--no-debug')
        return run_job(args, root)
    elif a.command == 'create-bundle':
        device = require_device(root, a.device or None) if a.signer.startswith('xcode:') else a.device
        return run_job([sys.executable, '-B', '-u', str(Path(__file__).with_name('debug_ipa.py')), 'create-bundle',
                        '--root', str(root), '--bundle', a.bundle, '--signer', a.signer, '--device', device, '--name', a.name], root)
    elif a.command == 'open-debugger':
        from debug_ipa import load_session
        session = load_session(a.session)
        if a.tool == 'frida':
            device_connection.require_wired(session['device'])
        path = a.session.parent / ('Open-' + a.tool.upper() + '.command')
        args = [sys.executable, '-B', str(Path(__file__).with_name('debug_ipa.py')), 'attach',
                '--session', str(a.session.resolve()), '--tool', a.tool, '--frida-path', a.frida_path]
        mode = a.frida_mode or read_config(root).get('FRIDA_MODE', 'attach')
        if a.tool == 'frida' and mode == 'spawn':
            args.append('--frida-spawn')
        if a.tool == 'lldb' and (a.lldb_mode or read_config(root).get('LLDB_MODE', 'attach')) == 'launch':
            args.append('--lldb-launch')
        path.write_text('#!/bin/bash\n' + shlex.join(args) + '\nresult=$?\nif [ "$result" -ne 0 ]; then\n  read -r -p "调试器未能启动，按回车关闭… " _\nfi\nexit "$result"\n')
        path.chmod(0o700)
        subprocess.run(['/usr/bin/open', '-a', 'Terminal', str(path)], check=True)
    elif a.command == 'open-xcode':
        subprocess.run(['/usr/bin/open', '-a', 'Xcode'], check=True)
    elif a.command == 'login':
        folder = root / 'desktop' / 'build'
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / 'Apple ID 登录.command'
        path.write_text('#!/bin/bash\nexec /bin/bash ' + shlex.quote(str(root / 'desktop' / 'login.sh')) + ' ' + shlex.quote(ipatool()) + '\n')
        path.chmod(0o700)
        subprocess.run(['/usr/bin/open', '-a', 'Terminal', str(path)], check=True)
    elif a.command == 'download':
        if not re.fullmatch(r'[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+', a.bundle) or not a.app_id.isdigit():
            raise ValueError('应用标识无效')
        folder = output_directory() / 'downloads'
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        dest = folder / f'{a.bundle}-{stamp}-{uuid.uuid4().hex[:6]}.ipa'
        args = [ipatool(), '--non-interactive', '--format', 'json', 'download', '--bundle-identifier', a.bundle,
                '--app-id', a.app_id, '--output', str(dest), '--platform', a.platform]
        if a.purchase:
            args.append('--purchase')
        code = run_job(args, root)
        if code == 0 and dest.is_file():
            print('FPD_RESULT=' + str(dest), flush=True)
        elif code == 0:
            raise ValueError('下载命令结束，但未找到输出 IPA')
        return code
    elif a.command == 'verify':
        return run_job(['/bin/bash', str(root / 'verify_ipa.sh'), str(a.ipa.resolve())], root)
    elif a.command == 'resume-export':
        if (not re.fullmatch(r'[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+', a.bundle)
                or not re.fullmatch(r'[A-Za-z0-9-]+', a.device)
                or not a.name or a.name in ('.', '..') or any(c in a.name for c in '/\\\r\n\0')):
            raise ValueError('重试启动的参数无效')
        device = require_device(root, a.device)
        return run_job(['/bin/bash', str(root / 'export_ipa.sh'), device, a.bundle, a.name], root)
    elif a.command == 'uninstall-helper':
        if (not re.fullmatch(r'[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+', a.bundle)
                or not re.fullmatch(r'[A-Za-z0-9-]+', a.device)):
            raise ValueError('卸载辅助 App 的参数无效')
        info = root / 'iOS/build/Build/Products/Debug-iphoneos/Unfairplayed.app/Info.plist'
        if not info.is_file() or plistlib.loads(info.read_bytes()).get('CFBundleIdentifier') != a.bundle:
            raise ValueError('待卸载的标识与本次构建的 Unfairplayed 辅助 App 不一致，请检查设置')
        device = require_device(root, a.device)
        return run_job(['xcrun', 'devicectl', 'device', 'uninstall', 'app', '--device', device, a.bundle], root)
    else:
        args = ['/bin/bash', str(root / 'fpdecrypt.sh')]
        if a.command == 'build':
            args.append('--build-only')
        else:
            args += ['--device', require_device(root)]
            if a.command == 'install':
                args.append('--install-only')
            else:
                if not a.ipa.is_file():
                    raise ValueError('找不到输入 IPA')
                args += ['--skip-trust-prompt', '--', str(a.ipa.resolve())]
        return run_job(args, root)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('错误：' + str(error), file=sys.stderr, flush=True)
        sys.exit(1)
