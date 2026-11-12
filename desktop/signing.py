"""Signing identities, profile inspection, and native codesign workflows."""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tempfile


def signing_store():
    return Path.home() / 'Library/Application Support/Unfairplayed/Signing'


def run(args, *, data=None, quiet=False, timeout=None):
    result = subprocess.run([str(a) for a in args], input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        detail = result.stderr.decode(errors='replace').strip() or result.stdout.decode(errors='replace').strip()
        raise ValueError(detail or f'{Path(str(args[0])).name} failed ({result.returncode})')
    if not quiet and result.stdout:
        print(result.stdout.decode(errors='replace'), end='', flush=True)
    return result.stdout


def helper_path(root):
    bundled = Path(__file__).with_name('SigningHelper')
    if bundled.is_file():
        return bundled
    path = root / 'desktop/build/SigningHelper'
    source = root / 'desktop/SigningHelper.swift'
    if not path.exists() or source.stat().st_mtime > path.stat().st_mtime:
        path.parent.mkdir(parents=True, exist_ok=True)
        run(['xcrun', 'swiftc', '-swift-version', '5', '-target', 'arm64-apple-macos15.0', '-O',
             '-file-prefix-map', str(root) + '=/UnfairplayedSource', '-file-prefix-map', str(Path.home()) + '=/User', '-framework', 'Security',
             '-framework', 'CryptoKit', source, '-o', path], quiet=True)
    return path


def helper(root, request):
    # P12 passwords never appear in argv or task logs.
    data = run([helper_path(root)], data=json.dumps(request).encode(), quiet=True)
    return json.loads(data)


def load_profile(path):
    raw = run(['/usr/bin/security', 'cms', '-D', '-i', path], quiet=True)
    profile = plistlib.loads(raw)
    if not profile.get('DeveloperCertificates') or not profile.get('Entitlements'):
        raise ValueError('描述文件缺少签名证书或权限信息')
    return profile


def iso_date(value):
    if isinstance(value, datetime.datetime):
        return value.replace(tzinfo=datetime.timezone.utc).isoformat()
    return ''


def profile_metadata(profile):
    entitlements = profile.get('Entitlements', {})
    return {'team': (profile.get('TeamIdentifier') or [''])[0],
            'profileName': profile.get('Name', ''),
            'profileUUID': profile.get('UUID', ''),
            'appIdentifier': entitlements.get('application-identifier', ''),
            'devices': profile.get('ProvisionedDevices', []),
            'allDevices': bool(profile.get('ProvisionsAllDevices')),
            'expires': iso_date(profile.get('ExpirationDate')),
            'debuggable': entitlements.get('get-task-allow') is True}


def certificate_expiry(certificate):
    data = run(['/usr/bin/openssl', 'x509', '-inform', 'DER', '-noout', '-enddate'], data=certificate, quiet=True)
    value = data.decode().strip().partition('=')[2]
    return datetime.datetime.strptime(value, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc).isoformat()


def imported_signers():
    result = []
    for path in sorted(signing_store().glob('*/identity.json')):
        try:
            item = json.loads(path.read_text())
            item.update(profile_metadata(load_profile(path.parent / 'profile.mobileprovision')))
            item['source'] = 'imported'
            result.append(item)
        except (ValueError, OSError, plistlib.InvalidFileException):
            continue
    return result


def availability(item, device, debug=False):
    if item.get('source') == 'xcode':
        return ''
    now = datetime.datetime.now(datetime.timezone.utc)
    for key in ('expires', 'certificateExpires'):
        try:
            if datetime.datetime.fromisoformat(item[key]) <= now:
                return '证书或描述文件已过期'
        except (KeyError, ValueError):
            return '无法确认有效期'
    if not device:
        return '请先选择已连接的 iPhone 或 iPad'
    if not item.get('allDevices') and device not in item.get('devices', []):
        return '描述文件不包含所选设备 UDID'
    if debug and not item.get('debuggable'):
        return '此描述文件未授权 get-task-allow，不能用于 LLDB 调试'
    return ''


def signer_choices(teams):
    return ([{'id': 'xcode:' + t['id'], 'name': t['name'], 'team': t['id'], 'source': 'xcode',
              'devices': [], 'allDevices': True, 'expires': '', 'certificateExpires': '',
              'debuggable': True, 'appIdentifier': ''} for t in teams] + imported_signers())


def import_folder(root, folder, password):
    folder = Path(folder).expanduser().resolve()
    if not folder.is_dir():
        raise ValueError('请选择包含 P12 和描述文件的目录')
    certificates = sorted(p for p in folder.rglob('*') if p.suffix.lower() in ('.p12', '.pfx') and p.is_file())
    profiles = sorted(p for p in folder.rglob('*.mobileprovision') if p.is_file())
    if not certificates or not profiles:
        raise ValueError('目录中需要至少一个 .p12/.pfx 和一个 .mobileprovision 文件')
    parsed = [(p, load_profile(p)) for p in profiles]
    imported = []
    failures = []
    store = signing_store()
    store.mkdir(parents=True, exist_ok=True, mode=0o700)
    store.chmod(0o700)
    for p12 in certificates:
        try:
            inspected = helper(root, {'action': 'inspect', 'p12': str(p12), 'password': password})
            certificate = base64.b64decode(inspected['certificate'])
            matches = [(p, data) for p, data in parsed if certificate in data['DeveloperCertificates']]
            if not matches:
                raise ValueError('没有找到与证书匹配的描述文件')
            for profile_path, profile in matches:
                key = hashlib.sha256(certificate + profile_path.read_bytes()).hexdigest()[:24]
                directory = store / key
                metadata_file = directory / 'identity.json'
                if metadata_file.exists():
                    imported.append(json.loads(metadata_file.read_text()))
                    continue
                if directory.exists():
                    helper(root, {'action': 'delete', 'id': key, 'keychain': str(directory / 'identity.keychain-db')})
                    shutil.rmtree(directory)
                directory.mkdir(mode=0o700)
                try:
                    imported_identity = helper(root, {'action': 'import', 'id': key,
                        'keychain': str(directory / 'identity.keychain-db'), 'p12': str(p12), 'password': password})
                    item = {'id': 'imported:' + key, 'name': p12.parent.name,
                            'identityName': imported_identity['name'], 'sha1': imported_identity['sha1'],
                            'source': 'imported', 'certificateExpires': certificate_expiry(certificate),
                            **profile_metadata(profile)}
                    shutil.copyfile(profile_path, directory / 'profile.mobileprovision')
                    (directory / 'profile.mobileprovision').chmod(0o600)
                    metadata_file.write_text(json.dumps(item, ensure_ascii=False, indent=2))
                    metadata_file.chmod(0o600)
                    imported.append(item)
                except Exception:
                    # Remove only this incomplete import, so the same pair can be retried.
                    try:
                        helper(root, {'action': 'delete', 'id': key, 'keychain': str(directory / 'identity.keychain-db')})
                        shutil.rmtree(directory)
                    except (OSError, ValueError):
                        pass
                    raise
        except (ValueError, OSError) as error:
            failures.append(p12.name + '：' + str(error))
    if not imported:
        raise ValueError('\n'.join(failures) or '未导入任何签名材料')
    return {'imported': len(imported), 'errors': failures}


def resolve_imported(root, signer_id, device, debug=False):
    item = next((s for s in imported_signers() if s['id'] == signer_id), None)
    if not item:
        raise ValueError('找不到导入的证书，请重新导入或选择 Xcode 团队')
    reason = availability(item, device, debug)
    if reason:
        raise ValueError(reason)
    key = signer_id.partition(':')[2]
    directory = signing_store() / key
    helper(root, {'action': 'unlock', 'id': key, 'keychain': str(directory / 'identity.keychain-db')})
    return {'item': item, 'profilePath': directory / 'profile.mobileprovision',
            'profile': load_profile(directory / 'profile.mobileprovision'),
            'identity': item['sha1'], 'keychain': directory / 'identity.keychain-db'}


def local_profiles():
    folders = [Path.home() / 'Library/Developer/Xcode/UserData/Provisioning Profiles',
               Path.home() / 'Library/MobileDevice/Provisioning Profiles']
    now = datetime.datetime.now(datetime.timezone.utc)
    for folder in folders:
        for path in sorted(folder.glob('*.mobileprovision')):
            try:
                profile = load_profile(path)
                metadata = profile_metadata(profile)
                expiry = datetime.datetime.fromisoformat(metadata['expires'])
                if expiry > now:
                    yield path, profile, metadata
            except (OSError, ValueError, plistlib.InvalidFileException):
                continue


def local_app_ids():
    result = {}
    for path, profile, item in local_profiles():
        prefix = (profile.get('ApplicationIdentifierPrefix') or profile.get('TeamIdentifier') or [''])[0] + '.'
        app_id = item['appIdentifier']
        bundle = app_id[len(prefix):] if app_id.startswith(prefix) else ''
        if valid_bundle(bundle) and item['debuggable']:
            key = (item['team'], bundle)
            result[key] = {'team': item['team'], 'bundle': bundle, 'name': item['profileName'],
                           'expires': item['expires'], 'devices': item['devices'], 'allDevices': item['allDevices']}
    return list(result.values())


def profile_identity(profile):
    text = run(['/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning'], quiet=True).decode()
    valid = {m.upper() for m in re.findall(r'\b[0-9a-fA-F]{40}\b', text)}
    return next((hashlib.sha1(c).hexdigest().upper() for c in profile['DeveloperCertificates']
                 if hashlib.sha1(c).hexdigest().upper() in valid), None)


class ProvisioningError(ValueError):
    def __init__(self, message, reason='signing', bundle=''):
        super().__init__(message)
        self.reason = reason
        self.bundle = bundle


def provisioning_failure(output):
    lower = output.lower()
    if any(text in lower for text in ('no accounts', 'no account for team', 'authentication session', 'session has expired', 'unable to log in', 'not logged in')):
        return ProvisioningError('请在 Xcode → Settings → Apple Accounts 登录或重新认证当前团队账号，然后点击重新申请。', 'account')
    if any(text in lower for text in ('maximum number of app ids', '10 app ids', 'too many app ids', 'app id limit')):
        return ProvisioningError('当前团队的 App ID 名额已用完。可复用辅助 App ID 或最近使用的 ID，名额恢复后再申请。', 'quota')
    if any(text in lower for text in ('bundle identifier is not available', 'not available to your development team', 'cannot be registered to your development team')):
        return ProvisioningError('这个 Bundle ID 不能用于当前团队，请修改标识或点击生成后重新申请。', 'identifier')
    if any(text in lower for text in ('network connection', 'internet connection', 'could not connect', 'timed out', 'not connected to the internet')):
        return ProvisioningError('无法连接 Apple 签名服务，请检查网络后重新申请。', 'network')
    return ProvisioningError('Xcode 未能完成签名申请，请检查任务日志中的具体原因后重试。')


def provision_xcode(root, team, bundle, device):
    if not re.fullmatch(r'[A-Z0-9]{10}', team) or not valid_bundle(bundle):
        raise ValueError('Xcode 团队或 Bundle ID 无效')
    for path, profile, item in local_profiles():
        app_id = item['appIdentifier']
        prefix = (profile.get('ApplicationIdentifierPrefix') or [team])[0] + '.'
        matches = app_id == prefix + bundle or (app_id.endswith('*') and (prefix + bundle).startswith(app_id[:-1]))
        if item['team'] == team and item['debuggable'] and matches and (item['allDevices'] or device in item['devices']):
            identity = profile_identity(profile)
            if identity:
                print('==> Reusing local development profile: ' + bundle, flush=True)
                return {'item': {'team': team}, 'profilePath': path, 'profile': profile, 'identity': identity, 'keychain': None}
    derived = root / 'iOS/debug-signing-build' / hashlib.sha256((team + bundle).encode()).hexdigest()[:16]
    print('==> Provisioning debug signature: ' + bundle, flush=True)
    process = subprocess.run(['xcodebuild', '-project', str(root / 'iOS/Unfairplayed.xcodeproj'),
        '-scheme', 'Unfairplayed', '-configuration', 'Debug', '-destination', 'id=' + device,
        '-derivedDataPath', str(derived), '-allowProvisioningUpdates', 'PRODUCT_BUNDLE_IDENTIFIER=' + bundle,
        'DEVELOPMENT_TEAM=' + team, 'FP_SKIP_EMBED_PAYLOAD=1', 'build'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if process.returncode:
        print(process.stdout.decode(errors='replace'), flush=True)
        raise provisioning_failure(process.stdout.decode(errors='replace'))
    app = derived / 'Build/Products/Debug-iphoneos/Unfairplayed.app'
    profile_path = app / 'embedded.mobileprovision'
    profile = load_profile(profile_path)
    if not profile.get('Entitlements', {}).get('get-task-allow'):
        raise ValueError('Xcode 生成的描述文件没有启用 get-task-allow')
    identity = profile_identity(profile)
    if not identity:
        raise ValueError('描述文件中没有与本机私钥匹配的有效开发签名证书')
    return {'item': {'team': team}, 'profilePath': profile_path, 'profile': profile,
            'identity': identity, 'keychain': None}


def valid_bundle(value):
    return bool(re.fullmatch(r'[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+', value))


def debug_bundle(original, mode, custom, team):
    if mode == 'reuse':
        value = original
    elif mode in ('custom', 'helper'):
        value = custom.strip()
    elif mode == 'new':
        suffix = hashlib.sha256((team + ':' + original).encode()).hexdigest()[:12]
        value = 'dev.unfairplayed.debug.' + suffix
    else:
        raise ValueError('未知的 Bundle ID 方式')
    if not valid_bundle(value):
        raise ValueError('Bundle ID 格式错误')
    return value


def signing_entitlements(profile, bundle, debug):
    allowed = profile['Entitlements']
    if debug and allowed.get('get-task-allow') is not True:
        raise ValueError('此描述文件未授权 get-task-allow，不能启用动态调试')
    app_id = allowed.get('application-identifier', '')
    # Re-signers preserve a fixed authorized entitlement separately from the
    # app's CFBundleIdentifier. A fixed profile ID alone must not disable a
    # different user-selected bundle ID; the device validates installation.
    if '*' in app_id:
        prefix = (profile.get('ApplicationIdentifierPrefix') or profile.get('TeamIdentifier') or [''])[0]
        candidate = prefix + '.' + bundle
        if not candidate.startswith(app_id.partition('*')[0]):
            raise ValueError('Bundle ID 超出通配符描述文件的前缀范围')
        app_id = candidate
    if not app_id:
        raise ValueError('描述文件缺少 application-identifier')
    team = (profile.get('TeamIdentifier') or [''])[0]
    ent = {'application-identifier': app_id, 'com.apple.developer.team-identifier': team,
           'get-task-allow': bool(debug)}
    groups = allowed.get('keychain-access-groups', [])
    if groups:
        ent['keychain-access-groups'] = [groups[0].replace('*', bundle)]
    return ent


def sign_app(app, credential, bundle, debug, embedded_payload=False):
    app = Path(app)
    profile = credential['profile']
    ent = signing_entitlements(profile, bundle, debug)
    info_path = app / 'Info.plist'
    info = plistlib.loads(info_path.read_bytes())
    info['CFBundleIdentifier'] = bundle
    info.pop('CFBundleResourceSpecification', None)
    info_path.write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
    for p in (app / '_CodeSignature', app / 'SC_Info'):
        if p.is_dir() and not p.is_symlink():
            shutil.rmtree(p)
    shutil.copyfile(credential['profilePath'], app / 'embedded.mobileprovision')
    common = ['/usr/bin/codesign', '--force', '--sign', credential['identity'], '--timestamp=none', '--generate-entitlement-der']
    if credential.get('keychain'):
        common += ['--keychain', str(credential['keychain'])]
    nested = [p for p in app.rglob('*') if not p.is_symlink() and
              not (embedded_payload and 'EmbeddedPayload' in p.relative_to(app).parts) and
              ((p.is_dir() and p.suffix == '.framework') or (p.is_file() and p.suffix == '.dylib'))]
    for p in sorted(nested, key=lambda p: len(p.parts), reverse=True):
        run(common + [p], quiet=True)
    with tempfile.TemporaryDirectory(prefix='unfairplayed-entitlements-') as folder:
        path = Path(folder) / 'entitlements.plist'
        path.write_bytes(plistlib.dumps(ent)); path.chmod(0o600)
        run(common + ['--entitlements', path, app], quiet=True)
    verify_args = ['/usr/bin/codesign', '--verify', '--strict']
    if not embedded_payload:
        verify_args.append('--deep')
    run(verify_args + [app], quiet=True)
    actual = plistlib.loads(run(['/usr/bin/codesign', '-d', '--entitlements', '-', '--xml', app], quiet=True))
    if debug and actual.get('get-task-allow') is not True:
        raise ValueError('重签名结果没有启用 get-task-allow')
    return ent
