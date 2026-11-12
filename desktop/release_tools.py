"""Allowlisted, privacy-checked desktop runtime and public source packaging."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.parse
import zipfile

ROOT_FILES = ('.gitignore', '.unfairplayed.env.example', 'README.md', 'README.en.md', '使用说明.md',
              'Unfairplayed.command', 'build_desktop.sh', 'package_release.sh',
              'fpdecrypt.sh', 'embed_ipa.sh', 'export_ipa.sh', 'verify_ipa.sh')
CORE_FILES = ('iOS/Unfairplayed.xcodeproj/project.pbxproj',
              'iOS/Unfairplayed/Info.plist', 'iOS/Unfairplayed/main.m',
              'iOS/Unfairplayed/fpcore.c', 'iOS/Unfairplayed/fpcore.h',
              'iOS/Unfairplayed/zipio.c', 'iOS/Unfairplayed/zipio.h')
MODULES = ('backend.py', 'signing.py', 'debug_ipa.py', 'device_connection.py',
           'frida_env.py', 'ipa_library.py', 'dylib_injection.py', 'login.sh', 'SigningHelper.swift')
RUNTIME_FILES = ('fpdecrypt.sh', 'embed_ipa.sh', 'export_ipa.sh', 'verify_ipa.sh',
                 '.unfairplayed.env.example') + CORE_FILES + tuple('desktop/' + p for p in MODULES)
RUNTIME_ASSETS = ('libsubstrate.dylib', 'libhooker.dylib', 'libblackjack.dylib',
                  'LICENSE.iPatch', 'LICENSE.libhooker', 'README.md', 'manifest.json')
PRIVATE_SUFFIXES = ('.ipa', '.p12', '.pfx', '.p8', '.key', '.pem', '.mobileprovision',
                    '.provisionprofile', '.keychain', '.keychain-db', '.developerprofile')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def copy_public(source, destination):
    source = Path(source); destination = Path(destination)
    if source.is_symlink() or not source.is_file():
        raise ValueError('Missing or symlinked release source: ' + source.name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.name == 'project.pbxproj':
        text = source.read_text()
        # Xcode may have edited the developer checkout. Never publish its signing selections.
        text = re.sub(r'^[ \t]*(?:DEVELOPMENT_TEAM|DevelopmentTeam|PROVISIONING_PROFILE(?:_SPECIFIER)?|CODE_SIGN_IDENTITY)\s*=.*;[ \t]*\n?', '', text, flags=re.M)
        text = re.sub(r'(?m)^(\s*PRODUCT_BUNDLE_IDENTIFIER\s*=\s*)[^;]+;', r'\g<1>dev.unfairplayed.helper;', text)
        destination.write_text(text)
    else:
        shutil.copyfile(source, destination)
    destination.chmod(0o755 if source.suffix in ('.sh', '.command') else 0o644)


def stage_runtime(root, destination):
    root = Path(root); destination = Path(destination)
    for relative in RUNTIME_FILES:
        copy_public(root / relative, destination / relative)
    for name in RUNTIME_ASSETS:
        relative = 'desktop/InjectionRuntime/' + name
        copy_public(root / relative, destination / relative)
    files = []
    for path in sorted(destination.rglob('*')):
        if path.is_file():
            relative = path.relative_to(destination).as_posix()
            files.append(dict(path=relative, sha256=digest(path.read_bytes()),
                              executable=path.suffix == '.sh' or path.name == 'SigningHelper'))
    version = digest(json.dumps(files, sort_keys=True).encode())
    (destination / 'manifest.json').write_text(json.dumps(dict(version=version, files=files), indent=2) + '\n')


def source_files(root):
    root = Path(root)
    paths = set(ROOT_FILES + CORE_FILES)
    for path in (root / 'desktop').iterdir():
        if path.is_file() and path.suffix in ('.py', '.swift', '.c', '.sh'):
            paths.add(path.relative_to(root).as_posix())
    for directory in ('desktop/Assets', 'docs'):
        for path in (root / directory).rglob('*'):
            if path.is_file() and path.suffix in ('.md', '.png', '.jpg', '.icns'):
                paths.add(path.relative_to(root).as_posix())
    paths.update('desktop/InjectionRuntime/' + name for name in RUNTIME_ASSETS)
    # Preserve a project license if one is added later; no private Git metadata is copied.
    for name in ('LICENSE', 'LICENSE.md', 'NOTICE', 'NOTICE.md'):
        if (root / name).is_file(): paths.add(name)
    return sorted(paths)


def private_patterns(root):
    """Read local identifiers only to reject them; never persist their values in a report."""
    patterns = {str(Path.home()): 'builder-home'}
    if len(Path.home().name) >= 5:
        patterns[Path.home().name] = 'builder-username'
    root = Path(root)
    config = root / '.unfairplayed.env'
    if config.is_file():
        values = dict(line.partition('=')[::2] for line in config.read_text().splitlines() if '=' in line)
        for name in ('TEAM_ID', 'DEVICE', 'UNFAIRPLAYED_BUNDLE_ID', 'HELPER_SIGNER_ID', 'DEBUG_SIGNER_ID'):
            value = values.get(name, '')
            if value and value not in ('YOURTEAMID', 'dev.unfairplayed.helper'):
                patterns[value] = 'local-signing-configuration'
    for key in ('user.name', 'user.email'):
        value = subprocess.run(['git', '-C', str(root), 'config', key], capture_output=True, text=True).stdout.strip()
        if len(value) >= 5: patterns[value] = 'local-git-identity'
    remotes = subprocess.run(['git', '-C', str(root), 'remote', '-v'], capture_output=True, text=True).stdout
    for match in re.finditer(r'(?:git@|ssh://(?:[^/@]+@)?)([^/:\s]+)', remotes):
        host = match.group(1)
        if host.lower() not in ('github.com', 'gitlab.com', 'bitbucket.org'):
            patterns[host] = 'private-git-host'
    return patterns


def audit_tree(directory, patterns):
    directory = Path(directory)
    issues = []
    for path in sorted(directory.rglob('*')):
        relative = path.relative_to(directory).as_posix()
        if path.is_symlink():
            issues.append((relative, 'symlink')); continue
        if not path.is_file(): continue
        if path.name in ('.unfairplayed.env', '.DS_Store') or '.git' in path.relative_to(directory).parts or path.name.lower().endswith(PRIVATE_SUFFIXES):
            issues.append((relative, 'private-artifact'))
        data = path.read_bytes()
        searchable = relative.encode('utf-8') + b'\0' + data
        if re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----', data):
            issues.append((relative, 'private-key'))
        for value, category in patterns.items():
            encodings = [value.encode(e).lower() for e in ('utf-8', 'utf-16-le', 'utf-16-be')]
            encodings.append(urllib.parse.quote(value, safe='').encode().lower())
            if any(pattern in searchable.lower() for pattern in encodings):
                display_path = relative
                for private_value in patterns:
                    display_path = re.sub(re.escape(private_value), '<redacted>', display_path, flags=re.I)
                issues.append((display_path, category))
    if issues:
        # No matched secret values are included in errors or public audit reports.
        raise ValueError('Release privacy audit failed: ' + json.dumps(issues, ensure_ascii=False))


def write_zip(directory, destination):
    directory = Path(directory)
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(directory.rglob('*')):
            if path.is_file(): archive.write(path, str(Path(directory.name) / path.relative_to(directory)))


def package(root, app, output):
    root = Path(root).resolve(); app = Path(app).resolve(); output = Path(output).resolve()
    patterns = private_patterns(root)
    audit_tree(app, patterns)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='unfairplayed-public-source-') as temp:
        source = Path(temp) / 'Unfairplayed'
        for relative in source_files(root):
            copy_public(root / relative, source / relative)
        audit_tree(source, patterns)
        source_zip = output / 'Unfairplayed-Source.zip'
        write_zip(source, source_zip)
    app_zip = output / 'Unfairplayed-macOS-arm64.zip'
    write_zip(app, app_zip)
    checksums = ''.join(digest(path.read_bytes()) + '  ' + path.name + '\n' for path in (app_zip, source_zip))
    (output / 'SHA256SUMS.txt').write_text(checksums)
    (output / 'privacy-audit.json').write_text(json.dumps({
        'result': 'passed', 'scope': ['app bundle', 'allowlisted source snapshot'],
        'gitHistoryIncluded': False, 'localIdentifiersIncluded': False,
        'minimumMacOS': '15.0', 'architecture': 'arm64',
        'artifacts': {p.name: digest(p.read_bytes()) for p in (app_zip, source_zip)}}, indent=2) + '\n')
    print('Release artifacts: ' + str(output))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('stage', 'package'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--destination', type=Path)
    parser.add_argument('--helper', type=Path)
    parser.add_argument('--app', type=Path)
    args = parser.parse_args()
    if args.command == 'stage':
        if not args.helper or not args.destination: parser.error('stage needs --helper and --destination')
        copy_public(args.helper, args.destination / 'desktop/SigningHelper')
        stage_runtime(args.root, args.destination)
    else:
        if not args.app or not args.destination: parser.error('package needs --app and --destination')
        package(args.root, args.app, args.destination)


if __name__ == '__main__':
    main()
