"""Discover Frida executables without activating or changing Python environments."""
import os
from pathlib import Path
import shutil
import subprocess


def environments():
    roots = [Path('/opt/miniconda3'), Path('/opt/anaconda3'), Path('/opt/homebrew/Caskroom/miniconda/base'),
             Path.home() / 'miniconda3', Path.home() / 'anaconda3', Path.home() / 'miniforge3',
             Path('/opt/homebrew/Caskroom/miniforge/base')]
    prefixes = []
    for root in roots:
        if (root / 'bin/conda').exists():
            prefixes.append((root, 'Conda · base'))
            prefixes.extend((p, 'Conda · ' + p.name) for p in sorted((root / 'envs').glob('*')) if p.is_dir())
    registry = Path.home() / '.conda/environments.txt'
    if registry.is_file():
        for line in registry.read_text().splitlines():
            p = Path(line).expanduser()
            if p.is_dir():
                prefixes.append((p, 'Conda · ' + ('base' if (p / 'bin/conda').exists() else p.name)))
    found = []
    seen = set()
    for prefix, name in prefixes:
        path = str(prefix / 'bin/frida')
        if path not in seen:
            seen.add(path)
            found.append({'id': path, 'name': name, 'available': os.access(path, os.X_OK)})
    for path in [shutil.which('frida'), '/opt/homebrew/bin/frida', '/usr/local/bin/frida',
                 str(Path.home() / '.local/bin/frida')]:
        if path and path not in seen and os.access(path, os.X_OK):
            seen.add(path)
            found.append({'id': path, 'name': '本机 · ' + path, 'available': True})
    return found


def find_frida(selected=''):
    if selected:
        path = Path(selected).expanduser()
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError('所选 Frida 不可执行，请检查环境或重新选择 frida 文件')
        return str(path)
    choices = environments()
    # Prefer base; other virtual environments require an explicit user choice.
    base = next((c for c in choices if c['name'] == 'Conda · base'), None)
    if base:
        return find_frida(base['id']) if base['available'] else None
    return next((c['id'] for c in choices if c['available'] and c['name'].startswith('本机')), None)


def version(path):
    if not path:
        return ''
    try:
        result = subprocess.run([path, '--version'], capture_output=True, text=True, timeout=8)
        return result.stdout.strip() if result.returncode == 0 else ''
    except (OSError, subprocess.TimeoutExpired):
        return ''
