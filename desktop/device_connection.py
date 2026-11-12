"""Match a target device against physical USB devices, independently of Wi-Fi tunnels."""
import plistlib
import re
import subprocess


def normalize_udid(value):
    return re.sub('[^a-z0-9]', '', str(value).lower())


def usb_udids_from_registry(tree):
    found = set()

    def visit(value):
        if isinstance(value, dict):
            product = str(value.get('USB Product Name', value.get('kUSBProductString', ''))).lower()
            vendor = value.get('idVendor')
            if vendor == 0x05ac and any(name in product for name in ('iphone', 'ipad', 'ipod')):
                serial = value.get('USB Serial Number', value.get('kUSBSerialNumberString', ''))
                normalized = normalize_udid(serial)
                if len(normalized) in (24, 40) and re.fullmatch('[a-f0-9]+', normalized):
                    found.add(normalized)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(tree)
    return found


def wired_devices():
    try:
        result = subprocess.run(['/usr/sbin/ioreg', '-a', '-p', 'IOUSB', '-l'],
                                capture_output=True, timeout=8)
        if result.returncode:
            return set()
        return usb_udids_from_registry(plistlib.loads(result.stdout))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return set()


def require_wired(device):
    if not normalize_udid(device) or normalize_udid(device) not in wired_devices():
        raise ValueError('Frida 仅支持 USB 有线连接。请用数据线连接并解锁目标 iPhone / iPad；LLDB 可继续使用无线连接。')
