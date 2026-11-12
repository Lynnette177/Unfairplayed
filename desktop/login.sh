#!/bin/bash
# Keep credentials interactive and show the real outcome instead of closing the
# Terminal window after an unsuccessful attempt. Do not save verbose output.
set -uo pipefail
IPATOOL="${1:-/opt/homebrew/bin/ipatool}"
if [ ! -x "$IPATOOL" ]; then
  echo "未找到 ipatool，请先运行 brew install ipatool。"
  exit 1
fi

echo "首次认证可能需要几分钟。请等待验证码提示；停止可按 Ctrl+C。"
echo "ipatool 2.8.0 首次会从 Apple 恢复镜像下载、提取认证组件；此阶段原工具不显示进度。"
echo "依赖完整缓存后，后续登录会复用缓存。正在处理时请勿反复中断重试。"
echo "诊断信息仅显示在当前终端，不会写入项目日志。"
echo
"$IPATOOL" --verbose auth login
LOGIN_STATUS=$?
echo
if [ "$LOGIN_STATUS" -eq 0 ]; then
  # Confirm the persisted account too: some authentication paths may return 0
  # without saving usable credentials.
  "$IPATOOL" --non-interactive auth info
  LOGIN_STATUS=$?
fi
if [ "$LOGIN_STATUS" -eq 0 ]; then
  echo "登录成功。请回到 Unfairplayed 点击刷新。"
else
  echo "登录未完成（退出状态：${LOGIN_STATUS}）。请查看上方最后的错误。"
  echo "分享诊断时只发错误文字，请隐去账号、验证码、token 和 cookie。"
fi
echo
if [ -t 0 ]; then
  read -r -p "按回车关闭此登录窗口… " _
fi
exit "$LOGIN_STATUS"
