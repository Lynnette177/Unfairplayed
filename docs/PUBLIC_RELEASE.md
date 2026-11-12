# Unfairplayed 发布说明

## 生成公开产物

在源码根目录运行：

```bash
./package_release.sh
```

`desktop/dist/` 中生成：

- `Unfairplayed-macOS-arm64.zip`：包含 `Unfairplayed.app`，面向 Apple Silicon、macOS 15.0+。
- `Unfairplayed-Source.zip`：可重新构建的源码快照，不含 `.git` 和开发者历史。
- `SHA256SUMS.txt`：上述文件的 SHA-256。
- `privacy-audit.json`：本次产物隐私检查结果，不包含匹配规则中的私人值。

使用导出的干净源码包创建公开仓库；不要直接镜像开发用私有仓库。开发仓库的提交作者、邮箱、提交信息和远端配置不属于公开源码包，也不会复制到 App。

源码包采用文件白名单，App 的运行模板采用更小的独立白名单。配置、证书、描述文件、IPA、日志、用户缓存、构建产物及测试设备数据不进入安装包。打包工具还会读取本机配置、Git 身份和私有远端域名，仅用于检测产物是否意外包含这些值，不将值保存到报告。

## 独立运行

App 内置 `Contents/Resources/WorkspaceTemplate/`，包含辅助 App 工程、Python 模块、脚本、原生签名工具及 Hook 运行库。启动时依据哈希清单在以下位置准备工作目录：

```text
~/Library/Application Support/Unfairplayed/Workspace/
```

配置和生成文件只保存在用户目录。更新模板不会覆盖 `.unfairplayed.env`、IPA payload 或 Xcode 构建目录。安装包不包含源码仓库绝对路径，可直接移动至其他用户的「应用程序」目录；不需要保留下载或解压后的源码目录。

产物最低版本由两个可执行文件的 `-target arm64-apple-macos15.0` 和 App 的 `LSMinimumSystemVersion=15.0` 共同声明。Swift 编译启用文件/调试路径映射，移除构建者的主目录和仓库路径。

完整 Xcode、iOS SDK、Python 3 及用户自己的签名仍需在使用者的 Mac 上准备。ipatool 和 Frida 按功能需要安装。安装包不包含 Xcode、Apple 账号、认证组件或任何签名私钥。

## 校验

```bash
cd desktop/dist
shasum -a 256 -c SHA256SUMS.txt
```



当前分发包使用本机临时签名，不宣称已经获得 Developer ID 公证。没有自动关闭 Gatekeeper 或修改系统安全设置的脚本。

## 本次发布检查

90 项本地回归检查通过。发布 ZIP 在独立临时目录解压后，App 资源签名和两个 Mac 可执行文件的最低版本均通过检查。使用禁止读取原开发仓库的系统 sandbox，完成了空白用户工作目录初始化、内置 iOS 工程无签名构建，以及公开源码包重新构建桌面 App。

本机已有数据已进行一次性迁移；发布版不含旧名称或旧目录迁移代码。原开发仓库中的私人 Git 作者元数据没有改写，公开源码包完全不包含它。
