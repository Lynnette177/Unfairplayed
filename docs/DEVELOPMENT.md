# 开发与验证

## 结构

```text
Unfairplayed.command                  Finder 启动入口
build_desktop.sh                     构建、打包与可选安装桌面 App
fpdecrypt.sh                        下载、嵌入、构建并安装辅助 App
embed_ipa.sh                        将目标 IPA 嵌入构建资源
export_ipa.sh                       启动已安装的辅助 App、拉取并校验输出
verify_ipa.sh                       检查所有 Mach-O 架构的 cryptid
desktop/
  Unfairplayed.swift           SwiftUI / AppKit 界面、进程与交互状态
  backend.py                        Python 标准库命令适配、配置、设备和任务锁
  ipa_library.py                    本地包清单、主程序状态识别、图标和元数据缓存
  test_ipa_library.py               本地包分类、缓存、图标、路径引用与包不改写回归
  signing.py                        描述文件、身份匹配、Xcode 预配与 codesign
  SigningHelper.swift               Security 框架导入 P12 和独立钥匙串
  debug_ipa.py                      已脱壳 IPA 重签名、安装及调试器启动
  device_connection.py              按目标 UDID 检测 USB 连接并限制 Frida 入口
  frida_env.py                      Frida 环境发现、默认 base 和版本检测
  test_signing.py                   签名能力、归档路径、Bundle ID 与环境回归
  login.sh                          交互登录与真实结果检查
  test_backend.py                   本地回归检查
  build_icon.sh                     从 PNG 生成 macOS 多尺寸 ICNS
  Assets/                           Logo 原图、ICNS 与生成说明
iOS/
  Unfairplayed.xcodeproj/              iPhone 辅助 App 工程
  Unfairplayed/                     上游 Objective-C / C 核心
  payload/                          生成的嵌入内容（忽略）
  build/                            Xcode 构建产物（忽略）
```

IPA 下载、砸壳导出文件和运行日志统一写入 `~/Downloads/Unfairplayed-Output/`。构建缓存和输出不会随公开源码分发。

桌面 App 不依赖 Web 服务或第三方 Swift / Python 包。App 内置带哈希清单的 WorkspaceTemplate，由 WorkspaceBootstrap 在用户私有工作目录展开，通过该目录内的 Python 适配器调用脚本；安装包不记录构建者的仓库路径。Python 使用进程组运行任务，停止任务时会结束对应子进程；图形界面任务通过文件锁互斥。

## 界面与脚本协议

标准输出保留完整日志，以下行携带 JSON 数据供界面更新状态：

| 标记 | 触发条件 |
| --- | --- |
| `FPD_RESULT=<path>` | 下载命令成功且确认输出文件存在 |
| `FPD_TRUST_REQUIRED=<json>` | 启动失败且系统日志包含证书未信任相关信息，退出状态为 `78` |
| `FPD_EXPORT_COMPLETE=<json>` | 拉取与校验成功，且不是 `PARTIAL` |
| `FPD_DEBUG_READY=<json>` | 重签名且安装成功，携带 IPA、Bundle ID、设备和调试会话 |

证书重试复用失败时的设备、辅助 App 标识和目标名称，直接执行 `export_ipa.sh`。卸载询问只在完整导出成功后出现，使用成功时的设备和辅助 App 标识；后端还会比对已构建辅助 App 的 `Info.plist`，拒绝卸载其他标识。

## 本地检查

在仓库根目录执行：

```bash
python3 -m unittest discover -s desktop -p 'test_*.py' -v
bash -n fpdecrypt.sh embed_ipa.sh export_ipa.sh verify_ipa.sh build_desktop.sh desktop/login.sh desktop/build_icon.sh
./build_desktop.sh
```

90 项回归检查通过，覆盖固定输出目录（含用户路径中的空格）、配置权限和校验、团队读取、真机过滤、任务互斥、取消进程组、下载失败、证书重试、完整导出标记、卸载目标匹配与失败保留输出，以及 arm64 / arm64e / FAT、小型 Mach-O 和空包检查。

签名回归另覆盖设备与有效期、分发描述文件禁止提升调试权限、固定 App ID 与 Bundle ID 分离、稳定 ID 和历史去重、归档穿越与链接链逃逸、base 默认选择及辅助 App 嵌入内容不被重签。

原生界面的证书提醒、成功后卸载询问、保留选择、卸载失败后重试已通过模拟后端验证。回归检查不会登录 Apple ID、下载真实应用或卸载真实手机应用；设备兼容性仍需在相应系统上实测。

## 构建说明

`./build_desktop.sh --install` 会在 `~/Applications/` 安装本机版本；省略 `--install` 时只生成 `desktop/build/Unfairplayed.app`。Logo 有更新时会先生成 ICNS，然后复制 PNG、ICNS 与 Python 适配器，写入配置并进行临时签名。

`./fpdecrypt.sh --build-only` 仍需要可用的开发团队和 Xcode 签名账号。未选择 IPA 时构建空辅助 App，已嵌入 IPA 时构建当前内容。不带 IPA 的 `--install-only` 也复用当前嵌入内容。

## 签名与调试实现

P12 密码仅经标准输入传给原生辅助程序。证书 DER 与 profile 的 DeveloperCertificates 严格匹配，导入私钥到独立钥匙串，使用该证书的 SHA-1 标识签名，避免名称歧义。导入菜单按当前设备和权限状态禁用；后端再次检查，不能只依赖 UI。

Xcode 开发签名优先复用有效本地 profile；需要新预配时构建到独立 `debug-signing-build/`，以 `FP_SKIP_EMBED_PAYLOAD=1` 避免复制大型目标内容。导入签名的辅助 App 使用 unsigned build 后本地 codesign，`EmbeddedPayload` 的二进制和 SINF 不参与嵌套重签名。

目标重签名前验证所有 cryptid，检查归档路径和符号链接，逐个签名嵌套扩展、框架和主 App，最后严格校验。输入 IPA 不改写。只有安装成功才更新 Bundle ID 历史和最近会话。每个成功会话在重启后仍能打开调试器。Frida 绝对路径随会话保存，也可从界面指定环境覆盖；实际使用前始终检查所选版本并准备相同版本 Gadget。

LLDB 的 `device process attach` 在当前 Xcode 中异步完成，批量脚本立即执行后续命令可能早于附加完成；真机验证使用交互会话，等待停止事件后再读线程、寄存器和内存。

## 本次真机验证

在 iOS 27.0.1 上安装本地构建、已解密的 FairPlayed 测试包，重用辅助 App 的现有开发 App ID，签名结果包含 get-task-allow。LLDB 交互附加后读取线程、PC 和指令内存成功；USB 连接下使用 base 中 Frida 17.26.2 和匹配 Gadget，执行进程信息脚本与 getpid Interceptor Hook 成功。测试包没有第三方业务逻辑，此结果不能证明任意第三方 App 的全部功能可用。导入的分发签名另已通过不同 CFBundleIdentifier 的测试包安装验证，因 profile 未授权 get-task-allow，不用于动态调试验证。

原生界面另使用隔离的模拟后端验证了导出成功询问、保留辅助 App 后自动继续重签名、Bundle ID 历史和成功后显示两个调试器入口。真实桌面 App 已通过严格签名校验。

## Frida 连接与启动方式

Frida 仅允许 USB 有线连接，LLDB 保持可无线使用。USB 检测读取 IORegistry 中 Apple iPhone / iPad 的 USB Serial Number，归一化后匹配目标 UDID，不以 CoreDevice 的隧道传输方式或任意一台手机存在作为判断。界面每 2 秒刷新有线状态，对实际调试会话的目标设备启用或禁用按钮；点击入口和终端实际启动时均重新检查，USB 不可确认时拒绝 Frida。

Frida 启动方式在 GUI 中可选 Attach / Spawn，通过 FRIDA_MODE 保存在本地配置。Attach 先根据 Bundle ID 查询手机上的安装位置，再精确匹配主可执行文件的运行 PID；已运行时直接执行 frida -D <device> -p <pid>，不执行启动或终止命令。未运行时才通过 devicectl 启动，且不带 --terminate-existing，避免查询后的并发启动被覆盖；Spawn 传递 --frida-spawn，使用 Frida -f，在主线程继续前安装 Hook。默认 Attach，LLDB 继续采用 start-stopped。此前将无线连接时的卡顿归因为启动模式的判断不成立，不再为 Spawn 显示卡顿提示。

App 内运行模板只读，Python 模块在用户工作目录运行并使用 -B。构建在全新目录打包，避免混入旧的缓存和本地数据。

## 统一配置与 ID 管理

设备与签名、重新安装合并为一个页面。辅助 App ID 沿用已保存配置并在界面只读；新配置首次生成独立的 dev.unfairplayed.helper.<随机编号> 并固定保存，改变签名身份不再生成新辅助 ID。重新安装支持 helper / custom 两种界面模式，后端会用保存的辅助 ID 解析 helper，忽略调用方另外传入的 ID。旧 CLI 的 new / reuse 保留兼容。

Bundle ID 历史按最近使用去重，最多 10 条；读取旧的 40 条记录时迁移为 10 条，淘汰只改本地记录。成功安装与成功准备 ID 都会记忆。create-bundle 使用独立进程组和任务锁，Xcode 通过 -allowProvisioningUpdates 完成实际预配，返回 FPD_BUNDLE_READY。无法预配时以 FPD_BUNDLE_ACTION 和退出码 79 返回账号、名额、网络等原因，界面保持输入并支持处理后重试。导入签名只创建本地 ID，不伪称注册了 Apple App ID。

合并后的原生界面已用隔离后端验证：侧栏只保留一个设备与签名入口，固定 ID 无编辑控件，10 条历史菜单选择后正确回填，新建 ID 的账号处理入口与重试成功回填均正常。

描述文件未授权调试时，界面强制将动态调试开关关闭并禁用；选择签名时仅按设备、有效期等条件禁用选项，调试能力由开关控制。原生界面验证覆盖了加载旧的开启配置后自动关闭、恢复开发签名后可勾选、沿用辅助签名切换到分发描述文件后再次关闭。后端的 get-task-allow 检查继续保留。

独立「调试」页集中显示安装会话、LLDB / Frida 入口与 Frida 设置；设备与签名页只保留设备、签名、ID、重新安装和跳转入口。成功重新安装后自动进入调试页，侧栏可随时返回。

## 本地 IPA 列表

library 命令返回本地 IPA 元数据，可通过重复 --add 记住外部文件位置，不复制大包。自动扫描下载与导出、Downloads 根目录和旧输出目录；扫描会剪枝 debug 工作目录和解包的 .app，避免大量中间文件拖慢加载。缓存按规范化绝对路径索引，以大小、mtime、ctime 和 inode 检查失效。图标读取包内主图标或 iTunesArtwork，遇到 iOS 优化 PNG 时调用 Xcode pngcrush 还原到缓存，原 IPA 不变。

状态识别只读取主程序的 Mach-O 头和所有 FAT 架构，不能替代重签名前的完整 verify_ipa.sh 检查。PARTIAL 与损坏的包不会作为可直接重新安装的结果。新增回归覆盖元数据和图标提取、主程序状态、所有 FAT 切片、缓存命中与刷新、外部文件引用权限和去重、历史目录发现、损坏文件隔离及原 IPA 字节不变。

本地 IPA 原生界面已用现有 iCalculator 加密包与脱壳包验证：图标正常、分类正确、搜索与清空可用，脱壳包的重新安装按钮会准确带入配置页；独立调试页的会话和有线限制也已检查。

## 任务日志与纯数据框架校验

`TaskLogStore.swift` 把 GUI 收到的任务输出实时写入固定输出目录的 `logs/`，每次独立文件。任务运行前原子记录当前文件与未完成状态；失败后新任务继承前次记录，同一下载、导出及信任重试流程追加同一文件。重启恢复尾部显示，保存操作读取完整磁盘文件，不受界面 150 KB 尾部上限影响。原生日志回归覆盖运行中保存、超长日志、失败重试、未完成恢复和成功后另起任务。

SimpleQR 4.1.1 的 FirebaseCoreExtension 框架具有长度为零的 `__text`，加密区只有数据与填充，原先以新增返回指令作为必要条件造成误判。现保留 remap、完整读页、内容变化和熵校验，再允许严格匹配节边界、非空 ASCII C 字符串及零填充的纯数据候选。指令节重叠、异常节范围、全零读回、坏字符串与非零填充仍拒绝。原生 C 回归覆盖这些拒绝条件；同一原包在 iOS 27.0.1 真机重跑为 24 成功、0 失败，导出后检查全部 24 个二进制的 cryptid 为 0。

重新安装默认只保留主 App，从安装副本中移除嵌套 appex、Watch App 和 App Clip；下载与脱壳 IPA 不变。可勾选保留扩展，届时每个扩展独立解析签名，错误携带实际扩展 Bundle ID，避免主 App 复用时误提示为主 ID 申请失败。回归覆盖扩展移除且不触发预配、保留时独立签名和错误上下文。

LLDB 默认 Attach，根据安装路径及主可执行文件精确查找当前 PID。已有进程时不执行 launch/terminate；未运行时使用 start-stopped 启动，且不传 terminate-existing。显式 Launch 跳过 PID 复用，使用 terminate-existing 与 start-stopped。`LLDB_MODE=attach|launch` 独立于 Frida 配置，经后端生成的终端启动脚本传递 `--lldb-launch`。回归覆盖已有进程不重启、进程状态未知时拒绝启动、未运行时暂停启动、显式重启和配置/脚本传递。

本次 LLDB 真机验证使用 SimpleQR：Attach 附加已运行主进程，前后 PID 一致，线程与 PC 可读取；detach 后再以 Launch 启动，取得新 PID，停止位置为 dyld `_dyld_start`，确认重新启动且尚未进入主程序。验证完成后均 detach，应用恢复运行。

## 自定义 dylib 注入

`dylib_injection.py` 在安装副本中注入，在申请主程序身份和 codesign 之前运行。独立解析 64 位 Mach-O、FAT32/FAT64 与字节序、加载命令长度、架构与 iOS 平台。只在已声明节数据之前的零填充中添加 LC_LOAD_DYLIB，不移动任何代码或链接数据；所有切片验证成功才一次写入，空间不足直接拒绝。新增库统一由已有 sign_app 内层优先签名流程签署。

库复制到 UnfairplayedDylibs，install_name_tool 重写库 ID、所选库之间的依赖及 Substrate 常见越狱路径。Substrate 运行库可选，modern 从已校验的原始文件提取 arm64；legacy 原样保留 arm64/arm64e，再重定位依赖。自定义库不自动裁剪。重复名称、源架构不匹配、模拟器或 macOS 目标、已加密输入及 Hook 依赖缺失均拒绝。原输入不改写，安装副本失败时保留便于分析。会话记录兼容模式、源库 SHA-256、注入后签名前哈希与架构。

来源与本机对比证据见 desktop/InjectionRuntime/README.md。内置库及许可证随桌面 App 的 Resources 打包，运行不依赖本机额外安装 iPatch。

本地回归使用 Xcode 实际交叉编译 iOS arm64/arm64e 主程序和动态库，验证 FAT32/FAT64 与大小端表、所有切片的加载命令、后续切片失败不改写此前切片、代码数据不移动、源库不变、两种运行库架构、依赖重定位、头部空间失败不落盘、错误平台与冲突拒绝，以及 Unicode/空格路径的配置和后端参数传递。

本次注入验证使用独立 UIKit 测试 App（主程序 Validation）、导入的分发签名，以及调用 MSHookMessageEx 的自建测试 dylib。modern 模式已实际通过注入、全部 codesign 校验并安装到 iOS 27.0.1；启动输出 FPD_CUSTOM_DYLIB_PROBE: HOOK-OK，证明动态库构造函数和 Objective-C 类方法替换实际执行。随后收到的同次启动 IPS（18:02:17）显示 UIKit 在 UIApplicationEvaluateRuntimeIssueForNoSceneLifecycleAdoption 中触发 EXC_BREAKPOINT/SIGTRAP；测试 App 未采用当前 SDK 要求的 UIScene 生命周期。此前 devicectl 报告退出码 0 不能作为应用正常运行的依据，已更正该结论。此测试未覆盖修改 __text 的 inline Hook。原生界面已验证开关、文件选择、文件显示和移除、两种兼容模式切换。原用户会话与最近 ID 记录已恢复。legacy 的架构保留与重定位已通过本地检查，未用旧版 iOS 真机验证；不据此承诺任意 dylib 或 inline Hook 都兼容。

## 自包含发布与隐私

App 使用 `WorkspaceBootstrap.swift` 在 `~/Library/Application Support/Unfairplayed/Workspace/` 准备随包运行模板。模板清单经过 SHA-256 校验，持有任务锁后更新允许的运行文件，不覆盖配置、payload 或构建目录。`release_tools.py` 仅拷贝文件白名单，生成不含 Git 元数据的公开源码快照，并扫描两个产物中的构建者主目录、本机签名配置、Git 身份和私有远端域名。

两个 Mac 可执行文件固定为 arm64/macOS 15.0，Info.plist 同步声明 15.0，编译使用文件与调试路径映射。公开产物为 Unfairplayed.app、源码 ZIP、SHA-256 与隐私报告；发布包不记录构建者的仓库路径。

名称和数据路径的迁移只在开发者本机执行一次，迁移脚本不进入产品。新版本没有旧名称、旧配置键或旧目录的回退逻辑。第三方上游项目的真实名称和署名继续保留。
