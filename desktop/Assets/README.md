# Unfairplayed Logo

蓝色圆角底、白色锤子的扁平图标，用于 macOS App 图标及界面品牌标识。

- `UnfairplayedLogo.png`：1254 × 1254 原始生成图，保留透明外边距。
- `Unfairplayed.icns`：macOS 多分辨率图标，通过 `../build_icon.sh` 从 PNG 打包生成。
- `../../build_desktop.sh` 会复制资源并设置 `CFBundleIconFile`。

使用内置 `image_gen` 生成。完整提示词：

```text
Use case: logo-brand. Asset type: final macOS app icon for FairPlayed, a desktop IPA utility. Create ONE polished, flat, minimalist icon, square composition at high resolution. A single solid vivid blue (#1677F2) rounded-square tile, centered and occupying about 88% of the canvas, with transparent exterior corners/margin suitable for a macOS app icon. Inside: one bold white, beautifully balanced hammer silhouette, diagonally oriented with handle toward bottom-left and hammer head toward top-right. A practical engineering hammer with a short sturdy handle, compact broad rectangular striking head, subtly rounded geometric corners, instantly recognizable at 32 px. The hammer fills approximately 60% of the tile with generous even blue breathing room. Two flat colors only: blue background and white hammer. Crisp vector-like contours, precise optical centering, clean modern app-icon design. No letters, no text, no border, no extra symbols, no gavel, no pickaxe, no cracks, no sparks, no gradients, no texture, no drop shadow, no 3D, no mockup, no icon sheet.
```
