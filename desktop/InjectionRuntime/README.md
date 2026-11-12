# iPatch Hook compatibility runtime

This product includes software developed by CoolStar.

These three original universal binaries are redistributed from
[EamonTracey/iPatch](https://github.com/EamonTracey/iPatch), commit
`61e9d82cd4e6af4526a686c7d780d758377a6e4c`, `iPatch/Libs/`.
See `LICENSE.iPatch` (MIT) and `LICENSE.libhooker` (BSD-4-Clause).
The underlying runtime project is https://github.com/coolstar/libhooker.

| Original file | SHA-256 |
| --- | --- |
| libsubstrate.dylib | ddb437812d23e898de98ac7692d59edfb667d625a4663b619e6e9efe31e06e82 |
| libhooker.dylib | 854571b8277ae12922b18f5cc08a3db87ba9bf5546f5730b3ada6c7d40091838 |
| libblackjack.dylib | b4405a500a47983ee89d51d81349655d5f99295ff92092ee8f306673acd9e1d7 |

The original arm64e slices use CPU subtype `0x00000002`. For comparison,
Xcode 27 emits subtype `0x80000002` for a newly built arm64e dylib, indicating
the versioned pointer-authentication ABI. This metadata difference supports
an architecture/ABI compatibility explanation; it does not establish an exact
iOS release at which these original slices stopped working.

On the development Mac, all three `/Applications/iPatch.app/Contents/Resources/`
`.bak` files exactly matched the upstream universal files. Each active dylib
exactly matched `lipo -thin arm64` of its upstream file. No code patch was found.

Unfairplayed verifies these original hashes, then operates on copies:

* **modern**: extract only arm64, reproducing the locally working architecture choice.
* **legacy**: retain the original arm64 and arm64e slices.

Both modes then relocate install names/dependencies into the installation copy's
`UnfairplayedDylibs/` and sign them with the selected app identity. User-provided
dylibs retain their original architectures; this selector changes the bundled
Hook runtime only. No automatic iOS 17/18 version threshold is assumed.
