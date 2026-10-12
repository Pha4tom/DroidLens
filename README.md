# DroidLens

On-device APK security triage and decompilation for Android.

## Features
- Binary AndroidManifest.xml parser (custom, no apktool needed)
- Resource table decoder (resources.arsc)
- DEX class enumeration (custom parser)
- Signing certificate extraction
- Exported component analysis (attack surface)
- Heuristic findings engine (severity-ranked)
- **On-device jadx decompilation to Java source**

## Stack
- Kotlin, Material 3, XML layouts
- jadx-core + jadx-dex-input (1.4.7)
- Custom AXML, ARSC, and DEX parsers
- No Termux, no PC, no cloud

## Build
Requires CodeAssist or Android Studio. Min SDK 26.
