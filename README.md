# DroidLens

**On-device APK security triage, decompilation, and dynamic component fuzzing for Android.**

No PC. No Termux. No cloud. Everything runs in-process on the phone.

---

## What it does

DroidLens is an Android app that analyzes other Android apps. You pick an APK,
it parses it from the bytes up — no `apktool`, no external binaries — and tells
you what's interesting: what it exports, what secrets it ships, what native
code it bundles, what frameworks it uses, and what happens when you poke its
components at runtime.

Built entirely on a tablet in **CodeAssist**, targeting Android 14/15, with
custom implementations of three binary formats the platform normally hides
from you: AXML, ARSC, and DEX.

---

## Features

### Static analysis — parsers

- **Custom AndroidManifest.xml parser** — walks the binary AXML chunk structure
  and the string pool, emits readable XML. No apktool, no external tooling.
- **Custom resources.arsc decoder** — resolves resource IDs (`0x7f0f001c`) back
  to their string values, so `android:label` shows as the real app name.
- **Custom DEX parser** — enumerates every class across `classes*.dex`, handles
  MUTF-8 correctly, and survives crafted or oversized DEX files.
- **APK inventory** — full ZIP listing grouped by top-level folder, with size
  breakdown per directory.
- **Streamed hashing** — SHA-256 and MD5 computed with an 8 KB buffer, so
  multi-hundred-megabyte APKs never load fully into memory.

### Static analysis — signal extraction

- **Signing certificate extraction** — reads v1 (JAR) and v2/v3
  (`PackageManager.GET_SIGNING_CERTIFICATES`) signatures, reports subject,
  issuer, validity, and algorithm.
- **Exported component analysis** — finds every activity, service, receiver,
  and provider reachable from other apps on the device, including legacy
  implicit exports (intent-filter without `android:exported`).
- **Secrets & strings scanner** — every string from every DEX file, pattern-
  matched for API keys (Google, AWS, Stripe), JWTs, Firebase URLs, OAuth
  endpoints, crypto wallet addresses, Egyptian phone numbers, emails, and
  URLs. URLs are categorized (torrent trackers, piracy fronts, debrid
  services, streaming embeds) so the noise separates itself.
- **Native library scanner** — printable string extraction from every `.so`
  in the APK's `lib/` folder, with threat pattern matching for Frida,
  gdbserver, lldb-server, root-detection paths, anti-debug primitives,
  JNI entry points, and bundled OpenSSL.
- **Flutter detection** — recognizes Flutter apps by the presence of both
  `libflutter.so` and `libapp.so`, then extracts strings from the Dart AOT
  snapshot and pattern-matches Dart packages (`crypto`, `dio`,
  `flutter_secure_storage`, `webview_flutter`, Firebase) and runtime bridges
  (`dart:ffi`, MethodChannel, `dart:isolate`).

### Static analysis — aggregation

- **Severity-ranked findings engine** — merges signing, manifest flags,
  dangerous permissions, dangerous permission combinations, accessibility
  services, exported components, known SDK signatures, and SDK-version
  compatibility into one sorted list.

### Decompilation

- **On-device jadx** — full Java source recovery for any class in the APK,
  via `jadx-core` + `jadx-dex-input` 1.4.7. No server, no PC.
- **Class tree browser** — packages → classes → inner classes, with linear
  package chains collapsed (`com.example.bet` reads as one row, not three),
  search filtering, and expand/collapse.
- **Inner-class handling** — anonymous and nested classes are decompiled via
  their enclosing class when jadx inlines them, with an explanatory header
  instead of a blank screen.
- **Source viewer** — monospace scrollable Java source with a copy button.

### Dynamic analysis (Shizuku)

- **Intent fuzzer** — sends crafted Intents at every exported component and
  watches for crashes via logcat. Payloads cover malformed strings (path
  traversal, format strings, nulls), type confusion (int-as-string,
  bool-as-string, URI-as-string), and boundary lengths.
- **Runs without root** — uses **Shizuku** to run under the shell UID, giving
  access to `am start`, `am force-stop`, and full logcat reads. Works on any
  Android 11+ device with Wireless Debugging.
- **Crash extraction** — parses `FATAL EXCEPTION` blocks from logcat between
  each payload, filters for the target package, and surfaces the exception
  class and stack head.

---

## Stack

- **Kotlin** + Material 3, XML layouts (no Compose)
- **jadx-core 1.4.7** + **jadx-dex-input 1.4.7** (official Skylot builds; the
  1.5.x line and community forks are incompatible with each other)
- **Shizuku** (`dev.rikka.shizuku:api` + `:provider`) for shell-level access
- **Custom parsers** for AXML, ARSC, DEX, and native string extraction
- **Target:** Android 14/15 tablet (Redmi Pad 2), Min SDK 26, Target SDK 36

No Termux. No adb from a PC. No server component. No network calls.

---

## Why custom parsers

`apktool`, `aapt2`, and `dexlib2` all assume a desktop environment. DroidLens
runs on a phone, in-process, with no external binaries to shell out to — so
every binary format it needs to read is parsed by hand.

This sounds like masochism. It mostly is. It also means:

- No 40 MB apktool JAR bundled in the APK
- No `Runtime.exec()` calls that fail on locked-down devices
- Full control over malformed-input handling (both AXML and DEX parsers
  validate offsets with `Long` math and cap entry counts to prevent DoS)
- Works offline, in airplane mode, with no permissions

---

## Usage

1. Install **Shizuku** from [shizuku.rikka.app](https://shizuku.rikka.app/)
   and start it via **Wireless Debugging**.
2. Open **DroidLens** and grant it Shizuku access when prompted.
3. Tap **Pick APK** and select any `.apk` file on the device.
4. Tap **Analyze**.
5. Browse the collapsible result cards:
   - Findings (severity-ranked)
   - Overview (package, version, SDK levels)
   - Components (activity/service/receiver/provider counts)
   - APK Contents (file inventory)
   - DEX Classes (per-DEX class counts, top packages)
   - Native Libraries (per-`.so` string counts, threat patterns)
   - Flutter (only shown if the APK is a Flutter app)
   - Permissions
   - Secrets & Strings
   - Fingerprint & Signing
   - Exported Components
   - Raw Manifest

6. Tap **Browse all classes** to open the class tree, then tap any class to
   see its decompiled Java source.
7. For dynamic testing, tap **Run Intent Fuzzer (Shizuku)** on the Exported
   Components card. DroidLens will cycle through every exported activity with
   each malformed payload, force-stopping the target between iterations and
   scanning logcat for crashes.

**Note:** the fuzzer requires the target app to be **installed**, not just an
APK file on disk. Static analysis works on any file; dynamic analysis needs a
running package.

---

## Limitations

Honest list, because the interesting parts of this project are the ones that
were hard:

- **No Frida, no runtime hooking.** Both require root. Shizuku grants shell
  UID, not `ptrace` or `LD_PRELOAD` access to other processes.
- **Anonymous inner classes can't be decompiled standalone.** jadx inlines
  them into their enclosing method. DroidLens detects this and shows the
  outer class with a header explaining the substitution.
- **Model loading is slow.** jadx takes 5–30 seconds to load a large APK,
  depending on DEX count. First tap after analysis may wait.
- **First build after adding jadx dependencies takes ~100 seconds.** This is
  DEX regeneration. Warm builds are ~10 seconds.
- **Fuzzer payload set is intentionally small.** Broad-spectrum probes
  (malformed strings, type confusion). Deep per-component fuzzing (real extra
  keys extracted from decompiled source) is not yet implemented.

---

## Roadmap

- [x] Custom AXML / ARSC / DEX parsers
- [x] Signing extraction (v1 / v2 / v3)
- [x] Exported component analysis
- [x] Secrets + native + Flutter scanners
- [x] On-device jadx decompilation
- [x] Class tree browser with inner-class support
- [x] Shizuku-powered intent fuzzer
- [ ] Report export (HTML / JSON)
- [ ] Deep-link fuzzing (malformed URIs on `VIEW` filters)
- [ ] Non-exported component fuzzing (shell UID can reach them)
- [ ] Extra-key extraction from decompiled source for targeted fuzzing
- [ ] Network security config analysis
- [ ] Certificate pinning detection

---

## Author

**Pha4tom** — [github.com/Pha4tom](https://github.com/Pha4tom)

Built on a Redmi Pad 2 in CodeAssist, with no PC and no willingness to accept
"just use Android Studio."

---

## License

MIT License

Copyright (c) 2026 Pha4tom

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
