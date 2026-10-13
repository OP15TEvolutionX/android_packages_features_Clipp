# Upstream

## Sources

- [Clipp](https://github.com/martona/clipp), revision
  `d79b7bf841e1d7564a8c19e167f5ee84838975fa`, compatible with desktop release
  `v1.5.0.160`. Protocol reference under the MIT license; notices are retained
  in [LICENSE.clipp](LICENSE.clipp).
- Android clipboard integration derives from
  [ClipboardSync](https://github.com/OP15TEvolutionX/android_packages_features_ClipboardSync),
  revision `d675a14`, originally adapted from
  [syncclipboard-xposed](https://github.com/shaklow/syncclipboard-xposed).
  Original copyright notices are preserved.

## Dependencies

- libsodium 1.0.20 — [ISC license](third_party/libsodium/LICENSE).
- xxHash 0.8.3 — [BSD license](third_party/xxhash/LICENSE).
- Zstandard from EvolutionX `external/zstd`, revision
  `1bfdf8aef6bdec0e817c1f75aeaf382db22de668` — used under its
  [BSD license](third_party/zstd/LICENSE).

## Android integration

Sources compile into Settings and SystemUI, with a JNI library for protocol
primitives. Integration resides in the host repositories and is connected
through the ROM manifest. The Settings entry appears after Quick Share.

Devices use Wi-Fi discovery and a shared group and passphrase. Text, PNG and
JPEG synchronize through the system clipboard; other readable image formats
are converted to PNG. Historical replay frames do not change the Android clipboard. The client excludes
private clipboard entries. Event IDs and content hashes prevent duplicates.

Group keys are protected by Android Keystore; passphrases are not stored.
Connections and discovery stop in deep Doze and resume on exit. Text and images received
while the keyguard is showing are retained until `USER_PRESENT`; the deferred
write suppresses the clipboard preview. Live writes while unlocked keep the preview. A bounded cleanup wake
lock lets DNS-SD send its exit announcements before suspend; sockets close immediately.

An image-only share target uses a NoDisplay activity and a short-lived internal
SystemUI service. Shared images are copied into a private cache so paste access survives
the sender closing; no accessibility service is needed.

## Updating Clipp compatibility

The protocol is an Android port, so upstream C++ fixes require review and translation.

| Upstream | Android implementation |
| --- | --- |
| `NetworkDefs`, `ClipboardWire` | `ClippWire`: packed fields, framing and payload validation |
| `CryptoChannel`, `KeyManager` | `ClippWire`, `ClippCrypto`, `native/crypto.cpp`: handshake and primitives |
| `MDNSProtocol` | `ClippDiscovery`: discovery packet layout |
| `Peer`, `PeerManager`, `RegisterWire` | `ClippTransport`: discovery lifecycle, links and control messages |

`ClippEngine` owns Android clipboard access and Doze policy; Settings owns UI and
key storage. Keep protocol changes out of these platform layers where possible.

Compare upstream changes against the revision listed above using the mapping in this
section. Port relevant fixes and verify both handshake roles and clipboard formats
against the target desktop version before updating the documented revision.
