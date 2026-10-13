# Upstream

Clipp protocol: https://github.com/martona/clipp, revision d79b7bf841e1d7564a8c19e167f5ee84838975fa (MIT).
These protocol files are identical in the published desktop release v1.5.0.160.
Wire layouts, key derivation contexts, handshake roles, secretstream framing,
DNS-SD TXT record format and format IDs follow this revision. The Android
implementation is independent; MIT notices are retained in LICENSE.clipp.

Android clipboard integration was adapted from OP15TEvolutionX/android_packages_features_ClipboardSync,
revision d675a14, originally adapted from shaklow/syncclipboard-xposed.

Vendored dependencies:
- libsodium 1.0.20, ISC license: third_party/libsodium/LICENSE.
- xxHash 0.8.3, BSD license: third_party/xxhash/LICENSE.
- Zstandard sources from EvolutionX external/zstd (revision recorded below), dual BSD/GPL;
  use is under the BSD license in third_party/zstd/LICENSE.

Android adaptations:
- Sources are compiled inside Settings and SystemUI. The Settings entry remains
  in Connection preferences after Quick Share; no separate launcher app.
- A small JNI library uses libsodium's authenticated primitives; no custom cryptography.
  Argon2id group setup runs in a separate Settings provider process. The root key is
  encrypted at rest with Android Keystore AES-GCM; private signature-checked IPC
  gives SystemUI access only after credential unlock. Passphrases are not stored.
- Wi-Fi-scoped DNS-SD discovery/announcements replace manual server addresses.
  Five peers maximum; incoming and outgoing directional TCP links match Clipp.
- Text, PNG and JPEG only. Other readable Android images are converted to PNG.
  Text limit 1 MiB, image limits 5/10/20/50 MiB, decoded image dimensions are bounded.
  Zstd output and window size are bounded before allocation/decompression.
- No HTTP/SignalR and no HTTP polling. No permanent wake or Wi-Fi locks.
  Discovery and all sockets stop five minutes after screen off and restart on unlock.
  Discovery events accelerate reconnection; bounded backoff is a fallback.
- Latest-item SYNC catch-up is supported, without full history/register storage.
  Intermediate history entries never replace the Android clipboard. A catch-up older
  than the last local copy or already-applied remote copy is ignored; this assumes
  reasonably synchronized clocks. Private source flags are excluded.
- Event IDs and content hashes prevent echoes; ordinary mesh packets are not relayed.
  One-shot relay packets are forwarded with the relay flag cleared.
- Group members trust each other. Blocking a device applies only to the phone;
  other computers in the same group may still synchronize directly.

Desktop requirements follow Clipp: Windows 10 1809+; macOS 14+ on Apple Silicon.
LAN multicast/firewall restrictions and Android sleep can delay discovery. Fast
reconnection and battery usage require verification on actual devices.

Zstandard revision: 1bfdf8aef6bdec0e817c1f75aeaf382db22de668
