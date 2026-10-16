// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
// Implements the Clipp wire primitives using libsodium, not custom
// cryptography.
#include <cstring>
#include <jni.h>
#include <sodium.h>
#include <stdexcept>
#include <vector>
#include <xxhash.h>
#include <zstd.h>
using Bytes = std::vector<unsigned char>;
static Bytes get(JNIEnv *e, jbyteArray a) {
  if (!a)
    return {};
  Bytes b(e->GetArrayLength(a));
  e->GetByteArrayRegion(a, 0, b.size(), reinterpret_cast<jbyte *>(b.data()));
  return b;
}
static void need(bool b) {
  if (!b)
    throw std::runtime_error("Clipp cryptographic operation failed");
}
static jbyteArray result(JNIEnv *e, const Bytes &b) {
  auto a = e->NewByteArray(b.size());
  if (a)
    e->SetByteArrayRegion(a, 0, b.size(),
                          reinterpret_cast<const jbyte *>(b.data()));
  return a;
}
extern "C" JNIEXPORT jbyteArray JNICALL
Java_org_evolution_clipp_ClippCrypto_call(JNIEnv *e, jclass, jint op,
                                          jbyteArray aa, jbyteArray bb,
                                          jbyteArray cc) {
  try {
    need(sodium_init() >= 0);
    Bytes a = get(e, aa), b = get(e, bb), c = get(e, cc), o;
    struct Wipe {
      Bytes &a, &b, &c;
      ~Wipe() {
        sodium_memzero(a.data(), a.size());
        sodium_memzero(b.data(), b.size());
        sodium_memzero(c.data(), c.size());
      }
    } wipe{a, b, c};
    constexpr size_t S = sizeof(crypto_secretstream_xchacha20poly1305_state);
    if (op == 0) {
      unsigned char salt[16] = {0x9e, 0xa1, 0xe5, 0x5a, 0xbc, 0x07, 0xc8, 0x59,
                                0xfd, 0x90, 0x09, 0x58, 0xd8, 0xb7, 0xef, 0xbe};
      need(a.size() <= 4096);
      o.resize(32);
      need(crypto_pwhash(o.data(), 32, reinterpret_cast<const char *>(a.data()),
                         a.size(), salt, crypto_pwhash_OPSLIMIT_MODERATE,
                         crypto_pwhash_MEMLIMIT_MODERATE,
                         crypto_pwhash_ALG_ARGON2ID13) == 0);
    } else if (op == 1) {
      const char *ctx[] = {"CLPC2S01", "CLPS2C01", "CLPMDNS1", "CLPFNGR1"};
      need(a.size() == 32 && b.size() == 1 && b[0] >= 1 && b[0] <= 4);
      o.resize(32);
      need(crypto_kdf_derive_from_key(o.data(), 32, b[0], ctx[b[0] - 1],
                                      a.data()) == 0);
    } else if (op == 2) {
      need(a.size() == 32 && b.size() <= 4096);
      o.resize(24 + 16 + b.size());
      randombytes_buf(o.data(), 24);
      need(crypto_secretbox_easy(o.data() + 24, b.data(), b.size(), o.data(),
                                 a.data()) == 0);
    } else if (op == 3) {
      need(a.size() == 32 && b.size() >= 40 && b.size() <= 4096);
      o.resize(b.size() - 40);
      need(crypto_secretbox_open_easy(o.data(), b.data() + 24, b.size() - 24,
                                      b.data(), a.data()) == 0);
    } else if (op == 4) {
      o.resize(64);
      need(crypto_kx_keypair(o.data(), o.data() + 32) == 0);
    } else if (op == 5 || op == 6) {
      need(a.size() == 64 && b.size() == 32);
      o.resize(64);
      need((op == 5 ? crypto_kx_client_session_keys(o.data(), o.data() + 32,
                                                    a.data(), a.data() + 32,
                                                    b.data())
                    : crypto_kx_server_session_keys(o.data(), o.data() + 32,
                                                    a.data(), a.data() + 32,
                                                    b.data())) == 0);
    } else if (op == 7) {
      need(a.size() == 32);
      crypto_secretstream_xchacha20poly1305_state st{};
      o.resize(S + 24);
      need(crypto_secretstream_xchacha20poly1305_init_push(&st, o.data() + S,
                                                           a.data()) == 0);
      memcpy(o.data(), &st, S);
      sodium_memzero(&st, S);
    } else if (op == 8) {
      need(a.size() == 32 && b.size() == 24);
      crypto_secretstream_xchacha20poly1305_state st{};
      need(crypto_secretstream_xchacha20poly1305_init_pull(&st, b.data(),
                                                           a.data()) == 0);
      o.resize(S);
      memcpy(o.data(), &st, S);
      sodium_memzero(&st, S);
    } else if (op == 9 || op == 10) {
      need(a.size() == S && b.size() <= 64 * 1024 * 1024);
      crypto_secretstream_xchacha20poly1305_state st{};
      memcpy(&st, a.data(), S);
      unsigned long long len = 0;
      if (op == 9) {
        o.resize(b.size() + 17);
        need(crypto_secretstream_xchacha20poly1305_push(
                 &st, o.data(), &len, b.data(), b.size(), nullptr, 0, 0) == 0);
      } else {
        need(b.size() >= 17);
        o.resize(b.size() - 17);
        unsigned char tag;
        need(crypto_secretstream_xchacha20poly1305_pull(
                 &st, o.data(), &len, &tag, b.data(), b.size(), nullptr, 0) ==
             0);
        need(tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL);
      }
      o.resize(len);
      e->SetByteArrayRegion(aa, 0, S, reinterpret_cast<const jbyte *>(&st));
      sodium_memzero(&st, S);
    } else if (op == 11) {
      need(b.size() == 4);
      uint32_t limit = (uint32_t(b[0]) << 24) | (uint32_t(b[1]) << 16) |
                       (uint32_t(b[2]) << 8) | b[3];
      need(limit <= 50 * 1024 * 1024);
      o.resize(limit);
      ZSTD_DCtx *ctx = ZSTD_createDCtx();
      need(ctx != nullptr);
      ZSTD_DCtx_setParameter(ctx, ZSTD_d_windowLogMax, 26);
      size_t size =
          ZSTD_decompressDCtx(ctx, o.data(), o.size(), a.data(), a.size());
      ZSTD_freeDCtx(ctx);
      need(!ZSTD_isError(size) && size == limit);
    } else if (op == 12) {
      o.resize(16);
      XXH128_canonical_t h;
      XXH128_canonicalFromHash(
          &h,
          XXH3_128bits_withSeed(a.data(), a.size(),
                                b.size() == 4 ? ((uint32_t(b[0]) << 24) |
                                                 (uint32_t(b[1]) << 16) |
                                                 (uint32_t(b[2]) << 8) | b[3])
                                              : 0));
      memcpy(o.data(), h.digest, 16);
    } else if (op == 13) {
      need(a.size() == 32);
      o.resize(16);
      need(crypto_generichash(o.data(), 16, a.data(), 32, nullptr, 0) == 0);
    } else
      need(false);
    return result(e, o);
  } catch (const std::exception &) {
    e->ThrowNew(e->FindClass("java/lang/IllegalArgumentException"),
                "Clipp cryptographic operation failed");
    return nullptr;
  }
}
