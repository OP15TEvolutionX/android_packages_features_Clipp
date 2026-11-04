// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
// Implements the Clipp wire primitives using libsodium, not custom
// cryptography. A single JNI entry point keeps the exported surface small;
// ClippCrypto.java wraps each operation in a named method.
#include <cstring>
#include <jni.h>
#include <sodium.h>
#include <stdexcept>
#include <vector>
#include <xxhash.h>
#include <zstd.h>
using Bytes = std::vector<unsigned char>;

// Operation numbers; must match the OP_* constants in ClippCrypto.java.
enum Op : jint {
  OP_DERIVE = 0,         // a = "group|password" -> Argon2id root key
  OP_ROLE = 1,           // a = root, b = {role} -> role key
  OP_SEAL = 2,           // a = key, b = plaintext -> nonce + secretbox
  OP_OPEN = 3,           // a = key, b = nonce + secretbox -> plaintext
  OP_KEY_PAIR = 4,       // -> crypto_kx public key + secret key
  OP_CLIENT_KEYS = 5,    // a = key pair, b = remote public key -> rx + tx
  OP_SERVER_KEYS = 6,    // same, server side
  OP_INIT_PUSH = 7,      // a = tx key -> stream state + header
  OP_INIT_PULL = 8,      // a = rx key, b = header -> stream state
  OP_PUSH = 9,           // a = state (updated in place), b = frame -> ciphertext
  OP_PULL = 10,          // a = state (updated in place), b = ciphertext -> frame
  OP_DECOMPRESS = 11,    // a = zstd data, b = plain size -> data
  OP_CONTENT_HASH = 12,  // a = data, b = format seed -> XXH3-128
  OP_FINGERPRINT = 13,   // a = fingerprint role key -> 16-byte BLAKE2b
};

// Reads a Java byte array; null gives an empty vector.
static Bytes get(JNIEnv *e, jbyteArray a) {
  if (!a)
    return {};
  Bytes b(e->GetArrayLength(a));
  e->GetByteArrayRegion(a, 0, b.size(), reinterpret_cast<jbyte *>(b.data()));
  return b;
}
// Every failed check ends up as IllegalArgumentException in Java.
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
    // Inputs may hold keys; clear the copies however this call ends.
    struct Wipe {
      Bytes &a, &b, &c;
      ~Wipe() {
        sodium_memzero(a.data(), a.size());
        sodium_memzero(b.data(), b.size());
        sodium_memzero(c.data(), c.size());
      }
    } wipe{a, b, c};
    constexpr size_t S = sizeof(crypto_secretstream_xchacha20poly1305_state);
    if (op == OP_DERIVE) {
      // Fixed salt so every device derives the same key from the same password.
      unsigned char salt[16] = {0x9e, 0xa1, 0xe5, 0x5a, 0xbc, 0x07, 0xc8, 0x59,
                                0xfd, 0x90, 0x09, 0x58, 0xd8, 0xb7, 0xef, 0xbe};
      need(a.size() <= 4096);
      o.resize(32);
      need(crypto_pwhash(o.data(), 32, reinterpret_cast<const char *>(a.data()),
                         a.size(), salt, crypto_pwhash_OPSLIMIT_MODERATE,
                         crypto_pwhash_MEMLIMIT_MODERATE,
                         crypto_pwhash_ALG_ARGON2ID13) == 0);
    } else if (op == OP_ROLE) {
      const char *ctx[] = {"CLPC2S01", "CLPS2C01", "CLPMDNS1", "CLPFNGR1"};
      need(a.size() == 32 && b.size() == 1 && b[0] >= 1 && b[0] <= 4);
      o.resize(32);
      need(crypto_kdf_derive_from_key(o.data(), 32, b[0], ctx[b[0] - 1],
                                      a.data()) == 0);
    } else if (op == OP_SEAL) {
      need(a.size() == 32 && b.size() <= 4096);
      o.resize(24 + 16 + b.size());
      randombytes_buf(o.data(), 24);
      need(crypto_secretbox_easy(o.data() + 24, b.data(), b.size(), o.data(),
                                 a.data()) == 0);
    } else if (op == OP_OPEN) {
      need(a.size() == 32 && b.size() >= 40 && b.size() <= 4096);
      o.resize(b.size() - 40);
      need(crypto_secretbox_open_easy(o.data(), b.data() + 24, b.size() - 24,
                                      b.data(), a.data()) == 0);
    } else if (op == OP_KEY_PAIR) {
      o.resize(64);
      need(crypto_kx_keypair(o.data(), o.data() + 32) == 0);
    } else if (op == OP_CLIENT_KEYS || op == OP_SERVER_KEYS) {
      need(a.size() == 64 && b.size() == 32);
      o.resize(64);
      need((op == OP_CLIENT_KEYS ? crypto_kx_client_session_keys(o.data(), o.data() + 32,
                                                    a.data(), a.data() + 32,
                                                    b.data())
                    : crypto_kx_server_session_keys(o.data(), o.data() + 32,
                                                    a.data(), a.data() + 32,
                                                    b.data())) == 0);
    } else if (op == OP_INIT_PUSH) {
      need(a.size() == 32);
      crypto_secretstream_xchacha20poly1305_state st{};
      o.resize(S + 24);
      need(crypto_secretstream_xchacha20poly1305_init_push(&st, o.data() + S,
                                                           a.data()) == 0);
      memcpy(o.data(), &st, S);
      sodium_memzero(&st, S);
    } else if (op == OP_INIT_PULL) {
      need(a.size() == 32 && b.size() == 24);
      crypto_secretstream_xchacha20poly1305_state st{};
      need(crypto_secretstream_xchacha20poly1305_init_pull(&st, b.data(),
                                                           a.data()) == 0);
      o.resize(S);
      memcpy(o.data(), &st, S);
      sodium_memzero(&st, S);
    } else if (op == OP_PUSH || op == OP_PULL) {
      need(a.size() == S && b.size() <= 64 * 1024 * 1024);
      crypto_secretstream_xchacha20poly1305_state st{};
      memcpy(&st, a.data(), S);
      unsigned long long len = 0;
      if (op == OP_PUSH) {
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
      // Write the advanced state back so the next frame continues the stream.
      e->SetByteArrayRegion(aa, 0, S, reinterpret_cast<const jbyte *>(&st));
      sodium_memzero(&st, S);
    } else if (op == OP_DECOMPRESS) {
      need(b.size() == 4);
      uint32_t limit = (uint32_t(b[0]) << 24) | (uint32_t(b[1]) << 16) |
                       (uint32_t(b[2]) << 8) | b[3];
      need(limit <= 50 * 1024 * 1024);
      o.resize(limit);
      ZSTD_DCtx *ctx = ZSTD_createDCtx();
      need(ctx != nullptr);
      // 64 MiB window at most, so a hostile frame can't demand more memory.
      ZSTD_DCtx_setParameter(ctx, ZSTD_d_windowLogMax, 26);
      size_t size =
          ZSTD_decompressDCtx(ctx, o.data(), o.size(), a.data(), a.size());
      ZSTD_freeDCtx(ctx);
      need(!ZSTD_isError(size) && size == limit);
    } else if (op == OP_CONTENT_HASH) {
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
    } else if (op == OP_FINGERPRINT) {
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
