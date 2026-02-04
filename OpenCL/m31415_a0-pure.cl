/**
 * Author......: wtvemac, see also docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif

KERNEL_FQ KERNEL_FA void m31415_mxx (KERN_ATTR_RULES ())
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // Setup the data after encryption (salt input)
  const u32 salt_buf0[2] = {
    salt_bufs[SALT_POS_HOST].salt_buf_pc[0],
    salt_bufs[SALT_POS_HOST].salt_buf_pc[1]
  };

  // Setup variables to keep the key schedule and other DES context for decryption.

  u32 key_sched[6][16];
  u32 data[4][2];

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];
  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 l_idx = 0; l_idx < 64; l_idx++)
  {
    #ifdef _unroll
    #pragma unroll
    #endif
    for (u32 s_idx = 0; s_idx < 8; s_idx++)
    {
      s_SPtrans[s_idx][l_idx] = c_SPtrans[s_idx][l_idx];
      s_skb[s_idx][l_idx] = c_skb[s_idx][l_idx];
    }
  }
  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  // Setup password
  COPY_PW (pws[gid]);

  // Loop through passwords, decrypt the data with the password and check if the decrypted data matches the known decrypted data we have
  // If we matched our data then we found the password.

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    // Prepare the current password
    pw_t tmp = PASTE_PW;
    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    // Get the SHA1 of the current password.
    sha1_ctx_t s1ctx;
    sha1_init (&s1ctx);
    sha1_update_swap (&s1ctx, tmp.i, tmp.pw_len);
    sha1_final (&s1ctx);

    // The 3DES key is the full SHA1 result, with the last 4 bytes being the first 4 bytes of the SHA1 repeated.
    const u32 key[5] = {
      hc_swap32_S(s1ctx.h[0]),
      hc_swap32_S(s1ctx.h[1]),
      hc_swap32_S(s1ctx.h[2]),
      hc_swap32_S(s1ctx.h[3]),
      hc_swap32_S(s1ctx.h[4])
    };

    // The 3DES IV is the 3rd byte of the SHA1 to the 11th byte of the SHA1.
    // We shift bits around to generate the intended IV since we're dealing with 32-bit ints rather than bytes.
    const u32 iv[2] = {
      (s1ctx.h[0] << 0x10) | (s1ctx.h[1] >> 0x10),
      (s1ctx.h[1] << 0x10) | (s1ctx.h[2] >> 0x10)
    };

    data[0][0] = salt_buf0[0];
    data[0][1] = salt_buf0[1];

    // DES pass 1, Dencrypt with first key
    _des_crypt_keysetup_wtv (key[4],  key[0],  key_sched[0], key_sched[1], s_skb    );
    _des_crypt_decrypt_wtv  (data[1], data[0], key_sched[0], key_sched[1], s_SPtrans);

    // DES pass 2, Enecrypt with second key
    _des_crypt_keysetup_wtv (key[2],  key[3],  key_sched[2], key_sched[3], s_skb    );
    _des_crypt_encrypt_wtv  (data[2], data[1], key_sched[2], key_sched[3], s_SPtrans);

    // DES pass 3, Decrypt with third key
    _des_crypt_keysetup_wtv (key[0],  key[1],  key_sched[4], key_sched[5], s_skb    );
    _des_crypt_decrypt_wtv  (data[3], data[2], key_sched[4], key_sched[5], s_SPtrans);

    DES_FP (data[3][1], data[3][0]);
    data[3][0] = hc_swap32_S (data[3][0]) ^ iv[0];
    data[3][1] = hc_swap32_S (data[3][1]) ^ iv[1];

    // Check unencrypted data
    // Since we're only checking 8 bytes, we fill the rest of the buffer with 0 (z)
    // >> 8 allows us to compare the remaining 3 bytes since my confidence is higher we know those bytes.
    const u32x z = 0;
    data[3][0] >>= 8;
    data[3][1] >>= 8;
    COMPARE_M_SCALAR (data[3][0], data[3][1], z, z);
  }
}

KERNEL_FQ KERNEL_FA void m31415_sxx (KERN_ATTR_RULES ())
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // We're searching for the unencrypted data (digest input)
  // We will try to decrypt the salt input with various passwords until we match this.
  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    0,
    0
  };

  // Setup the data after encryption (salt input)
  const u32 salt_buf0[2] = {
    salt_bufs[SALT_POS_HOST].salt_buf_pc[0],
    salt_bufs[SALT_POS_HOST].salt_buf_pc[1]
  };

  // Setup variables to keep the key schedule and other DES context for decryption.

  u32 key_sched[6][16];
  u32 data[4][2];

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];
  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 l_idx = 0; l_idx < 64; l_idx++)
  {
    #ifdef _unroll
    #pragma unroll
    #endif
    for (u32 s_idx = 0; s_idx < 8; s_idx++)
    {
      s_SPtrans[s_idx][l_idx] = c_SPtrans[s_idx][l_idx];
      s_skb[s_idx][l_idx] = c_skb[s_idx][l_idx];
    }
  }
  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  // Setup password
  COPY_PW (pws[gid]);

  // Loop through passwords, decrypt the data with the password and check if the decrypted data matches the known decrypted data we have
  // If we matched our data then we found the password.

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    // Prepare the current password to try using specified rules.
    pw_t tmp = PASTE_PW;
    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    // Get the SHA1 of the current password.
    sha1_ctx_t s1ctx;
    sha1_init (&s1ctx);
    sha1_update_swap (&s1ctx, tmp.i, tmp.pw_len);
    sha1_final (&s1ctx);

    // The 3DES key is the full SHA1 result, with the last 4 bytes being the first 4 bytes of the SHA1 repeated.
    const u32 key[5] = {
      hc_swap32_S(s1ctx.h[0]),
      hc_swap32_S(s1ctx.h[1]),
      hc_swap32_S(s1ctx.h[2]),
      hc_swap32_S(s1ctx.h[3]),
      hc_swap32_S(s1ctx.h[4])
    };

    // The 3DES IV is the 3rd byte of the SHA1 to the 11th byte of the SHA1.
    // We shift bits around to generate the intended IV since we're dealing with 32-bit ints rather than bytes.
    const u32 iv[2] = {
      (s1ctx.h[0] << 0x10) | (s1ctx.h[1] >> 0x10),
      (s1ctx.h[1] << 0x10) | (s1ctx.h[2] >> 0x10)
    };

    data[0][0] = salt_buf0[0];
    data[0][1] = salt_buf0[1];

    // DES pass 1, Dencrypt with first key
    _des_crypt_keysetup_wtv (key[4],  key[0],  key_sched[0], key_sched[1], s_skb    );
    _des_crypt_decrypt_wtv  (data[1], data[0], key_sched[0], key_sched[1], s_SPtrans);

    // DES pass 2, Enecrypt with second key
    _des_crypt_keysetup_wtv (key[2],  key[3],  key_sched[2], key_sched[3], s_skb    );
    _des_crypt_encrypt_wtv  (data[2], data[1], key_sched[2], key_sched[3], s_SPtrans);

    // DES pass 3, Decrypt with third key
    _des_crypt_keysetup_wtv (key[0],  key[1],  key_sched[4], key_sched[5], s_skb    );
    _des_crypt_decrypt_wtv  (data[3], data[2], key_sched[4], key_sched[5], s_SPtrans);

    DES_FP (data[3][1], data[3][0]);
    data[3][0] = hc_swap32_S (data[3][0]) ^ iv[0];
    data[3][1] = hc_swap32_S (data[3][1]) ^ iv[1];

    // Check unencrypted data
    // Since we're only checking 8 bytes, we fill the rest of the buffer with 0 (z)
    // >> 8 allows us to compare the remaining 3 bytes since my confidence is higher we know those bytes.
    const u32x z = 0;
    data[3][0] >>= 8;
    data[3][1] >>= 8;
    COMPARE_S_SCALAR (data[3][0], data[3][1], z, z);
  }
}
