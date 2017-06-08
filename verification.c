/*
 *
 * The Secure Remote Password 6a implementation included here is by
 *  - Tom Cocagne
 *    <https://github.com/cocagne/csrp>
 *
 *
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <plist/plist.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sodium.h>

#include "verification.h"

#define USERNAME "12:34:56:78:90:AB"
#define AUTHTAG_LENGTH 16
#define AES_SETUP_KEY  "Pair-Setup-AES-Key"
#define AES_SETUP_IV   "Pair-Setup-AES-IV"
#define AES_VERIFY_KEY "Pair-Verify-AES-Key"
#define AES_VERIFY_IV  "Pair-Verify-AES-IV"

enum hash_alg
{
  HASH_SHA1, 
  HASH_SHA224,
  HASH_SHA256,
  HASH_SHA384,
  HASH_SHA512,
};

struct verification_setup_context
{
  struct SRPUser *user;

  char pin[4];

  const uint8_t *pkA;
  int pkA_len;

  uint8_t *pkB;
  uint64_t pkB_len;

  const uint8_t *M1;
  int M1_len;

  uint8_t *M2;
  uint64_t M2_len;

  uint8_t *salt;
  uint64_t salt_len;
  uint8_t public_key[crypto_sign_PUBLICKEYBYTES];
  uint8_t private_key[crypto_sign_SECRETKEYBYTES];
  // Hex-formatet concatenation of public + private, 0-terminated
  char auth_key[2 * (crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES) + 1];

  // We don't actually use the server's epk and authtag for anything
  uint8_t *epk;
  uint64_t epk_len;
  uint8_t *authtag;
  uint64_t authtag_len;

  const char *errmsg;
};

struct verification_verify_context
{
  uint8_t server_eph_public_key[32];
  uint8_t server_public_key[64];

  uint8_t client_public_key[crypto_sign_PUBLICKEYBYTES];
  uint8_t client_private_key[crypto_sign_SECRETKEYBYTES];

  uint8_t client_eph_public_key[32];
  uint8_t client_eph_private_key[32];

  const char *errmsg;
};


/* ---------------------------------- SRP ---------------------------------- */

typedef enum
{
  SRP_NG_2048,
  SRP_NG_CUSTOM
} SRP_NGType;

typedef struct
{
  BIGNUM     * N;
  BIGNUM     * g;
} NGConstant;

typedef union
{
  SHA_CTX    sha;
  SHA256_CTX sha256;
  SHA512_CTX sha512;
} HashCTX;

struct SRPUser
{
  enum hash_alg     alg;
  NGConstant        *ng;
    
  BIGNUM *a;
  BIGNUM *A;
    BIGNUM *S;

  const unsigned char * bytes_A;
  int                   authenticated;
    
  const char *          username;
  const unsigned char * password;
  int                   password_len;
    
  unsigned char M           [SHA512_DIGEST_LENGTH];
  unsigned char H_AMK       [SHA512_DIGEST_LENGTH];
  unsigned char session_key [2 * SHA512_DIGEST_LENGTH]; // See hash_session_key()
  int           session_key_len;
};

struct NGHex 
{
  const char * n_hex;
  const char * g_hex;
};

// We only need 2048 right now, but keep the array in case we want to add others later
// All constants here were pulled from Appendix A of RFC 5054
static struct NGHex global_Ng_constants[] =
{
  { /* 2048 */
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4"
    "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60"
    "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF"
    "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907"
    "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861"
    "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB"
    "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
    "2"
  },
  {0,0} /* null sentinel */
};

static int srp_initialized = 0;


static NGConstant *
new_ng(SRP_NGType ng_type, const char * n_hex, const char * g_hex)
{
  NGConstant * ng   = (NGConstant *) malloc( sizeof(NGConstant) );
  ng->N             = BN_new();
  ng->g             = BN_new();

  if( !ng || !ng->N || !ng->g )
    return 0;

  if ( ng_type != SRP_NG_CUSTOM )
    {
      n_hex = global_Ng_constants[ ng_type ].n_hex;
      g_hex = global_Ng_constants[ ng_type ].g_hex;
    }
        
  BN_hex2bn( &ng->N, n_hex );
  BN_hex2bn( &ng->g, g_hex );
    
  return ng;
}

static void
delete_ng(NGConstant * ng)
{
 if (ng)
   {
     BN_free( ng->N );
     BN_free( ng->g );
     ng->N = 0;
     ng->g = 0;
     free(ng);
   }
}

static int
hash_init(enum hash_alg alg, HashCTX *c)
{
  switch (alg)
    {
      case HASH_SHA1  : return SHA1_Init( &c->sha );
      case HASH_SHA224: return SHA224_Init( &c->sha256 );
      case HASH_SHA256: return SHA256_Init( &c->sha256 );
      case HASH_SHA384: return SHA384_Init( &c->sha512 );
      case HASH_SHA512: return SHA512_Init( &c->sha512 );
      default:
        return -1;
    };
}

static int
hash_update(enum hash_alg alg, HashCTX *c, const void *data, size_t len)
{
  switch (alg)
    {
      case HASH_SHA1  : return SHA1_Update( &c->sha, data, len );
      case HASH_SHA224: return SHA224_Update( &c->sha256, data, len );
      case HASH_SHA256: return SHA256_Update( &c->sha256, data, len );
      case HASH_SHA384: return SHA384_Update( &c->sha512, data, len );
      case HASH_SHA512: return SHA512_Update( &c->sha512, data, len );
      default:
        return -1;
    };
}

static int
hash_final(enum hash_alg alg, HashCTX *c, unsigned char *md)
{
  switch (alg)
    {
      case HASH_SHA1  : return SHA1_Final( md, &c->sha );
      case HASH_SHA224: return SHA224_Final( md, &c->sha256 );
      case HASH_SHA256: return SHA256_Final( md, &c->sha256 );
      case HASH_SHA384: return SHA384_Final( md, &c->sha512 );
      case HASH_SHA512: return SHA512_Final( md, &c->sha512 );
      default:
        return -1;
    };
}

static unsigned char *
hash(enum hash_alg alg, const unsigned char *d, size_t n, unsigned char *md)
{
  switch (alg)
    {
      case HASH_SHA1  : return SHA1( d, n, md );
      case HASH_SHA224: return SHA224( d, n, md );
      case HASH_SHA256: return SHA256( d, n, md );
      case HASH_SHA384: return SHA384( d, n, md );
      case HASH_SHA512: return SHA512( d, n, md );
      default:
        return 0;
    };
}

static int
hash_length(enum hash_alg alg)
{
  switch (alg)
    {
      case HASH_SHA1  : return SHA_DIGEST_LENGTH;
      case HASH_SHA224: return SHA224_DIGEST_LENGTH;
      case HASH_SHA256: return SHA256_DIGEST_LENGTH;
      case HASH_SHA384: return SHA384_DIGEST_LENGTH;
      case HASH_SHA512: return SHA512_DIGEST_LENGTH;
      default:
        return -1;
    };
}

static int
hash_ab(enum hash_alg alg, unsigned char *md, const unsigned char *m1, int m1_len, const unsigned char *m2, int m2_len)
{
  HashCTX         ctx;

  hash_init(alg, &ctx);
  hash_update(alg, &ctx, m1, m1_len);
  hash_update(alg, &ctx, m2, m2_len);
  return hash_final(alg, &ctx, md);
}    

static BIGNUM *
H_nn_pad(enum hash_alg alg, const BIGNUM * n1, const BIGNUM * n2)
{
  unsigned char * bin;
  unsigned char   buff[ SHA512_DIGEST_LENGTH ];
  int             len_n1 = BN_num_bytes(n1);
  int             len_n2 = BN_num_bytes(n2);
  int             nbytes = 2 * len_n1;

  if ((len_n2 < 1) || (len_n2 > len_n1))
    return 0;
  bin = (unsigned char *) calloc( 1, nbytes );
  if (!bin)
    return 0;
  BN_bn2bin(n1, bin);
  BN_bn2bin(n2, bin + nbytes - len_n2);
  hash( alg, bin, nbytes, buff );
  free(bin);
  return BN_bin2bn(buff, hash_length(alg), NULL);
}

static BIGNUM *
H_ns(enum hash_alg alg, const BIGNUM * n, const unsigned char * bytes, int len_bytes)
{
  unsigned char   buff[ SHA512_DIGEST_LENGTH ];
  int             len_n  = BN_num_bytes(n);
  int             nbytes = len_n + len_bytes;
  unsigned char * bin    = (unsigned char *) malloc( nbytes );
  if (!bin)
    return 0;
  BN_bn2bin(n, bin);
  memcpy( bin + len_n, bytes, len_bytes );
  hash( alg, bin, nbytes, buff );
  free(bin);
  return BN_bin2bn(buff, hash_length(alg), NULL);
}

static BIGNUM *
calculate_x(enum hash_alg alg, const BIGNUM * salt, const char * username, const unsigned char * password, int password_len)
{
  unsigned char ucp_hash[SHA512_DIGEST_LENGTH];
  HashCTX       ctx;

  hash_init( alg, &ctx );
  hash_update( alg, &ctx, username, strlen(username) );
  hash_update( alg, &ctx, ":", 1 );
  hash_update( alg, &ctx, password, password_len );
  hash_final( alg, &ctx, ucp_hash );
        
  return H_ns( alg, salt, ucp_hash, hash_length(alg) );
}

static void
update_hash_n(enum hash_alg alg, HashCTX *ctx, const BIGNUM * n)
{
  unsigned long len = BN_num_bytes(n);
  unsigned char * n_bytes = (unsigned char *) malloc( len );
  if (!n_bytes)
     return;
  BN_bn2bin(n, n_bytes);
  hash_update(alg, ctx, n_bytes, len);
  free(n_bytes);
}

static void
hash_num(enum hash_alg alg, const BIGNUM * n, unsigned char * dest)
{
  int             nbytes = BN_num_bytes(n);
  unsigned char * bin    = (unsigned char *) malloc( nbytes );
  if(!bin)
     return;
  BN_bn2bin(n, bin);
  hash( alg, bin, nbytes, dest );
  free(bin);
}

static int
hash_session_key(enum hash_alg alg, const BIGNUM * n, unsigned char * dest)
{
  int             nbytes = BN_num_bytes(n);
  unsigned char * bin    = (unsigned char *) malloc( nbytes );
  unsigned char   fourbytes[4] = { 0 }; // Only God knows the reason for this, and perhaps some poor soul at Apple
  if(!bin)
     return 0;
  BN_bn2bin(n, bin);

  hash_ab(alg, dest, bin, nbytes, fourbytes, sizeof(fourbytes));

  fourbytes[3] = 1; // Again, only ...

  hash_ab(alg, dest + hash_length(alg), bin, nbytes, fourbytes, sizeof(fourbytes));

  free(bin);

  return (2 * hash_length(alg));
}

static void
calculate_M(enum hash_alg alg, NGConstant *ng, unsigned char * dest, const char * I, const BIGNUM * s,
            const BIGNUM * A, const BIGNUM * B, const unsigned char * K, int K_len)
{
  unsigned char H_N[ SHA512_DIGEST_LENGTH ];
  unsigned char H_g[ SHA512_DIGEST_LENGTH ];
  unsigned char H_I[ SHA512_DIGEST_LENGTH ];
  unsigned char H_xor[ SHA512_DIGEST_LENGTH ];
  HashCTX       ctx;
  int           i = 0;
  int           hash_len = hash_length(alg);
        
  hash_num( alg, ng->N, H_N );
  hash_num( alg, ng->g, H_g );
    
  hash(alg, (const unsigned char *)I, strlen(I), H_I);
    
  for (i=0; i < hash_len; i++ )
    H_xor[i] = H_N[i] ^ H_g[i];
    
  hash_init( alg, &ctx );
    
  hash_update( alg, &ctx, H_xor, hash_len );
  hash_update( alg, &ctx, H_I,   hash_len );
  update_hash_n( alg, &ctx, s );
  update_hash_n( alg, &ctx, A );
  update_hash_n( alg, &ctx, B );
  hash_update( alg, &ctx, K, K_len );
    
  hash_final( alg, &ctx, dest );
}

static void
calculate_H_AMK(enum hash_alg alg, unsigned char *dest, const BIGNUM * A, const unsigned char * M, const unsigned char * K, int K_len)
{
  HashCTX ctx;
    
  hash_init( alg, &ctx );
    
  update_hash_n( alg, &ctx, A );
  hash_update( alg, &ctx, M, hash_length(alg) );
  hash_update( alg, &ctx, K, K_len );
    
  hash_final( alg, &ctx, dest );
}

static void
init_random()
{    
  FILE *fp = 0;    
  unsigned char buff[64];

  if (srp_initialized)
    return;
 
  fp = fopen("/dev/urandom", "r");
  if (fp)
    {
      fread(buff, sizeof(buff), 1, fp);
      fclose(fp);
      srp_initialized = 1;
    }

  if (srp_initialized)
    RAND_seed(buff, sizeof(buff));
}

static struct SRPUser *
srp_user_new(enum hash_alg alg, SRP_NGType ng_type, const char * username, 
             const unsigned char * bytes_password, int len_password,
             const char * n_hex, const char * g_hex)
{
  struct SRPUser  *usr  = calloc(1, sizeof(struct SRPUser) );
  int              ulen = strlen(username) + 1;

  if (!usr)
    goto err_exit;

  init_random(); /* Only happens once */
    
  usr->alg      = alg;
  usr->ng       = new_ng( ng_type, n_hex, g_hex );
    
  usr->a = BN_new();
  usr->A = BN_new();
  usr->S = BN_new();

  if (!usr->ng || !usr->a || !usr->A || !usr->S)
    goto err_exit;
    
  usr->username     = (const char *) malloc(ulen);
  usr->password     = (const unsigned char *) malloc(len_password);
  usr->password_len = len_password;

  if (!usr->username || !usr->password)
    goto err_exit;
    
  memcpy((char *)usr->username, username,       ulen);
  memcpy((char *)usr->password, bytes_password, len_password);

  usr->authenticated = 0;
  usr->bytes_A = 0;
    
  return usr;

 err_exit:
  if (!usr)
    return NULL;

  BN_free(usr->a);
  BN_free(usr->A);
  BN_free(usr->S);
  if (usr->username)
    free((void*)usr->username);
  if (usr->password)
    {
      memset((void*)usr->password, 0, usr->password_len);
      free((void*)usr->password);
    }
  free(usr);

  return NULL;
}

static void
srp_user_delete(struct SRPUser * usr)
{
  if(!usr)
    return;

  BN_free(usr->a);
  BN_free(usr->A);
  BN_free(usr->S);
      
  delete_ng(usr->ng);

  memset((void*)usr->password, 0, usr->password_len);
      
  free((char *)usr->username);
  free((char *)usr->password);
      
  if (usr->bytes_A) 
    free( (char *)usr->bytes_A );

  memset(usr, 0, sizeof(*usr));
  free(usr);
}

static int
srp_user_is_authenticated(struct SRPUser * usr)
{
  return usr->authenticated;
}

static const unsigned char *
srp_user_get_session_key(struct SRPUser * usr, int * key_length)
{
  if (key_length)
    *key_length = usr->session_key_len;
  return usr->session_key;
}

/* Output: username, bytes_A, len_A */
static void
srp_user_start_authentication(struct SRPUser * usr, const char ** username,
                              const unsigned char ** bytes_A, int * len_A)
{
  BN_CTX  *ctx  = BN_CTX_new();
  BN_rand(usr->a, 256, -1, 0);
  BN_mod_exp(usr->A, usr->ng->g, usr->a, usr->ng->N, ctx);
  BN_CTX_free(ctx);
    
  *len_A   = BN_num_bytes(usr->A);
  *bytes_A = malloc(*len_A);

  if (!*bytes_A)
    {
      *len_A = 0;
      *bytes_A = 0;
      *username = 0;
      return;
    }
        
  BN_bn2bin(usr->A, (unsigned char *) *bytes_A);
    
  usr->bytes_A = *bytes_A;
  *username = usr->username;
}

/* Output: bytes_M. Buffer length is SHA512_DIGEST_LENGTH */
static void
srp_user_process_challenge(struct SRPUser * usr, const unsigned char * bytes_s, int len_s,
                           const unsigned char * bytes_B, int len_B,
                           const unsigned char ** bytes_M, int * len_M )
{
  BIGNUM *s    = BN_bin2bn(bytes_s, len_s, NULL);
  BIGNUM *B    = BN_bin2bn(bytes_B, len_B, NULL);
  BIGNUM *u    = 0;
  BIGNUM *x    = 0;
  BIGNUM *k    = 0;
  BIGNUM *v    = BN_new();
  BIGNUM *tmp1 = BN_new();
  BIGNUM *tmp2 = BN_new();
  BIGNUM *tmp3 = BN_new();
  BN_CTX *ctx  = BN_CTX_new();

  *len_M = 0;
  *bytes_M = 0;

  if (!s || !B || !v || !tmp1 || !tmp2 || !tmp3 || !ctx)
    goto cleanup_and_exit;
    
  u = H_nn_pad(usr->alg, usr->A, B);
  if (!u)
    goto cleanup_and_exit;
    
  x = calculate_x(usr->alg, s, usr->username, usr->password, usr->password_len);
  if (!x)
    goto cleanup_and_exit;
    
  k = H_nn_pad(usr->alg, usr->ng->N, usr->ng->g);
  if (!k)
    goto cleanup_and_exit;
    
  /* SRP-6a safety check */
  if (!BN_is_zero(B) && !BN_is_zero(u))
    {
      BN_mod_exp(v, usr->ng->g, x, usr->ng->N, ctx);
        
      /* S = (B - k*(g^x)) ^ (a + ux) */
      BN_mul(tmp1, u, x, ctx);
      BN_add(tmp2, usr->a, tmp1);             /* tmp2 = (a + ux)      */
      BN_mod_exp(tmp1, usr->ng->g, x, usr->ng->N, ctx);
      BN_mul(tmp3, k, tmp1, ctx);             /* tmp3 = k*(g^x)       */
      BN_sub(tmp1, B, tmp3);                  /* tmp1 = (B - K*(g^x)) */
      BN_mod_exp(usr->S, tmp1, tmp2, usr->ng->N, ctx);

      usr->session_key_len = hash_session_key(usr->alg, usr->S, usr->session_key);
        
      calculate_M(usr->alg, usr->ng, usr->M, usr->username, s, usr->A, B, usr->session_key, usr->session_key_len);
      calculate_H_AMK(usr->alg, usr->H_AMK, usr->A, usr->M, usr->session_key, usr->session_key_len);
        
      *bytes_M = usr->M;
      if (len_M)
        *len_M = hash_length(usr->alg);
    }
  else
    {
      *bytes_M = NULL;
      if (len_M) 
        *len_M   = 0;
    }

 cleanup_and_exit:
  BN_free(s);
  BN_free(B);
  BN_free(u);
  BN_free(x);
  BN_free(k);
  BN_free(v);
  BN_free(tmp1);
  BN_free(tmp2);
  BN_free(tmp3);
  BN_CTX_free(ctx);
}

static void
srp_user_verify_session(struct SRPUser * usr, const unsigned char * bytes_HAMK)
{
  if (memcmp( usr->H_AMK, bytes_HAMK, hash_length(usr->alg) ) == 0)
    usr->authenticated = 1;
}


/* -------------------------------- HELPERS -------------------------------- */

static int
encrypt_gcm(unsigned char *ciphertext, unsigned char *tag, unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, const char **errmsg)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  if ( !(ctx = EVP_CIPHER_CTX_new()) ||
       (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) ||
       (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL) != 1) ||
       (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) )
    {
      *errmsg = "Error initialising AES 128 GCM encryption";
      goto error;
    }

  if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
    {
      *errmsg = "Error GCM encrypting";
      goto error;
    }

  ciphertext_len = len;

  if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    {
      *errmsg = "Error finalising GCM encryption";
      goto error;
    }

  ciphertext_len += len;

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AUTHTAG_LENGTH, tag) != 1)
    {
      *errmsg = "Error getting authtag";
      goto error;
    }

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;

 error:
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}

static int
encrypt_ctr(unsigned char *ciphertext, unsigned char *plaintext1, int plaintext1_len, unsigned char *plaintext2, int plaintext2_len, unsigned char *key, unsigned char *iv, const char **errmsg)
{
  EVP_CIPHER_CTX *ctx;
  int ciphertext_len;
  int len;

  if ( !(ctx = EVP_CIPHER_CTX_new()) || (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) != 1) )
    {
      *errmsg = "Error initialising AES 128 CTR encryption";
      goto error;
    }

  if ( (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext1, plaintext1_len) != 1) ||
       (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext2, plaintext2_len) != 1) )
    {
      *errmsg = "Error CTR encrypting";
      goto error;
    }

  ciphertext_len = len;

  if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    {
      *errmsg = "Error finalising encryption";
      goto error;
    }

  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;

 error:
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}


/* ---------------------------------- API ---------------------------------- */

struct verification_setup_context *
verification_setup_new(const char *pin)
{
  struct verification_setup_context *sctx;

  if (sodium_init() == -1)
    return NULL;

  sctx = calloc(1, sizeof(struct verification_setup_context));
  if (!sctx)
    return NULL;

  memcpy(sctx->pin, pin, sizeof(sctx->pin));

  return sctx;
}

void
verification_setup_free(struct verification_setup_context *sctx)
{
  if (!sctx)
    return;

  srp_user_delete(sctx->user);

  free(sctx->pkB);
  free(sctx->M2);
  free(sctx->salt);
  free(sctx->epk);
  free(sctx->authtag);

  free(sctx);
}

const char *
verification_setup_errmsg(struct verification_setup_context *sctx)
{
  return sctx->errmsg;
}

uint8_t *
verification_setup_request1(uint32_t *len, struct verification_setup_context *sctx)
{
  plist_t dict;
  plist_t method;
  plist_t user;
  char *data = NULL; // Necessary to initialize because plist_to_bin() uses value

  sctx->user = srp_user_new(HASH_SHA1, SRP_NG_2048, USERNAME, (unsigned char *)sctx->pin, sizeof(sctx->pin), 0, 0);

  dict = plist_new_dict();

  method = plist_new_string("pin");
  user = plist_new_string(USERNAME);

  plist_dict_set_item(dict, "method", method);
  plist_dict_set_item(dict, "user", user);
  plist_to_bin(dict, &data, len);
  plist_free(dict);

  return (uint8_t *)data;
}

uint8_t *
verification_setup_request2(uint32_t *len, struct verification_setup_context *sctx)
{
  plist_t dict;
  plist_t pk;
  plist_t proof;
  const char *auth_username = NULL;
  char *data = NULL;

  // Calculate A
  srp_user_start_authentication(sctx->user, &auth_username, &sctx->pkA, &sctx->pkA_len);

  // Calculate M1 (client proof)
  srp_user_process_challenge(sctx->user, (const unsigned char *)sctx->salt, sctx->salt_len, (const unsigned char *)sctx->pkB, sctx->pkB_len, &sctx->M1, &sctx->M1_len);

  pk = plist_new_data((char *)sctx->pkA, sctx->pkA_len);
  proof = plist_new_data((char *)sctx->M1, sctx->M1_len);

  dict = plist_new_dict();
  plist_dict_set_item(dict, "pk", pk);
  plist_dict_set_item(dict, "proof", proof);
  plist_to_bin(dict, &data, len);
  plist_free(dict);

  return (uint8_t *)data;
}

uint8_t *
verification_setup_request3(uint32_t *len, struct verification_setup_context *sctx)
{
  plist_t dict;
  plist_t epk;
  plist_t authtag;
  char *data = NULL;
  const unsigned char *session_key;
  int session_key_len;
  unsigned char key[SHA512_DIGEST_LENGTH];
  unsigned char iv[SHA512_DIGEST_LENGTH];
  unsigned char encrypted[128]; // Alloc a bit extra - should only need 2*16
  unsigned char tag[16];
  const char *errmsg;
  int ret;

  session_key = srp_user_get_session_key(sctx->user, &session_key_len);
  if (!session_key)
    {
      sctx->errmsg = "Setup request 3: No valid session key";
      return NULL;
    }

  ret = hash_ab(HASH_SHA512, key, (unsigned char *)AES_SETUP_KEY, strlen(AES_SETUP_KEY), session_key, session_key_len);
  if (ret < 0)
    {
      sctx->errmsg = "Setup request 3: Hashing of key string and shared secret failed";
      return NULL;
    }

  ret = hash_ab(HASH_SHA512, iv, (unsigned char *)AES_SETUP_IV, strlen(AES_SETUP_IV), session_key, session_key_len);
  if (ret < 0)
    {
      sctx->errmsg = "Setup request 3: Hashing of iv string and shared secret failed";
      return NULL;
    }

  iv[15]++; // Magic
/*
  if (iv[15] == 0x00 || iv[15] == 0xff)
    printf("- note that value of last byte is %d!\n", iv[15]);
*/
  crypto_sign_keypair(sctx->public_key, sctx->private_key);

  *len = encrypt_gcm(encrypted, tag, sctx->public_key, sizeof(sctx->public_key), key, iv, &errmsg);
  if (*len < 1)
    {
      sctx->errmsg = errmsg;
      return NULL;
    }

  epk = plist_new_data((char *)encrypted, *len);
  authtag = plist_new_data((char *)tag, AUTHTAG_LENGTH);

  dict = plist_new_dict();
  plist_dict_set_item(dict, "epk", epk);
  plist_dict_set_item(dict, "authTag", authtag);
  plist_to_bin(dict, &data, len);
  plist_free(dict);

  return (uint8_t *)data;
}

int
verification_setup_response1(struct verification_setup_context *sctx, const uint8_t *data, uint32_t data_len)
{
  plist_t dict;
  plist_t pk;
  plist_t salt;

  plist_from_bin((const char *)data, data_len, &dict);

  pk = plist_dict_get_item(dict, "pk");
  salt = plist_dict_get_item(dict, "salt");
  if (!pk || !salt)
    {
      sctx->errmsg = "Setup response 1: Missing pk or salt";
      plist_free(dict);
      return -1;
    }

  plist_get_data_val(pk, (char **)&sctx->pkB, &sctx->pkB_len); // B
  plist_get_data_val(salt, (char **)&sctx->salt, &sctx->salt_len);

  plist_free(dict);

  return 0;
}

int
verification_setup_response2(struct verification_setup_context *sctx, const uint8_t *data, uint32_t data_len)
{
  plist_t dict;
  plist_t proof;

  plist_from_bin((const char *)data, data_len, &dict);

  proof = plist_dict_get_item(dict, "proof");
  if (!proof)
    {
      sctx->errmsg = "Setup response 2: Missing proof";
      plist_free(dict);
      return -1;
    }

  plist_get_data_val(proof, (char **)&sctx->M2, &sctx->M2_len); // M2

  plist_free(dict);

  // Check M2
  srp_user_verify_session(sctx->user, (const unsigned char *)sctx->M2);
  if (!srp_user_is_authenticated(sctx->user))
    {
      sctx->errmsg = "Setup response 2: Server authentication failed";
      return -1;
    }

  return 0;
}

int
verification_setup_response3(struct verification_setup_context *sctx, const uint8_t *data, uint32_t data_len)
{
  plist_t dict;
  plist_t epk;
  plist_t authtag;

  plist_from_bin((const char *)data, data_len, &dict);

  epk = plist_dict_get_item(dict, "epk");
  if (!epk)
    {
      sctx->errmsg = "Setup response 3: Missing epk";
      plist_free(dict);
      return -1;
    }

  plist_get_data_val(epk, (char **)&sctx->epk, &sctx->epk_len);

  authtag = plist_dict_get_item(dict, "authTag");
  if (!authtag)
    {
      sctx->errmsg = "Setup response 3: Missing authTag";
      plist_free(dict);
      return -1;
    }

  plist_get_data_val(authtag, (char **)&sctx->authtag, &sctx->authtag_len);

  plist_free(dict);

  return 0;
}

int
verification_setup_result(const char **authorisation_key, struct verification_setup_context *sctx)
{
  struct verification_verify_context *vctx;
  char *ptr;
  int i;

  if (sizeof(vctx->client_public_key) != sizeof(sctx->public_key) || sizeof(vctx->client_private_key) != sizeof(sctx->private_key))
    {
      sctx->errmsg = "Setup result: Bug!";
      return -1;
    }

  // Fills out the auth_key with public + private in hex. It seems that the private
  // key actually includes the public key (last 32 bytes), so we could in
  // principle just export the private key
  ptr = sctx->auth_key;
  for (i = 0; i < sizeof(sctx->public_key); i++)
    ptr += sprintf(ptr, "%02x", sctx->public_key[i]);
  for (i = 0; i < sizeof(sctx->private_key); i++)
    ptr += sprintf(ptr, "%02x", sctx->private_key[i]);
  *ptr = '\0';

  *authorisation_key = sctx->auth_key;
  return 0;
}


struct verification_verify_context *
verification_verify_new(const char *authorisation_key)
{
  struct verification_verify_context *vctx;
  char hex[] = { 0, 0, 0 };
  const char *ptr;
  int i;

  if (sodium_init() == -1)
    return NULL;

  vctx = calloc(1, sizeof(struct verification_verify_context));
  if (!vctx)
    return NULL;

  if (strlen(authorisation_key) != 2 * (sizeof(vctx->client_public_key) + sizeof(vctx->client_private_key)))
    return NULL;

  ptr = authorisation_key;
  for (i = 0; i < sizeof(vctx->client_public_key); i++, ptr+=2)
    {
      hex[0] = ptr[0];
      hex[1] = ptr[1];
      vctx->client_public_key[i] = strtol(hex, NULL, 16);
    }
  for (i = 0; i < sizeof(vctx->client_private_key); i++, ptr+=2)
    {
      hex[0] = ptr[0];
      hex[1] = ptr[1];
      vctx->client_private_key[i] = strtol(hex, NULL, 16);
    }

  return vctx;
}

void
verification_verify_free(struct verification_verify_context *vctx)
{
  if (!vctx)
    return;

  free(vctx);
}

const char *
verification_verify_errmsg(struct verification_verify_context *vctx)
{
  return vctx->errmsg;
}

uint8_t *
verification_verify_request1(uint32_t *len, struct verification_verify_context *vctx)
{
  const uint8_t basepoint[32] = {9};
  uint8_t *data;
  int ret;

  ret = crypto_scalarmult(vctx->client_eph_public_key, vctx->client_eph_private_key, basepoint);
  if (ret < 0)
    {
      vctx->errmsg = "Verify request 1: Curve 25519 returned an error";
      return NULL;
    }

  *len = 4 + sizeof(vctx->client_eph_public_key) + sizeof(vctx->client_public_key);
  data = calloc(1, *len);
  if (!data)
    {
      vctx->errmsg = "Verify request 1: Out of memory";
      return NULL;
    }

  data[0] = 1; // Magic
  memcpy(data + 4, vctx->client_eph_public_key, sizeof(vctx->client_eph_public_key));
  memcpy(data + 4 + sizeof(vctx->client_eph_public_key), vctx->client_public_key, sizeof(vctx->client_public_key));

  return data;
}

uint8_t *
verification_verify_request2(uint32_t *len, struct verification_verify_context *vctx)
{
  uint8_t shared_secret[crypto_scalarmult_BYTES];
  uint8_t key[SHA512_DIGEST_LENGTH];
  uint8_t iv[SHA512_DIGEST_LENGTH];
  uint8_t encrypted[128]; // Alloc a bit extra
  uint8_t signature[crypto_sign_BYTES];
  uint8_t *data;
  int ret;
  const char *errmsg;

  *len = sizeof(vctx->client_eph_public_key) + sizeof(vctx->server_eph_public_key);
  data = malloc(*len);
  if (!data)
    {
      vctx->errmsg = "Verify request 2: Out of memory";
      return NULL;
    }

  memcpy(data, vctx->client_eph_public_key, sizeof(vctx->client_eph_public_key));
  memcpy(data + sizeof(vctx->client_eph_public_key), vctx->server_eph_public_key, sizeof(vctx->server_eph_public_key));

  crypto_sign_detached(signature, NULL, data, *len, vctx->client_private_key);

  free(data);

  ret = crypto_scalarmult(shared_secret, vctx->client_eph_private_key, vctx->server_eph_public_key);
  if (ret < 0)
    {
      vctx->errmsg = "Verify request 2: Curve 25519 returned an error";
      return NULL;
    }

  ret = hash_ab(HASH_SHA512, key, (unsigned char *)AES_VERIFY_KEY, strlen(AES_VERIFY_KEY), shared_secret, sizeof(shared_secret));
  if (ret < 0)
    {
      vctx->errmsg = "Verify request 2: Hashing of key string and shared secret failed";
      return NULL;
    }

  ret = hash_ab(HASH_SHA512, iv, (unsigned char *)AES_VERIFY_IV, strlen(AES_VERIFY_IV), shared_secret, sizeof(shared_secret));
  if (ret < 0)
    {
      vctx->errmsg = "Verify request 2: Hashing of iv string and shared secret failed";
      return NULL;
    }

  *len = encrypt_ctr(encrypted, vctx->server_public_key, sizeof(vctx->server_public_key), signature, sizeof(signature), key, iv, &errmsg);
  if (*len < 1)
    {
      vctx->errmsg = errmsg;
      return NULL;
    }

  data = calloc(1, 4 + *len);
  if (!data)
    {
      vctx->errmsg = "Verify request 2: Out of memory";
      return NULL;
    }

  memcpy(data + 4, encrypted, *len);
  *len += 4;

  return data;
}

int
verification_verify_response1(struct verification_verify_context *vctx, const uint8_t *data, uint32_t data_len)
{
  uint32_t wanted;

  wanted = sizeof(vctx->server_eph_public_key) + sizeof(vctx->server_public_key);
  if (data_len < wanted)
    {
      vctx->errmsg = "Verify response 2: Unexpected response (too short)";
      return -1;
    }

  memcpy(vctx->server_eph_public_key, data, sizeof(vctx->server_eph_public_key));
  memcpy(vctx->server_public_key, data + sizeof(vctx->server_eph_public_key), sizeof(vctx->server_public_key));

  return 0;
}
