#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <plist/plist.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sodium.h>

#include "verification.h"

#include "csrp/srp.h"

#define USERNAME "12:34:56:78:90:AB"
#define AUTHTAG_LENGTH 16
#define AES_SETUP_KEY  "Pair-Setup-AES-Key"
#define AES_SETUP_IV   "Pair-Setup-AES-IV"
#define AES_VERIFY_KEY "Pair-Verify-AES-Key"
#define AES_VERIFY_IV  "Pair-Verify-AES-IV"

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

  uint8_t public_key[32];
  uint8_t private_key[64];

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

  uint8_t client_public_key[32];
  uint8_t client_private_key[64];

  uint8_t client_eph_public_key[32];
  uint8_t client_eph_private_key[32];

  const char *errmsg;
};


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

  sctx->user = srp_user_new(SRP_SHA1, SRP_NG_2048, USERNAME, (unsigned char *)sctx->pin, sizeof(sctx->pin), 0, 0);

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
  printf("- made pkA with length %d\n", (int)sctx->pkA_len);

  proof = plist_new_data((char *)sctx->M1, sctx->M1_len);
  printf("- made M1 with length %d\n", (int)sctx->M1_len);

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
  SHA512_CTX sha512;
  unsigned char key[SHA512_DIGEST_LENGTH];
  unsigned char iv[SHA512_DIGEST_LENGTH];
  unsigned char encrypted[128]; // Alloc a bit extra - should only need 2*16
  unsigned char tag[16];
  const char *errmsg;

  session_key = srp_user_get_session_key(sctx->user, &session_key_len);
  if (!session_key)
    {
      sctx->errmsg = "Setup request 3: No valid session key";
      return NULL;
    }

  SHA512_Init(&sha512);
  SHA512_Update(&sha512, (unsigned char *)AES_SETUP_KEY, strlen(AES_SETUP_KEY));
  SHA512_Update(&sha512, session_key, session_key_len);
  SHA512_Final(key, &sha512);

  SHA512_Init(&sha512);
  SHA512_Update(&sha512, (unsigned char *)AES_SETUP_IV, strlen(AES_SETUP_IV));
  SHA512_Update(&sha512, session_key, session_key_len);
  SHA512_Final(iv, &sha512);

  iv[15]++; // Magic
  if (iv[15] == 0x00 || iv[15] == 0xff)
    printf("- note that value of last byte is %d!\n", iv[15]);

  crypto_sign_keypair(sctx->public_key, sctx->private_key);

  *len = encrypt_gcm(encrypted, tag, sctx->public_key, sizeof(sctx->public_key), key, iv, &errmsg);
  if (*len < 1)
    {
      sctx->errmsg = errmsg;
      return NULL;
    }

  epk = plist_new_data((char *)encrypted, *len);
  printf("- made epk with length %d\n", *len);

  authtag = plist_new_data((char *)tag, AUTHTAG_LENGTH);
  printf("- made authtag with length %d\n", AUTHTAG_LENGTH);

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
  printf("- got pkB with length %d\n", (int)sctx->pkB_len);

  plist_get_data_val(salt, (char **)&sctx->salt, &sctx->salt_len);
  printf("- got salt with length %d\n", (int)sctx->salt_len);

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
  printf("- got proof with length %d\n", (int)sctx->M2_len);

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
  printf("- got epk with length %d\n", (int)sctx->epk_len);

  authtag = plist_dict_get_item(dict, "authTag");
  if (!authtag)
    {
      sctx->errmsg = "Setup response 3: Missing authTag";
      plist_free(dict);
      return -1;
    }

  plist_get_data_val(authtag, (char **)&sctx->authtag, &sctx->authtag_len);
  printf("- got authtag with length %d\n", (int)sctx->authtag_len);

  plist_free(dict);

  return 0;
}

uint8_t *
verification_setup_result(uint32_t *len, struct verification_setup_context *sctx)
{
  struct verification_verify_context *vctx;
  uint8_t *authorisation_key;

  if (sizeof(vctx->client_public_key) != sizeof(sctx->public_key) || sizeof(vctx->client_private_key) != sizeof(sctx->private_key))
    {
      sctx->errmsg = "Setup result: Bug!";
      return NULL;
    }

  *len = sizeof(sctx->public_key) + sizeof(sctx->private_key);
  authorisation_key = malloc(*len);
  if (!authorisation_key)
    {
      sctx->errmsg = "Setup result: Out of memory";
      return NULL;
    }

  memcpy(authorisation_key, sctx->public_key, sizeof(sctx->public_key));
  memcpy(authorisation_key + sizeof(sctx->public_key), sctx->private_key, sizeof(sctx->private_key));

  return authorisation_key;
}


struct verification_verify_context *
verification_verify_new(const uint8_t *authorisation_key)
{
  struct verification_verify_context *vctx;

  if (sodium_init() == -1)
    return NULL;

  vctx = calloc(1, sizeof(struct verification_verify_context));
  if (!vctx)
    return NULL;

  memcpy(vctx->client_public_key, authorisation_key, sizeof(vctx->client_public_key));
  memcpy(vctx->client_private_key, authorisation_key + sizeof(vctx->client_public_key), sizeof(vctx->client_private_key));

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
  SHA512_CTX sha512;
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

  SHA512_Init(&sha512);
  SHA512_Update(&sha512, (unsigned char *)AES_VERIFY_KEY, strlen(AES_VERIFY_KEY));
  SHA512_Update(&sha512, shared_secret, sizeof(shared_secret));
  SHA512_Final(key, &sha512);

  SHA512_Init(&sha512);
  SHA512_Update(&sha512, (unsigned char *)AES_VERIFY_IV, strlen(AES_VERIFY_IV));
  SHA512_Update(&sha512, shared_secret, sizeof(shared_secret));
  SHA512_Final(iv, &sha512);

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

  printf("- got eph_public_key with length %d\n", (int)sizeof(vctx->server_eph_public_key));
  printf("- got public_key with length %d\n", (int)sizeof(vctx->server_public_key));

  return 0;
}
