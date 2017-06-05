#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <plist/plist.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "evrtsp/evrtsp.h"
#include "csrp/srp.h"
#include "ed25519/ed25519.h"
#include "curve25519/curve25519-donna.c" //TODO

#define ADDRESS "192.168.1.213"
#define PORT 7000
#define ACTIVE_REMOTE "3515324763"
#define DACP_ID "FF1DB45949E6CBD3"
#define USER_AGENT "testagent/1.0"
#define USERNAME "12:34:56:78:90:AB"
#define AUTHTAG_LENGTH 16


typedef void (*request_cb)(struct evrtsp_request *, void *);

struct setup_ctx
{
  struct SRPUser *user;

  char *pin;
  size_t pin_len;

  const unsigned char *pkA; //Use uint8_t instead
  int pkA_len;

  char *pkB;
  uint64_t pkB_len;

  const unsigned char *M1;
  int M1_len;

  char *M2;
  uint64_t M2_len;

  char *salt;
  uint64_t salt_len;

  unsigned char public_key[32];
  unsigned char private_key[64];

  char *epk;
  uint64_t epk_len;
  char *authtag;
  uint64_t authtag_len;

} sctx;

struct verify_ctx
{
  unsigned char server_eph_public_key[32];
  unsigned char server_public_key[64];

  unsigned char client_eph_public_key[32];
  unsigned char client_eph_private_key[32];
} vctx;

static struct event_base *evbase;
static struct evrtsp_connection *evcon;
static int cseq;

static char *aes_setup_key_str = "Pair-Setup-AES-Key";
static char *aes_setup_iv_str = "Pair-Setup-AES-IV";
static char *aes_verify_key_str = "Pair-Verify-AES-Key";
static char *aes_verify_iv_str = "Pair-Verify-AES-IV";

static int
response_ok(struct evrtsp_request *req)
{
  if (req->response_code != 200)
    {
      printf("failed with error code %d: %s\n", req->response_code, req->response_code_line);
      event_base_loopbreak(evbase);
      return -1;
    }

  printf("success\n");
  return 0;
}

static int
make_request(const char *url, const void *data, size_t len, const char *content_type, request_cb cb)
{
  struct evrtsp_request *req;
  char buffer[1024];

  req = evrtsp_request_new(cb, NULL);

  if (data)
    evbuffer_add(req->output_buffer, data, len);

  if (content_type)
    evrtsp_add_header(req->output_headers, "Content-Type", content_type);

  cseq++;
  snprintf(buffer, sizeof(buffer), "%d", cseq);
  evrtsp_add_header(req->output_headers, "CSeq", buffer);

  evrtsp_add_header(req->output_headers, "User-Agent", USER_AGENT);
  evrtsp_add_header(req->output_headers, "DACP-ID", DACP_ID);
  evrtsp_add_header(req->output_headers, "Active-Remote", ACTIVE_REMOTE);

  printf("Making request %d to '%s'... ", cseq, url);

  return evrtsp_make_request(evcon, req, EVRTSP_REQ_POST, url);
}


static int
encrypt_gcm(unsigned char *ciphertext, unsigned char *tag, unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  if ( !(ctx = EVP_CIPHER_CTX_new()) ||
       (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) ||
       (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL) != 1) ||
       (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) )
    {
      printf("Error initialising AES 128 GCM encryption\n");
      goto error;
    }

  if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
    {
      printf("Error encrypting\n");
      return -1;
    }

  ciphertext_len = len;

  if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    {
      printf("Error finalising encryption\n");
      return -1;
    }

  ciphertext_len += len;

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AUTHTAG_LENGTH, tag) != 1)
    {
      printf("Error getting authtag\n");
      EVP_CIPHER_CTX_free(ctx);
      return -1;
    }

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;

 error:
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}

static int
encrypt_ctr(unsigned char *ciphertext, unsigned char *plaintext1, int plaintext1_len, unsigned char *plaintext2, int plaintext2_len, unsigned char *key, unsigned char *iv)
{
  EVP_CIPHER_CTX *ctx;
  int ciphertext_len;
  int len;

  if ( !(ctx = EVP_CIPHER_CTX_new()) || (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) != 1) )
    {
      printf("Error initialising AES 128 CTR encryption\n");
      goto error;
    }

  if ( (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext1, plaintext1_len) != 1) ||
       (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext2, plaintext2_len) != 1) )
    {
      printf("Error encrypting\n");
      goto error;
    }

  ciphertext_len = len;

  if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    {
      printf("Error finalising encryption\n");
      goto error;
    }

  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;

 error:
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}

static void
eph_keygen(void)
{
  const uint8_t basepoint[32] = {9};

//  arc4random_buf(vctx.client_eph_private_key, sizeof(vctx.client_eph_private_key));
  curve25519_donna(vctx.client_eph_public_key, vctx.client_eph_private_key, basepoint);
}

static void
verify_step2_response(struct evrtsp_request *req, void *arg)
{
  if (response_ok(req) < 0)
    return;

  printf("Verification complete\n");

  event_base_loopbreak(evbase);
}

static int
verify_step2_request(void)
{
  SHA512_CTX sha512;
  unsigned char shared_secret[32];
  unsigned char key[SHA512_DIGEST_LENGTH];
  unsigned char iv[SHA512_DIGEST_LENGTH];
  unsigned char encrypted[128]; // Alloc a bit extra
  unsigned char signature[64];
  unsigned char *data;
  uint32_t len;
  int ret;

  len = sizeof(vctx.client_eph_public_key) + sizeof(vctx.server_eph_public_key);
  data = malloc(len);

  memcpy(data, vctx.client_eph_public_key, sizeof(vctx.client_eph_public_key));
  memcpy(data + sizeof(vctx.client_eph_public_key), vctx.server_eph_public_key, sizeof(vctx.server_eph_public_key));

  ed25519_sign(signature, data, len, sctx.public_key, sctx.private_key);

  free(data);

  curve25519_donna(shared_secret, vctx.client_eph_private_key, vctx.server_eph_public_key);

  SHA512_Init(&sha512);
  SHA512_Update(&sha512, (unsigned char *)aes_verify_key_str, strlen(aes_verify_key_str));
  SHA512_Update(&sha512, shared_secret, sizeof(shared_secret));
  SHA512_Final(key, &sha512);

  SHA512_Init(&sha512);
  SHA512_Update(&sha512, (unsigned char *)aes_verify_iv_str, strlen(aes_verify_iv_str));
  SHA512_Update(&sha512, shared_secret, sizeof(shared_secret));
  SHA512_Final(iv, &sha512);

  len = encrypt_ctr(encrypted, vctx.server_public_key, sizeof(vctx.server_public_key), signature, sizeof(signature), key, iv);
  if (len < 1)
    {
      event_base_loopbreak(evbase);
      return -1;
    }

  data = calloc(1, 4 + len);
  memcpy(data + 4, encrypted, len);
  len += 4;

  ret = make_request("/pair-verify", data, len, "application/octet-stream", verify_step2_response);

  free(data);

  return ret;
}

static void
verify_step1_response(struct evrtsp_request *req, void *arg)
{
  int wanted;

  if (response_ok(req) < 0)
    return;

  wanted = sizeof(vctx.server_eph_public_key) + sizeof(vctx.server_public_key);
  if (evbuffer_get_length(req->input_buffer) < wanted)
    {
      printf("Unexpected response\n");
      event_base_loopbreak(evbase);
      return;
    }

  evbuffer_remove(req->input_buffer, vctx.server_eph_public_key, sizeof(vctx.server_eph_public_key));
  evbuffer_remove(req->input_buffer, vctx.server_public_key, sizeof(vctx.server_public_key));

  verify_step2_request();
}

static int
verify_step1_request(void)
{
  unsigned char *data;
  int len;
  int ret;

  eph_keygen();

  len = 4 + sizeof(vctx.client_eph_public_key) + sizeof(sctx.public_key);
  data = calloc(1, len);

  data[0] = 1; // Magic
  memcpy(data + 4, vctx.client_eph_public_key, sizeof(vctx.client_eph_public_key));
  memcpy(data + 4 + sizeof(vctx.client_eph_public_key), sctx.public_key, sizeof(sctx.public_key));

  ret = make_request("/pair-verify", data, len, "application/octet-stream", verify_step1_response);

  free(data);

  return ret;
}

static void
setup_step3_response(struct evrtsp_request *req, void *arg)
{
  plist_t dict;
  plist_t epk;
  plist_t authtag;
  char *data;
  uint64_t len;

  if (response_ok(req) < 0)
    return;

  data = (char *)evbuffer_pullup(req->input_buffer, -1);
  len = evbuffer_get_length(req->input_buffer);

  plist_from_bin(data, len, &dict);

  epk = plist_dict_get_item(dict, "epk");
  if (!epk)
    {
      printf("No epk from server\n");
      goto error;
    }

  plist_get_data_val(epk, &sctx.epk, &sctx.epk_len);
  printf("- got epk with length %d\n", (int)sctx.epk_len);

  authtag = plist_dict_get_item(dict, "authTag");
  if (!authtag)
    {
      printf("No authtag from server\n");
      goto error;
    }

  plist_get_data_val(authtag, &sctx.authtag, &sctx.authtag_len);
  printf("- got authtag with length %d\n", (int)sctx.authtag_len);

  printf("Setup complete\n");

  plist_free(dict);

  verify_step1_request();
  return;

 error:
  plist_free(dict);
  event_base_loopbreak(evbase);
}

static int
setup_step3_request(void)
{
  const unsigned char *session_key;
  int session_key_len;
  SHA512_CTX sha512;
  unsigned char key[SHA512_DIGEST_LENGTH];
  unsigned char iv[SHA512_DIGEST_LENGTH];
  unsigned char encrypted[128]; // Alloc a bit extra - should only need 2*16
  unsigned char tag[16];
  plist_t dict;
  plist_t epk;
  plist_t authtag;
  char *data;
  uint32_t len;
  int ret;

  session_key = srp_user_get_session_key(sctx.user, &session_key_len);

  SHA512_Init(&sha512);
  SHA512_Update(&sha512, (unsigned char *)aes_setup_key_str, strlen(aes_setup_key_str));
  SHA512_Update(&sha512, session_key, session_key_len);
  SHA512_Final(key, &sha512);

  SHA512_Init(&sha512);
  SHA512_Update(&sha512, (unsigned char *)aes_setup_iv_str, strlen(aes_setup_iv_str));
  SHA512_Update(&sha512, session_key, session_key_len);
  SHA512_Final(iv, &sha512);

  iv[15]++; // Magic
  if (iv[15] == 0x00 || iv[15] == 0xff)
    printf("- note that value of last byte is %d!\n", iv[15]);

  ed25519_create_keypair(sctx.public_key, sctx.private_key, 0);

  len = encrypt_gcm(encrypted, tag, sctx.public_key, sizeof(sctx.public_key), key, iv);
  if (len < 1)
    return -1;

  epk = plist_new_data((char *)encrypted, len);
  printf("- made epk with length %d\n", len);

  authtag = plist_new_data((char *)tag, AUTHTAG_LENGTH);
  printf("- made authtag with length %d\n", AUTHTAG_LENGTH);

  dict = plist_new_dict();
  plist_dict_set_item(dict, "epk", epk);
  plist_dict_set_item(dict, "authTag", authtag);

  data = NULL;
  plist_to_bin(dict, &data, &len);

  ret = make_request("/pair-setup-pin", data, len, "application/x-apple-binary-plist", setup_step3_response);

  plist_free(dict);
  free(data);

  return ret;
}

static void
setup_step2_response(struct evrtsp_request *req, void *arg)
{
  plist_t dict;
  plist_t proof;
  char *data;
  uint64_t len;

  if (response_ok(req) < 0)
    return;

  data = (char *)evbuffer_pullup(req->input_buffer, -1);
  len = evbuffer_get_length(req->input_buffer);

  plist_from_bin(data, len, &dict);

  proof = plist_dict_get_item(dict, "proof");
  if (!proof)
    {
      printf("No proof from server\n");
      goto error;
    }

  plist_get_data_val(proof, &sctx.M2, &sctx.M2_len); // M2
  printf("- got proof with length %d\n", (int)sctx.M2_len);

  // Check M2
  srp_user_verify_session(sctx.user, (const unsigned char *)sctx.M2);
  if (!srp_user_is_authenticated(sctx.user))
    {
      printf("Server authentication failed\n");
      goto error;
    }

  printf("Setup SRP stage complete\n");

  plist_free(dict);

  setup_step3_request();
  return;

 error:
  plist_free(dict);
  event_base_loopbreak(evbase);
}

static int
setup_step2_request(void)
{
  const char *auth_username = 0;

  plist_t dict;
  plist_t pk;
  plist_t proof;
  char *data;
  uint32_t len;
  int ret;

  // Calculate A
  srp_user_start_authentication(sctx.user, &auth_username, &sctx.pkA, &sctx.pkA_len);

  // Calculate M1 (client proof)
  srp_user_process_challenge(sctx.user, (const unsigned char *)sctx.salt, sctx.salt_len, (const unsigned char *)sctx.pkB, sctx.pkB_len, &sctx.M1, &sctx.M1_len);

  pk = plist_new_data((char *)sctx.pkA, sctx.pkA_len);
  printf("- made pkA with length %d\n", (int)sctx.pkA_len);

  proof = plist_new_data((char *)sctx.M1, sctx.M1_len);
  printf("- made M1 with length %d\n", (int)sctx.M1_len);

  dict = plist_new_dict();
  plist_dict_set_item(dict, "pk", pk);
  plist_dict_set_item(dict, "proof", proof);

  data = NULL; // Not sure why required, Valgrind says plist_to_bin() will use value of the pointer?!?
  plist_to_bin(dict, &data, &len);

  ret = make_request("/pair-setup-pin", data, len, "application/x-apple-binary-plist", setup_step2_response);

  plist_free(dict);
  free(data);

  return ret;
}

static void
setup_step1_response(struct evrtsp_request *req, void *arg)
{
  plist_t dict;
  plist_t pk;
  plist_t salt;
  char *data;
  uint64_t len;

  if (response_ok(req) < 0)
    return;

  data = (char *)evbuffer_pullup(req->input_buffer, -1);
  len = evbuffer_get_length(req->input_buffer);

  plist_from_bin(data, len, &dict);

  pk = plist_dict_get_item(dict, "pk");
  salt = plist_dict_get_item(dict, "salt");
  if (!pk || !salt)
    {
      printf("No pk or salt\n");
      plist_free(dict);
      event_base_loopbreak(evbase);
      return;
    }

  plist_get_data_val(pk, &sctx.pkB, &sctx.pkB_len); // B
  printf("- got pkB with length %d\n", (int)sctx.pkB_len);

  plist_get_data_val(salt, &sctx.salt, &sctx.salt_len);
  printf("- got salt with length %d\n", (int)sctx.salt_len);

  plist_free(dict);

  setup_step2_request();
}

static int
setup_step1_request(void)
{
  plist_t dict;
  plist_t method;
  plist_t user;
  char *data;
  uint32_t len;
  int ret;

  sctx.user = srp_user_new(SRP_SHA1, SRP_NG_2048, USERNAME, (const unsigned char *)sctx.pin, 4, 0, 0);

  dict = plist_new_dict();

  method = plist_new_string("pin");
  user = plist_new_string(USERNAME);

  plist_dict_set_item(dict, "method", method);
  plist_dict_set_item(dict, "user", user);

  data = NULL; // Not sure why required, but Valgrind says plist_to_bin() will use value of the pointer?!?
  plist_to_bin(dict, &data, &len);

  ret = make_request("/pair-setup-pin", data, len, "application/x-apple-binary-plist", setup_step1_response);

  plist_free(dict);
  free(data);

  return ret;
}

static void
setup_start_response(struct evrtsp_request *req, void *arg)
{
  size_t len;

  if (response_ok(req) < 0)
    return;

  printf ("Enter pin: ");
  fflush (stdout);

  len = getline(&sctx.pin, &sctx.pin_len, stdin);
  if (len != 5) // Includes EOL
    {
      printf ("Bad pin length %zu %zu\n", len, strlen(sctx.pin));
      event_base_loopbreak(evbase);
      return;
    }

  setup_step1_request();
}

static int
setup_start_request(void)
{
  return make_request("/pair-pin-start", NULL, 0, "application/x-apple-binary-plist", setup_start_response);
}


int
main( int argc, char * argv[] )
{
  int ret;

  evbase = event_base_new();
  evcon = evrtsp_connection_new(ADDRESS, PORT);
  evrtsp_connection_set_base(evcon, evbase);

  ret = setup_start_request();
  if (ret < 0)
    goto the_end;

  event_base_dispatch(evbase);

 the_end:
  evrtsp_connection_free(evcon);
  event_base_free(evbase);

  return 0;
}
