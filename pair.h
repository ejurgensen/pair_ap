#ifndef __PAIR_AP_H__
#define __PAIR_AP_H__

#include <stdint.h>

enum pair_type
{
  // This is the pairing type required for Apple TV device verification, which
  // became mandatory with tvOS 10.2.
  PAIR_FRUIT,
  // This is the Homekit type required for AirPlay 2.
  PAIR_HOMEKIT,
};

struct pair_setup_context;
struct pair_verify_context;
struct pair_cipher_context;

/* When you have the pin-code (must be 4 bytes), create a new context with this
 * function and then call pair_setup_request1(). device_id is only
 * required for homekit pairing, where it should have length 16.
 */
struct pair_setup_context *
pair_setup_new(enum pair_type type, const char *pin, const char *device_id);
void
pair_setup_free(struct pair_setup_context *sctx);

/* Returns last error message
 */
const char *
pair_setup_errmsg(struct pair_setup_context *sctx);

uint8_t *
pair_setup_request1(uint32_t *len, struct pair_setup_context *sctx);
uint8_t *
pair_setup_request2(uint32_t *len, struct pair_setup_context *sctx);
uint8_t *
pair_setup_request3(uint32_t *len, struct pair_setup_context *sctx);

int
pair_setup_response1(struct pair_setup_context *sctx, const uint8_t *data, uint32_t data_len);
int
pair_setup_response2(struct pair_setup_context *sctx, const uint8_t *data, uint32_t data_len);
int
pair_setup_response3(struct pair_setup_context *sctx, const uint8_t *data, uint32_t data_len);

/* Returns a 0-terminated string that is the authorisation key. The caller
 * should save it and use it later to initialize pair_verify_new().
 * Note that the pointer becomes invalid when you free sctx.
 */
int
pair_setup_result(const char **authorisation_key, struct pair_setup_context *sctx);


/* When you have completed the setup you can extract a key with
 * pair_setup_result(). Give the string as input to this function to
 * create a verification context and then call pair_verify_request1()
 * device_id is only required for homekit pairing, where it should have len 16.
 */
struct pair_verify_context *
pair_verify_new(enum pair_type type, const char *authorisation_key, const char *device_id);
void
pair_verify_free(struct pair_verify_context *vctx);

/* Returns last error message
 */
const char *
pair_verify_errmsg(struct pair_verify_context *vctx);

uint8_t *
pair_verify_request1(uint32_t *len, struct pair_verify_context *vctx);
uint8_t *
pair_verify_request2(uint32_t *len, struct pair_verify_context *vctx);

int
pair_verify_response1(struct pair_verify_context *vctx, const uint8_t *data, uint32_t data_len);

/* Returns a pointer to the shared secret that is 32 bytes. The caller
 * should save it and use it later to initialize pair_cipher_new().
 * Note that the pointer becomes invalid when you free vctx.
 */
int
pair_verify_result(const uint8_t **shared_secret, struct pair_verify_context *vctx);

/* When you have completed the verification you can extract a key with
 * pair_verify_result(). Give the string as input to this function to
 * create a ciphering context.
 */
struct pair_cipher_context *
pair_cipher_new(enum pair_type type, const uint8_t shared_secret[32]);
void
pair_cipher_free(struct pair_cipher_context *cctx);

/* Returns last error message
 */
const char *
pair_cipher_errmsg(struct pair_cipher_context *cctx);

int
pair_encrypt(uint8_t **ciphertext, size_t *ciphertext_len, uint8_t *plaintext, size_t plaintext_len, struct pair_cipher_context *cctx);
int
pair_decrypt(uint8_t **plaintext, size_t *plaintext_len, uint8_t *ciphertext, size_t ciphertext_len, struct pair_cipher_context *cctx);

#endif  /* !__PAIR_AP_H__ */
