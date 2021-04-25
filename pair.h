#ifndef __PAIR_AP_H__
#define __PAIR_AP_H__

#include <stdint.h>

#define PAIR_AP_VERSION_MAJOR 0
#define PAIR_AP_VERSION_MINOR 2

#define PAIR_AP_DEVICE_ID_LEN_MAX 64

enum pair_type
{
  // This is the pairing type required for Apple TV device verification, which
  // became mandatory with tvOS 10.2.
  PAIR_CLIENT_FRUIT,
  // This is the Homekit type required for AirPlay 2 with both PIN setup and
  // verification
  PAIR_CLIENT_HOMEKIT_NORMAL,
  // Same as normal except PIN is fixed to 3939 and stops after setup step 2,
  // when session key is established
  PAIR_CLIENT_HOMEKIT_TRANSIENT,
  // Server side implementation supporting both transient and normal mode,
  // letting client choose mode. However, if a PIN is with pair_setup_new()
  // then only normal mode will be possible.
  PAIR_SERVER_HOMEKIT,
};

/* Stores the various forms of pairing results. The shared secret is used to
 * initialise an encrypted session via pair_cipher_new(). For non-transient
 * client pair setup, you should convert the result to a hex string with
 * pair_result_to_hex(), store it, and then initialise pair_verify_new() with it.
 * For non-transient server pair setup, store the client's id and public key
 * (e.g. in a database), and during pair-verify pass it back when requested by
 * the callback. Table showing returned data (everything else will be zeroed):
 *
 *                                  | pair-setup                    | pair-verify
 *  --------------------------------|-------------------------------|--------------
 *  PAIR_CLIENT_FRUIT               | client keys                   | shared secret
 *  PAIR_CLIENT_HOMEKIT_NORMAL      | client keys, server public    | shared secret
                                    | key, server id                | shared secret
 *  PAIR_CLIENT_HOMEKIT_TRANSIENT   | shared secret                 | n/a
 *  PAIR_SERVER_HOMEKIT (normal)    | client public key, client id  | shared secret
 *  PAIR_SERVER_HOMEKIT (transient) | shared secret                 | n/a
 */
struct pair_result
{
  char device_id[PAIR_AP_DEVICE_ID_LEN_MAX]; // ID of the peer, 16 bytes + zero term
  uint8_t client_private_key[64];
  uint8_t client_public_key[32];
  uint8_t server_public_key[32];
  uint8_t shared_secret[64];
  size_t shared_secret_len; // Will be 32 (normal) or 64 (transient)
};

struct pair_setup_context;
struct pair_verify_context;
struct pair_cipher_context;

/* Client
 * When you have the pin-code (must be 4 bytes), create a new context with this
 * function and then call pair_setup_request1(). device_id is only
 * required for homekit pairing, where it should have length 16.
 *
 * Server
 * Create a new context with the pin-code to verify with, then when the request
 * is received, use pair_setup_response1() to read it, and then reply using
 * pair_setup_request1().
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
pair_setup_request1(size_t *len, struct pair_setup_context *sctx);
uint8_t *
pair_setup_request2(size_t *len, struct pair_setup_context *sctx);
uint8_t *
pair_setup_request3(size_t *len, struct pair_setup_context *sctx);

int
pair_setup_response1(struct pair_setup_context *sctx, const uint8_t *data, size_t data_len);
int
pair_setup_response2(struct pair_setup_context *sctx, const uint8_t *data, size_t data_len);
int
pair_setup_response3(struct pair_setup_context *sctx, const uint8_t *data, size_t data_len);

/* Returns the result of a pairing, or negative if pairing is not completed. See
 * 'struct pair_result' for info about pairing results. The string is a
 * representation of the result that is easy to persist and can be used to feed
 * back into pair_verify_new. The result and string becomes invalid when you
 * free sctx.
 */
int
pair_setup_result(const char **client_setup_keys, struct pair_result **result, struct pair_setup_context *sctx);


/* Client
 * When you have completed pair setup you get a string containing some keys
 * from pair_setup_result(). Give the string as input to this function to create
 * a verification context. Set the callback to NULL. Then call
 * pair_verify_request1() device_id is only required for homekit pairing, where
 * it should have len 16.
 *
 * Server
 * When you get a pair verify request from a new peer, create a new context with
 * client_setup_keys set to NULL, with a callback set and the server's device ID
 * (same as for setup). Then call pair_verify_response1() to read the request,
 * and then pair_verify_request1() to make a reply. The callback is used to get
 * the persisted client public key (saved after pair setup), so the client can
 * be verified. You can set the callback to NULL if you don't care about that.
 * If set, the callback is made as part of pair_verify_response2. The job of the
 * callback is to fill out the client_public_key with the public key from the
 * setup stage (see 'struct pair_result'). If the client device id is not known
 * (i.e. it has not completed pair-setup), return -1.
 */
typedef int (*pair_get_cb)(uint8_t client_public_key[32], const char *device_id, void *cb_arg);

struct pair_verify_context *
pair_verify_new(enum pair_type type, const char *client_setup_keys, pair_get_cb cb, void *cb_arg, const char *device_id);
void
pair_verify_free(struct pair_verify_context *vctx);

/* Returns last error message
 */
const char *
pair_verify_errmsg(struct pair_verify_context *vctx);

uint8_t *
pair_verify_request1(size_t *len, struct pair_verify_context *vctx);
uint8_t *
pair_verify_request2(size_t *len, struct pair_verify_context *vctx);

int
pair_verify_response1(struct pair_verify_context *vctx, const uint8_t *data, size_t data_len);
int
pair_verify_response2(struct pair_verify_context *vctx, const uint8_t *data, size_t data_len);

/* Returns a pointer to the result of the pairing. Only the shared secret will
 * be filled out. Note that the result become invalid when you free vctx.
 */
int
pair_verify_result(struct pair_result **result, struct pair_verify_context *vctx);


/* When you have completed the verification you can extract a key with
 * pair_verify_result(). Give the shared secret as input to this function to
 * create a ciphering context.
 */
struct pair_cipher_context *
pair_cipher_new(enum pair_type type, int channel, const uint8_t *shared_secret, size_t shared_secret_len);
void
pair_cipher_free(struct pair_cipher_context *cctx);

/* Returns last error message
 */
const char *
pair_cipher_errmsg(struct pair_cipher_context *cctx);

/* The return value equals length of plaintext that was encrypted, so if the
 * return value == plaintext_len then everything was encrypted. On error -1 is
 * returned.
 */
ssize_t
pair_encrypt(uint8_t **ciphertext, size_t *ciphertext_len, uint8_t *plaintext, size_t plaintext_len, struct pair_cipher_context *cctx);

/* The return value equals length of ciphertext that was decrypted, so if the
 * return value == ciphertext_len then everything was decrypted. On error -1 is
 * returned.
 */
ssize_t
pair_decrypt(uint8_t **plaintext, size_t *plaintext_len, uint8_t *ciphertext, size_t ciphertext_len, struct pair_cipher_context *cctx);

/* Rolls back the nonce
 */
void
pair_encrypt_rollback(struct pair_cipher_context *cctx);
void
pair_decrypt_rollback(struct pair_cipher_context *cctx);

/* For parsing an incoming message to see what type ("state") it is. Mostly
 * useful for servers. Returns 1-6 for pair-setup and 1-4 for pair-verify.
 */
int
pair_state_get(enum pair_type type, const char **errmsg, const uint8_t *data, size_t data_len);

#endif  /* !__PAIR_AP_H__ */
