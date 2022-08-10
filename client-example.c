#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <event2/event.h>
#include <event2/buffer.h>

#include "evrtsp/evrtsp.h"
#include "pair.h"

#ifdef CONFIG_GCRYPT
# include <gcrypt.h>
#endif

#define DEVICE_ID "AABBCCDD11223344"
#define ACTIVE_REMOTE "3515324763"
#define DACP_ID "FF1DB45949E6CBD3"
#define USER_AGENT "AirPlay/381.13"

#define ENDPOINT_SETUP_FRUIT "/pair-setup-pin"
#define CONTENTTYPE_SETUP_FRUIT "application/x-apple-binary-plist"

#define ENDPOINT_SETUP_HOMEKIT "/pair-setup"
#define CONTENTTYPE_SETUP_HOMEKIT "application/octet-stream"


typedef void (*request_cb)(struct evrtsp_request *, void *);

static struct event_base *evbase;
static struct evrtsp_connection *evcon;
static int cseq;

static const char *endpoint_setup;
static const char *content_type_setup;

static enum pair_type pair_type;

static struct pair_cipher_context *cipher_ctx;
static struct pair_verify_context *verify_ctx;
static struct pair_setup_context *setup_ctx;


static char *
prompt_pin(void)
{
  char *pin = NULL;
  ssize_t len;
  size_t sz;

  printf ("Enter pin: ");
  fflush (stdout);

  len = getline(&pin, &sz, stdin);
  if (len < 1)
    {
      printf("Bad pin entered (len=%zd)\n", len);
      return NULL;
    }

  pin[len - 1] = '\0'; // Zero the EOL

  return pin;
}

static int
response_process(uint8_t **response, struct evrtsp_request *req)
{
  if (!req)
    {
      printf("failed, could not read response\n");
      return -1;
    }
  else if (req->response_code != 200)
    {
      printf("failed with error code %d: %s (body is %zu bytes)\n\n", req->response_code, req->response_code_line, evbuffer_get_length(req->input_buffer));
      return -1;
    }

  printf("success\n\n");

  *response = evbuffer_pullup(req->input_buffer, -1);

  return evbuffer_get_length(req->input_buffer);
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
//  evrtsp_add_header(req->output_headers, "DACP-ID", DACP_ID);
//  evrtsp_add_header(req->output_headers, "Active-Remote", ACTIVE_REMOTE);

  if (pair_type == PAIR_CLIENT_HOMEKIT_NORMAL)
    evrtsp_add_header(req->output_headers, "X-Apple-HKP", "3");
  else if (pair_type == PAIR_CLIENT_HOMEKIT_TRANSIENT)
    evrtsp_add_header(req->output_headers, "X-Apple-HKP", "4");

  printf("Making request %d to '%s' (len %zu)... ", cseq, url, len);

  return evrtsp_make_request(evcon, req, EVRTSP_REQ_POST, url);
}

static int
make_request_options(const char *url, const void *data, size_t len, const char *content_type, request_cb cb)
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
//  evrtsp_add_header(req->output_headers, "DACP-ID", DACP_ID);
//  evrtsp_add_header(req->output_headers, "Active-Remote", ACTIVE_REMOTE);
  evrtsp_add_header(req->output_headers, "X-Apple-HKP", "3");

  printf("Making request %d to '%s' (len %zu)... ", cseq, url, len);

  return evrtsp_make_request(evcon, req, EVRTSP_REQ_OPTIONS, url);
}


static void
options_response(struct evrtsp_request *req, void *arg)
{
  uint8_t *response;
  int ret;

  ret = response_process(&response, req);
  if (ret >= 0)
    printf("OPTIONS complete\n");

  printf("Done\n");

  event_base_loopbreak(evbase);
}

static int
options_request(void)
{
  return make_request_options("*", NULL, 0, NULL, options_response);
}

static void
rtsp_cipher(struct evbuffer *evbuf, void *arg, int encrypt)
{
  uint8_t *out = NULL;
  size_t out_len = 0;
  ssize_t processed;

  uint8_t *in = evbuffer_pullup(evbuf, -1);
  size_t in_len = evbuffer_get_length(evbuf);

  if (encrypt)
    processed = pair_encrypt(&out, &out_len, in, in_len, cipher_ctx);
  else
    processed = pair_decrypt(&out, &out_len, in, in_len, cipher_ctx);

  evbuffer_drain(evbuf, in_len);

  if (processed < 0)
    {
      printf("Error while ciphering: %s\n", pair_cipher_errmsg(cipher_ctx));
      return;
    }
  else if (processed != in_len)
    {
      printf("Partial ciphering, only %zd of %zu input bytes were processed\n", processed, in_len);
    }

  evbuffer_add(evbuf, out, out_len);
}

static void
verify_step2_response(struct evrtsp_request *req, void *arg)
{
  uint8_t *response;
  struct pair_result *result;
  int ret;

  ret = response_process(&response, req);
  if (ret < 0)
    goto error;

  ret = pair_verify_response2(verify_ctx, response, ret);
  if (ret < 0)
    goto error;

  printf("Verify complete!\n\n");

  ret = pair_verify_result(&result, verify_ctx);
  if (ret < 0)
    goto error;

  cipher_ctx = pair_cipher_new(pair_type, 0, result->shared_secret, result->shared_secret_len);
  if (!cipher_ctx)
    goto error;

  evrtsp_connection_set_ciphercb(evcon, rtsp_cipher, NULL);

  ret = options_request();
  if (ret < 0)
    goto error;

  pair_verify_free(verify_ctx);

  return;

 error:
  printf("Error: %s\n", pair_verify_errmsg(verify_ctx));
  pair_verify_free(verify_ctx);
  pair_cipher_free(cipher_ctx);
  event_base_loopbreak(evbase);
}

static int
verify_step2_request(void)
{
  uint8_t *request;
  size_t len;
  int ret;

  request = pair_verify_request2(&len, verify_ctx);
  if (!request)
    return -1;

  ret = make_request("/pair-verify", request, len, "application/octet-stream", verify_step2_response);

  free(request);

  return ret;
}

static void
verify_step1_response(struct evrtsp_request *req, void *arg)
{
  uint8_t *response;
  int ret;

  ret = response_process(&response, req);
  if (ret <= 0)
    goto error;

  ret = pair_verify_response1(verify_ctx, response, ret);
  if (ret < 0)
    goto error;

  ret = verify_step2_request();
  if (ret < 0)
    goto error;

  return;

 error:
  printf("Error: %s\n", pair_verify_errmsg(verify_ctx));
  pair_verify_free(verify_ctx);
  event_base_loopbreak(evbase);
}

static int
verify_step1_request(const char *authorisation_key)
{
  uint8_t *request = NULL;
  size_t len;
  int ret;

  verify_ctx = pair_verify_new(pair_type, authorisation_key, NULL, NULL, DEVICE_ID);
  if (!verify_ctx)
    return -1;

  request = pair_verify_request1(&len, verify_ctx);
  if (!request)
    goto error;

  ret = make_request("/pair-verify", request, len, "application/octet-stream", verify_step1_response);
  if (ret < 0)
    goto error;

  free(request);
  return ret;

 error:
  printf("Error: %s\n", pair_verify_errmsg(verify_ctx));
  pair_verify_free(verify_ctx);
  free(request);
  return -1;
}

static void
setup_step3_response(struct evrtsp_request *req, void *arg)
{
  const char *key;
  uint8_t *response;
  struct pair_result *result;
  int ret;

  ret = response_process(&response, req);
  if (ret <= 0)
    goto error;

  ret = pair_setup_response3(setup_ctx, response, ret);
  if (ret < 0)
    goto error;

  ret = pair_setup_result(&key, &result, setup_ctx);
  if (ret < 0)
    goto error;

  printf("Setup of device ID %s complete, got key: %s\n", result->device_id, key);

  ret = verify_step1_request(key);
  if (ret < 0)
    goto error;

  pair_setup_free(setup_ctx);

  return;

 error:
  printf("Error: %s\n", pair_setup_errmsg(setup_ctx));
  pair_setup_free(setup_ctx);
  event_base_loopbreak(evbase);
}

static int
setup_step3_request(void)
{
  uint8_t *request;
  size_t len;
  int ret;

  request = pair_setup_request3(&len, setup_ctx);
  if (!request)
    return -1;

  ret = make_request(endpoint_setup, request, len, content_type_setup, setup_step3_response);

  free(request);

  return ret;
}

static void
setup_step2_response(struct evrtsp_request *req, void *arg)
{
  uint8_t *response;
  struct pair_result *result;
  int ret;

  ret = response_process(&response, req);
  if (ret <= 0)
    goto error;

  ret = pair_setup_response2(setup_ctx, response, ret);
  if (ret < 0)
    goto error;

  printf("Setup SRP stage complete\n");

  if (pair_type == PAIR_CLIENT_HOMEKIT_TRANSIENT)
    {
      ret = pair_setup_result(NULL, &result, setup_ctx);
      if (ret < 0)
	goto error;

      cipher_ctx = pair_cipher_new(pair_type, 0, result->shared_secret, result->shared_secret_len);
      if (!cipher_ctx)
	goto error;

      evrtsp_connection_set_ciphercb(evcon, rtsp_cipher, NULL);

      ret = options_request();
      if (ret < 0)
	goto error;

      pair_setup_free(setup_ctx);

      return;
    }

  ret = setup_step3_request();
  if (ret < 0)
    goto error;

  return;

 error:
  printf("Error: %s\n", pair_setup_errmsg(setup_ctx));
  pair_setup_free(setup_ctx);
  event_base_loopbreak(evbase);
}

static int
setup_step2_request(void)
{
  uint8_t *request;
  size_t len;
  int ret;

  request = pair_setup_request2(&len, setup_ctx);
  if (!request)
    return -1;

  ret = make_request(endpoint_setup, request, len, content_type_setup, setup_step2_response);

  free(request);

  return ret;
}

static void
setup_step1_response(struct evrtsp_request *req, void *arg)
{
  uint8_t *response;
  int ret;

  ret = response_process(&response, req);
  if (ret <= 0)
    goto error;

  ret = pair_setup_response1(setup_ctx, response, ret);
  if (ret < 0)
    goto error;

  ret = setup_step2_request();
  if (ret < 0)
    goto error;

  return;

 error:
  printf("Error: %s\n", pair_setup_errmsg(setup_ctx));
  pair_setup_free(setup_ctx);
  event_base_loopbreak(evbase);
}

static int
setup_step1_request(void)
{
  uint8_t *request;
  size_t len;
  int ret;

  request = pair_setup_request1(&len, setup_ctx);
  if (!request)
    return -1;

  ret = make_request(endpoint_setup, request, len, content_type_setup, setup_step1_response);

  free(request);
  return ret;
}

static void
setup_start_response(struct evrtsp_request *req, void *arg)
{
  uint8_t *response;
  char *pin = NULL;
  int ret;

  if (req)
    {
      ret = response_process(&response, req);
      if (ret < 0)
	goto error;
    }

  if (pair_type != PAIR_CLIENT_HOMEKIT_TRANSIENT)
    {
      pin = prompt_pin();
      if (!pin)
	goto error;
    }

  setup_ctx = pair_setup_new(pair_type, pin, NULL, NULL, DEVICE_ID);
  if (!setup_ctx)
    goto error;

  ret = setup_step1_request();
  if (ret < 0)
    goto error;

  free(pin);
  return;

 error:
  if (setup_ctx)
    printf("Error: %s\n", pair_setup_errmsg(setup_ctx));
  free(pin);
  pair_setup_free(setup_ctx);
  event_base_loopbreak(evbase);
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

  if (argc < 4 || argc > 5)
    {
      printf("%s ip_address port homekit|fruit|transient [skip_pin]\n", argv[0]);
      return -1;
    }

  const char *address = argv[1];
  const char *port = argv[2];
  int skip_pin = (argc == 5);

  if (strcmp(argv[3], "fruit") == 0)
    {
      printf("Pair type is fruit\n");
      pair_type = PAIR_CLIENT_FRUIT;
      endpoint_setup = ENDPOINT_SETUP_FRUIT;
      content_type_setup = CONTENTTYPE_SETUP_FRUIT;
    }
  else if (strcmp(argv[3], "homekit") == 0)
    {
      printf("Pair type is homekit (normal)\n");
      pair_type = PAIR_CLIENT_HOMEKIT_NORMAL;
      endpoint_setup = ENDPOINT_SETUP_HOMEKIT;
      content_type_setup = CONTENTTYPE_SETUP_HOMEKIT;
    }
  else if (strcmp(argv[3], "transient") == 0)
    {
      printf("Pair type is homekit (transient)\n");
      pair_type = PAIR_CLIENT_HOMEKIT_TRANSIENT;
      endpoint_setup = ENDPOINT_SETUP_HOMEKIT;
      content_type_setup = CONTENTTYPE_SETUP_HOMEKIT;
    }

// libgcrypt requires that the application initializes the library
#ifdef CONFIG_GCRYPT
  if (!gcry_check_version(NULL))
    {
      printf("libgcrypt not initialized\n");
      return -1;
    }
  gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif

  evbase = event_base_new();
  evcon = evrtsp_connection_new(address, atoi(port));
  evrtsp_connection_set_base(evcon, evbase);

  if (pair_type == PAIR_CLIENT_HOMEKIT_TRANSIENT || skip_pin)
    {
      setup_start_response(NULL, NULL);
    }
  else
    {
      ret = setup_start_request();
      if (ret < 0)
	goto the_end;
    }

  event_base_dispatch(evbase);

 the_end:
  evrtsp_connection_free(evcon);
  event_base_free(evbase);

  return 0;
}
