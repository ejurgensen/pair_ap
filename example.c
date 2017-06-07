#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <event2/event.h>
#include <event2/buffer.h>

#include "evrtsp/evrtsp.h"
#include "verification.h"

#define ADDRESS "192.168.1.213"
#define PORT 7000
#define ACTIVE_REMOTE "3515324763"
#define DACP_ID "FF1DB45949E6CBD3"
#define USER_AGENT "testagent/1.0"


typedef void (*request_cb)(struct evrtsp_request *, void *);

static struct event_base *evbase;
static struct evrtsp_connection *evcon;
static int cseq;

static struct verification_verify_context *verify_ctx;
static struct verification_setup_context *setup_ctx;


static int
response_process(uint8_t **response, struct evrtsp_request *req)
{
  if (req->response_code != 200)
    {
      printf("failed with error code %d: %s\n", req->response_code, req->response_code_line);
      return -1;
    }

  printf("success\n");

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
  evrtsp_add_header(req->output_headers, "DACP-ID", DACP_ID);
  evrtsp_add_header(req->output_headers, "Active-Remote", ACTIVE_REMOTE);

  printf("Making request %d to '%s'... ", cseq, url);

  return evrtsp_make_request(evcon, req, EVRTSP_REQ_POST, url);
}


static void
verify_step2_response(struct evrtsp_request *req, void *arg)
{
  uint8_t *response;
  int ret;

  ret = response_process(&response, req);
  if (ret >= 0)
    printf("Verification complete\n");

  event_base_loopbreak(evbase);
}

static int
verify_step2_request(void)
{
  uint8_t *request;
  uint32_t len;
  int ret;

  request = verification_verify_request2(&len, verify_ctx);
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

  ret = verification_verify_response1(verify_ctx, response, ret);
  if (ret < 0)
    goto error;

  ret = verify_step2_request();
  if (ret < 0)
    goto error;

  return;

 error:
  printf("Error: %s\n", verification_verify_errmsg(verify_ctx));
  verification_verify_free(verify_ctx);
  event_base_loopbreak(evbase);
}

static int
verify_step1_request(uint8_t *authorisation_key)
{
  uint8_t *request = NULL;
  uint32_t len;
  int ret;

  verify_ctx = verification_verify_new(authorisation_key);
  if (!verify_ctx)
    return -1;

  request = verification_verify_request1(&len, verify_ctx);
  if (!request)
    goto error;

  ret = make_request("/pair-verify", request, len, "application/octet-stream", verify_step1_response);
  if (ret < 0)
    goto error;

  free(request);
  return ret;

 error:
  printf("Error: %s\n", verification_verify_errmsg(verify_ctx));
  verification_verify_free(verify_ctx);
  free(request);
  return -1;
}

static void
setup_step3_response(struct evrtsp_request *req, void *arg)
{
  uint8_t *response;
  uint8_t *authorisation_key = NULL;
  uint32_t len;
  int ret;

  ret = response_process(&response, req);
  if (ret <= 0)
    goto error;

  ret = verification_setup_response3(setup_ctx, response, ret);
  if (ret < 0)
    goto error;

  authorisation_key = verification_setup_result(&len, setup_ctx);
  if (!authorisation_key)
    goto error;

  printf("Setup complete, got an authorisation key of length %d\n", (int)len);

  ret = verify_step1_request(authorisation_key);
  if (ret < 0)
    goto error;

  verification_setup_free(setup_ctx);
  free(authorisation_key);

  return;

 error:
  free(authorisation_key);
  printf("Error: %s\n", verification_setup_errmsg(setup_ctx));
  verification_setup_free(setup_ctx);
  event_base_loopbreak(evbase);
}

static int
setup_step3_request(void)
{
  uint8_t *request;
  uint32_t len;
  int ret;

  request = verification_setup_request3(&len, setup_ctx);
  if (!request)
    return -1;

  ret = make_request("/pair-setup-pin", request, len, "application/x-apple-binary-plist", setup_step3_response);

  free(request);

  return ret;
}

static void
setup_step2_response(struct evrtsp_request *req, void *arg)
{
  uint8_t *response;
  int ret;

  ret = response_process(&response, req);
  if (ret <= 0)
    goto error;

  ret = verification_setup_response2(setup_ctx, response, ret);
  if (ret < 0)
    goto error;

  printf("Setup SRP stage complete\n");

  ret = setup_step3_request();
  if (ret < 0)
    goto error;

  return;

 error:
  printf("Error: %s\n", verification_setup_errmsg(setup_ctx));
  verification_setup_free(setup_ctx);
  event_base_loopbreak(evbase);
}

static int
setup_step2_request(void)
{
  uint8_t *request;
  uint32_t len;
  int ret;

  request = verification_setup_request2(&len, setup_ctx);
  if (!request)
    return -1;

  ret = make_request("/pair-setup-pin", request, len, "application/x-apple-binary-plist", setup_step2_response);

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

  ret = verification_setup_response1(setup_ctx, response, ret);
  if (ret < 0)
    goto error;

  ret = setup_step2_request();
  if (ret < 0)
    goto error;

  return;

 error:
  printf("Error: %s\n", verification_setup_errmsg(setup_ctx));
  verification_setup_free(setup_ctx);
  event_base_loopbreak(evbase);
}

static int
setup_step1_request(void)
{
  uint8_t *request;
  uint32_t len;
  int ret;

  request = verification_setup_request1(&len, setup_ctx);
  if (!request)
    return -1;

  ret = make_request("/pair-setup-pin", request, len, "application/x-apple-binary-plist", setup_step1_response);

  free(request);
  return ret;
}

static void
setup_start_response(struct evrtsp_request *req, void *arg)
{
  uint8_t *response;
  char *pin = NULL;
  size_t len;
  int ret;

  ret = response_process(&response, req);
  if (ret < 0)
    goto error;

  printf ("Enter pin: ");
  fflush (stdout);

  len = getline(&pin, &len, stdin);
  if (len != 5) // Includes EOL
    {
      printf ("Bad pin length %zu\n", len);
      goto error;
    }

  setup_ctx = verification_setup_new(pin);
  if (!setup_ctx)
    goto error;

  free(pin);

  ret = setup_step1_request();
  if (ret < 0)
    goto error;

  return;

 error:
  if (setup_ctx)
    printf("Error: %s\n", verification_setup_errmsg(setup_ctx));
  free(pin);
  verification_setup_free(setup_ctx);
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
