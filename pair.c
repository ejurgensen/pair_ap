#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <plist/plist.h>
#include <event2/event.h>
#include <event2/buffer.h>

#include "evrtsp/evrtsp.h"
#include "csrp/srp.h"

#define ADDRESS "192.168.1.213"
#define PORT 7000
#define ACTIVE_REMOTE "3515324763"
#define DACP_ID "FF1DB45949E6CBD3"
#define USER_AGENT "testagent/1.0"
#define USERNAME "84:8F:69:F5:28:24"
//#define USERNAME "0x005056c00001"


typedef void (*request_cb)(struct evrtsp_request *, void *);

struct verification_ctx
{
  struct SRPUser *user;

  char *pin;
  size_t pin_len;

  const unsigned char *pkA;
  int pkA_len;

  char *pkB;
  uint64_t pkB_len;

  const unsigned char *M1;
  int M1_len;

  char *M2;
  uint64_t M2_len;

  char *salt;
  uint64_t salt_len;

} vctx;

static struct event_base *evbase;
static struct evrtsp_connection *evcon;
static int cseq;

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


static void
step3_response(struct evrtsp_request *req, void *arg)
{ 
  plist_t dict;
  plist_t proof;
  char *data;
  uint64_t data_len;

  if (response_ok(req) < 0)
    return;

  data = (char *)evbuffer_pullup(req->input_buffer, -1);
  data_len = evbuffer_get_length(req->input_buffer);

  plist_from_bin(data, data_len, &dict);

  proof = plist_dict_get_item(dict, "proof");
  if (!proof)
    {
      printf("No proof from server\n");
      goto error;
    }

  plist_get_data_val(proof, &vctx.M2, &vctx.M2_len); // M2
  printf("- got proof with length %d\n", (int)vctx.M2_len);

  // Check M2
  srp_user_verify_session(vctx.user, (const unsigned char *)vctx.M2);
  if (!srp_user_is_authenticated(vctx.user))
    {
      printf("Server authentication failed\n");
      goto error;
    }

  printf("Stage 1 complete - you did it!!\n");

  plist_free(dict);
  event_base_loopbreak(evbase);
  return;

 error:
  plist_free(dict);
  event_base_loopbreak(evbase);
}

static int
step3_request(void)
{
  const char *auth_username = 0;

  plist_t dict;
  plist_t pk;
  plist_t proof;
  char *data;
  uint32_t data_len;
  int ret;

  // Calculate A
  srp_user_start_authentication(vctx.user, &auth_username, &vctx.pkA, &vctx.pkA_len);

  // Calculate M1 (client proof)
  srp_user_process_challenge(vctx.user, (const unsigned char *)vctx.salt, vctx.salt_len, (const unsigned char *)vctx.pkB, vctx.pkB_len, &vctx.M1, &vctx.M1_len);

  pk = plist_new_data((char *)vctx.pkA, vctx.pkA_len);
  printf("- made pkA with length %d\n", (int)vctx.pkA_len);

  proof = plist_new_data((char *)vctx.M1, vctx.M1_len);
  printf("- made M1 with length %d\n", (int)vctx.M1_len);

  dict = plist_new_dict();
  plist_dict_insert_item(dict, "pk", pk);
  plist_dict_insert_item(dict, "proof", proof);

  data = NULL; // Not sure why required, Valgrind says plist_to_bin() will use value of the pointer?!?
  plist_to_bin(dict, &data, &data_len);

  ret = make_request("/pair-setup-pin", data, data_len, "application/x-apple-binary-plist", step3_response);

  plist_free(dict);
  free(data);

  return ret;
}

static void
step2_response(struct evrtsp_request *req, void *arg)
{
  plist_t dict;
  plist_t pk;
  plist_t salt;
  char *data;
  uint64_t data_len;

  if (response_ok(req) < 0)
    return;

  data = (char *)evbuffer_pullup(req->input_buffer, -1);
  data_len = evbuffer_get_length(req->input_buffer);

  plist_from_bin(data, data_len, &dict);

  pk = plist_dict_get_item(dict, "pk");
  salt = plist_dict_get_item(dict, "salt");
  if (!pk || !salt)
    {
      printf("No pk or salt\n");
      plist_free(dict);
      event_base_loopbreak(evbase);
      return;
    }

  plist_get_data_val(pk, &vctx.pkB, &vctx.pkB_len); // B
  printf("- got pkB with length %d\n", (int)vctx.pkB_len);

  plist_get_data_val(salt, &vctx.salt, &vctx.salt_len);
  printf("- got salt with length %d\n", (int)vctx.salt_len);

  plist_free(dict);

  step3_request();
}

static int
step2_request(void)
{
  plist_t dict;
  plist_t method;
  plist_t user;
  char *data;
  uint32_t data_len;
  int ret;

  vctx.user = srp_user_new(SRP_SHA1, SRP_NG_2048, USERNAME, (const unsigned char *)vctx.pin, 4, 0, 0);

  dict = plist_new_dict();

  method = plist_new_string("pin");
  user = plist_new_string(USERNAME);

  plist_dict_insert_item(dict, "method", method);
  plist_dict_insert_item(dict, "user", user);

  data = NULL; // Not sure why required, but Valgrind says plist_to_bin() will use value of the pointer?!?
  plist_to_bin(dict, &data, &data_len);

  ret = make_request("/pair-setup-pin", data, data_len, "application/x-apple-binary-plist", step2_response);

  plist_free(dict);
  free(data);

  return ret;
}

static void
step1_response(struct evrtsp_request *req, void *arg)
{
  size_t len;

  if (response_ok(req) < 0)
    return;

  printf ("Enter pin: ");
  fflush (stdout);

  len = getline(&vctx.pin, &vctx.pin_len, stdin);
  if (len != 5) // Includes EOL
    {
      printf ("Bad pin length %d %d\n", len, strlen(vctx.pin));
      event_base_loopbreak(evbase);
      return;
    }

  step2_request();
}

static int
step1_request(void)
{
  return make_request("/pair-pin-start", NULL, 0, "application/x-apple-binary-plist", step1_response);
}


int
main( int argc, char * argv[] )
{
  int ret;

  evbase = event_base_new();
  evcon = evrtsp_connection_new(ADDRESS, PORT);
  evrtsp_connection_set_base(evcon, evbase);

  ret = step1_request();
  if (ret < 0)
    goto the_end;

  event_base_dispatch(evbase);

 the_end:
  evrtsp_connection_free(evcon);
  event_base_free(evbase);

  return 0;
}
