/*
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
#include <inttypes.h>
#include <unistd.h>

#include <assert.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

#include "pair.h"

#ifdef CONFIG_GCRYPT
# include <gcrypt.h>
#endif

#define DEVICE_ID "FFEEDDCCBBAA9988"
#define LISTEN_PORT 7000
#define CONTENT_TYPE_OCTET "application/octet-stream"
#define RTSP_VERSION "RTSP/1.0"
#define OPTIONS "OPTIONS *"

struct connection_ctx
{
  struct evbuffer *pending;
  struct pair_setup_context *setup_ctx;
  struct pair_verify_context *verify_ctx;
  struct pair_cipher_context *cipher_ctx;

  int pair_completed;
};

struct rtsp_msg
{
  int content_length;
  char *content_type;
  char *first_line;
  int cseq;

  const uint8_t *body;
  size_t bodylen;

  const uint8_t *data;
  size_t datalen;
};

struct pairings
{
  char device_id[PAIR_AP_DEVICE_ID_LEN_MAX];
  uint8_t public_key[32];

  struct pairings *next;
} *pairings;


static void
connection_free(struct connection_ctx *conn_ctx)
{
  if (!conn_ctx)
    return;

  evbuffer_free(conn_ctx->pending);
  pair_setup_free(conn_ctx->setup_ctx);
  pair_cipher_free(conn_ctx->cipher_ctx);

  free(conn_ctx);
}

static void
response_headers_add(struct evbuffer *response, int cseq, size_t content_length, const char *content_type)
{
  evbuffer_add_printf(response, "%s 200 OK\r\n", RTSP_VERSION);
  evbuffer_add_printf(response, "Server: MyServer/1.0\r\n");
  if (content_length)
    evbuffer_add_printf(response, "Content-Length: %zu\r\n", content_length);
  if (content_type)
    evbuffer_add_printf(response, "Content-Type: %s\r\n", content_type);
  evbuffer_add_printf(response, "CSeq: %d\r\n", cseq);
  evbuffer_add_printf(response, "\r\n");
}

static void
response_create_from_raw(struct evbuffer *response, uint8_t *body, size_t body_len, int cseq, const char *content_type)
{
  response_headers_add(response, cseq, body_len, content_type);

  if (body)
    evbuffer_add(response, body, body_len);
}

static int
encryption_enable(struct connection_ctx *conn_ctx, const uint8_t *shared_secret, size_t shared_secret_len)
{
  conn_ctx->cipher_ctx = pair_cipher_new(PAIR_SERVER_HOMEKIT, 2, shared_secret, shared_secret_len);
  if (!conn_ctx->cipher_ctx)
    {
      printf("Error setting up ciphering\n");
      return -1;
    }

  return 0;
}

static int
buffer_encrypt(struct evbuffer *output, uint8_t *in, size_t in_len, struct connection_ctx *conn_ctx)
{
  uint8_t *out;
  size_t out_len;
  int ret;

  ret = pair_encrypt(&out, &out_len, in, in_len, conn_ctx->cipher_ctx);
  if (ret < 0)
    {
      printf("Error encrypting: %s\n", pair_cipher_errmsg(conn_ctx->cipher_ctx));
      return -1;
    }

  evbuffer_add(output, out, out_len);
  free(out);
  return 0;
}

static int
buffer_decrypt(struct evbuffer *output, struct evbuffer *input, struct connection_ctx *conn_ctx)
{
  uint8_t *in;
  size_t in_len;
  ssize_t bytes_decrypted;
  uint8_t *plain;
  size_t plain_len;

  in = evbuffer_pullup(input, -1);
  in_len = evbuffer_get_length(input);

  // Note that bytes_decrypted is not necessarily equal to plain_len
  bytes_decrypted = pair_decrypt(&plain, &plain_len, in, in_len, conn_ctx->cipher_ctx);
  if (bytes_decrypted < 0)
    {
      printf("Error decrypting: %s\n", pair_cipher_errmsg(conn_ctx->cipher_ctx));
      return -1;
    }

  evbuffer_add(output, plain, plain_len);
  evbuffer_drain(input, bytes_decrypted);
  free(plain);
  return 0;
}


/* ---------------------------- Pairing callbacks --------------------------- */
/*   Note that none of these callbacks are required if you don't care about   */
/*  securely verifying the client + don't require support for the pair-add,   */
/*                   pair-remove and pair-list methods.                       */

static struct pairings *
pairing_find(const char *device_id)
{
  struct pairings *pairing;

  for (pairing = pairings; pairing; pairing = pairing->next)
    {
      if (strcmp(device_id, pairing->device_id) == 0)
        break;
    }

  return pairing;
}

static int
pairing_add_cb(uint8_t public_key[32], const char *device_id, void *cb_arg)
{
  struct pairings *pairing;

  printf("Adding paired device %s\n", device_id);

  pairing = pairing_find(device_id);
  if (pairing)
    {
      memcpy(pairing->public_key, public_key, sizeof(pairing->public_key));
      return 0;
    }

  pairing = calloc(1, sizeof(struct pairings));
  snprintf(pairing->device_id, sizeof(pairing->device_id), "%s", device_id);
  memcpy(pairing->public_key, public_key, sizeof(pairing->public_key));

  pairing->next = pairings;
  pairings = pairing;

  return 0;
}

static int
pairing_remove_cb(uint8_t public_key[32], const char *device_id, void *cb_arg)
{
  struct pairings *pairing;
  struct pairings *iter;

  printf("Removing paired device %s\n", device_id);

  pairing = pairing_find(device_id);
  if (!pairing)
    {
      printf("Remove callback for unknown device\n");
      return -1;
    }

  if (pairing == pairings)
    pairings = pairing->next;
  else
    {
      for (iter = pairings; iter && (iter->next != pairing); iter = iter->next)
	; /* EMPTY */

      if (iter)
	iter->next = pairing->next;
    }

  free(pairing);
  return 0;
}

static void
pairing_list_cb(pair_cb enum_cb, void *enum_cb_arg, void *cb_arg)
{
  struct pairings *pairing;

  printf("Listing paired devices\n");

  for (pairing = pairings; pairing; pairing = pairing->next)
    {
      enum_cb(pairing->public_key, pairing->device_id, enum_cb_arg);
    }
}

static int
pairing_get_cb(uint8_t public_key[32], const char *device_id, void *cb_arg)
{
  struct pairings *pairing;

  printf("Returning public key for paired device %s\n", device_id);

  pairing = pairing_find(device_id);
  if (!pairing)
    return -1;

  memcpy(public_key, pairing->public_key, sizeof(pairing->public_key));

  return 0;
}


/* -------------------------- Pair request handlers ------------------------- */

static int
handle_pin_start(struct evbuffer *output, struct connection_ctx *conn_ctx, struct rtsp_msg *msg)
{
  printf("Please pair with code 3939\n");

  response_create_from_raw(output, NULL, 0, msg->cseq, NULL);

  return 0;
}

static int
handle_pair_setup(struct evbuffer *output, struct connection_ctx *conn_ctx, struct rtsp_msg *msg)
{
  uint8_t *out;
  size_t out_len;
  struct pair_result *result;
  int ret;

  if (!conn_ctx->setup_ctx)
    {
      conn_ctx->setup_ctx = pair_setup_new(PAIR_SERVER_HOMEKIT, NULL, pairing_add_cb, NULL, DEVICE_ID);
      if (!conn_ctx->setup_ctx)
        {
          printf("Error creating setup context\n");
          return -1;
        }
    }

  ret = pair_setup(&out, &out_len, conn_ctx->setup_ctx, msg->body, msg->bodylen);
  if (ret < 0)
    {
      printf("Pair setup error: %s\n", pair_setup_errmsg(conn_ctx->setup_ctx));
      return -1;
    }

  ret = pair_setup_result(NULL, &result, conn_ctx->setup_ctx);
  if (ret == 0 && result->shared_secret_len > 0) // Transient pairing completed (step 2)
    {
      encryption_enable(conn_ctx, result->shared_secret, result->shared_secret_len);
      conn_ctx->pair_completed = 1;
    }

  response_create_from_raw(output, out, out_len, msg->cseq, CONTENT_TYPE_OCTET);
  free(out);

  return 0;
}

static int
handle_pair_verify(struct evbuffer *output, struct connection_ctx *conn_ctx, struct rtsp_msg *msg)
{
  uint8_t *out;
  size_t out_len;
  struct pair_result *result;
  int ret;

  if (!conn_ctx->verify_ctx)
    {
      conn_ctx->verify_ctx = pair_verify_new(PAIR_SERVER_HOMEKIT, NULL, pairing_get_cb, NULL, DEVICE_ID);
      if (!conn_ctx->verify_ctx)
        {
          printf("Error creating verify context\n");
          return -1;
        }
    }

  ret = pair_verify(&out, &out_len, conn_ctx->verify_ctx, msg->body, msg->bodylen);
  if (ret < 0)
    {
      printf("Pair verify error: %s\n", pair_verify_errmsg(conn_ctx->verify_ctx));
      return -1;
    }

  ret = pair_verify_result(&result, conn_ctx->verify_ctx);
  if (ret == 0)
    {
      encryption_enable(conn_ctx, result->shared_secret, result->shared_secret_len);
      conn_ctx->pair_completed = 1;
    }

  response_create_from_raw(output, out, out_len, msg->cseq, CONTENT_TYPE_OCTET);
  free(out);

  return 0;
}

static int
handle_pair_add(struct evbuffer *output, struct connection_ctx *conn_ctx, struct rtsp_msg *msg)
{
  uint8_t *out;
  size_t out_len;
  int ret;

  ret = pair_add(PAIR_SERVER_HOMEKIT, &out, &out_len, pairing_add_cb, NULL, msg->body, msg->bodylen);
  if (ret < 0)
    {
      printf("Error adding device to list\n");
      return -1;
    }

  response_create_from_raw(output, out, out_len, msg->cseq, CONTENT_TYPE_OCTET);
  free(out);

  return 0;
}

static int
handle_pair_remove(struct evbuffer *output, struct connection_ctx *conn_ctx, struct rtsp_msg *msg)
{
  uint8_t *out;
  size_t out_len;
  int ret;

  ret = pair_remove(PAIR_SERVER_HOMEKIT, &out, &out_len, pairing_remove_cb, NULL, msg->body, msg->bodylen);
  if (ret < 0)
    {
      printf("Error removing device from list\n");
      return -1;
    }

  response_create_from_raw(output, out, out_len, msg->cseq, CONTENT_TYPE_OCTET);
  free(out);

  return 0;
}

static int
handle_pair_list(struct evbuffer *output, struct connection_ctx *conn_ctx, struct rtsp_msg *msg)
{
  uint8_t *out;
  size_t out_len;
  int ret;

  ret = pair_list(PAIR_SERVER_HOMEKIT, &out, &out_len, pairing_list_cb, NULL, msg->body, msg->bodylen);
  if (ret < 0)
    {
      printf("Error creating list of paired devices\n");
      return -1;
    }

  response_create_from_raw(output, out, out_len, msg->cseq, CONTENT_TYPE_OCTET);
  free(out);

  return 0;
}

static int
handle_options(struct evbuffer *output, struct connection_ctx *conn_ctx, struct rtsp_msg *msg)
{
  struct evbuffer *response;
  uint8_t *plain;
  size_t plain_len;
  int ret;

  response = evbuffer_new();

  response_create_from_raw(response, NULL, 0, msg->cseq, NULL);

  if (!conn_ctx->cipher_ctx)
    {
      evbuffer_add_buffer(output, response);
      evbuffer_free(response);
      return 0;
    }

  plain = evbuffer_pullup(response, -1);
  plain_len = evbuffer_get_length(response);

  ret = buffer_encrypt(output, plain, plain_len, conn_ctx);

  evbuffer_free(response);
  return ret;
}

static int
response_send(struct evbuffer *output, struct connection_ctx *conn_ctx, struct rtsp_msg *msg)
{
  if (!msg->first_line)
    return -1;

  if (strncmp(msg->first_line, PAIR_AP_POST_PIN_START, strlen(PAIR_AP_POST_PIN_START)) == 0)
    return handle_pin_start(output, conn_ctx, msg);
  else if (strncmp(msg->first_line, PAIR_AP_POST_SETUP, strlen(PAIR_AP_POST_SETUP)) == 0)
    return handle_pair_setup(output, conn_ctx, msg);
  else if (strncmp(msg->first_line, PAIR_AP_POST_VERIFY, strlen(PAIR_AP_POST_VERIFY)) == 0)
    return handle_pair_verify(output, conn_ctx, msg);
  else if (strncmp(msg->first_line, PAIR_AP_POST_ADD, strlen(PAIR_AP_POST_ADD)) == 0)
    return handle_pair_add(output, conn_ctx, msg);
  else if (strncmp(msg->first_line, PAIR_AP_POST_LIST, strlen(PAIR_AP_POST_LIST)) == 0)
    return handle_pair_list(output, conn_ctx, msg);
  else if (strncmp(msg->first_line, PAIR_AP_POST_REMOVE, strlen(PAIR_AP_POST_REMOVE)) == 0)
    return handle_pair_remove(output, conn_ctx, msg);
  else if (strncmp(msg->first_line, OPTIONS, strlen(OPTIONS)) == 0)
    return handle_options(output, conn_ctx, msg);

  printf("Unknown method: %s\n", msg->first_line);
  return -1;
}


/* --------------------- A basic RTSP server implementation ----------------- */

static void
rtsp_clear(struct rtsp_msg *msg)
{
  free(msg->first_line);
  free(msg->content_type);
}

// Very primitive RTSP message parser, hope you have a better one
static int
rtsp_parse(struct rtsp_msg *msg, uint8_t *in, size_t in_len)
{
  char *line;
  int i;

  line = (char *)in;
  for (i = 0; i < in_len; i++)
    {
      if (in[i] != '\n' && in[i - 1] != '\r')
	continue;

      if (in[i - 2] == '\n' && in[i - 3] == '\r')
	{
	  msg->bodylen = in_len - (i + 1);
	  if (msg->bodylen != msg->content_length)
	    {
	      printf("Incomplete read (have %zu, content-length %d), waiting for more data\n\n", msg->bodylen, msg->content_length);
	      rtsp_clear(msg);
	      return 1;
	    }
	  else if (msg->bodylen > 0)
	    msg->body = in + i + 1;

	  break;
	}

      in[i - 1] = '\0';

      if (!msg->first_line)
	msg->first_line = strdup(line);

      if (strncmp(line, "CSeq: ", strlen("CSeq: ")) == 0)
	msg->cseq = atoi(line + strlen("CSeq: "));

      if (strncmp(line, "Content-Length: ", strlen("Content-Length: ")) == 0)
	msg->content_length = atoi(line + strlen("Content-Length: "));

      if (strncmp(line, "Content-Type: ", strlen("Content-Type: ")) == 0 && !msg->content_type)
	msg->content_type = strdup(line + strlen("Content-Type: "));

      in[i - 1] = '\r';

      line = (char *)in + i + 1;
    }

  msg->data = in;
  msg->datalen = in_len;

  return 0;
}

static void
in_read_cb(struct bufferevent *bev, void *arg)
{
  struct connection_ctx *conn_ctx = arg;
  struct evbuffer *input;
  struct evbuffer *output;
  uint8_t *plain;
  size_t plain_len;
  struct rtsp_msg msg = { 0 };
  int ret;

  input = bufferevent_get_input(bev);
  output = bufferevent_get_output(bev);

  printf("\n--------------------------------------------------------------------------\n");

  if (conn_ctx->pair_completed)
    {
      buffer_decrypt(conn_ctx->pending, input, conn_ctx);
    }
  else
    {
      evbuffer_add_buffer(conn_ctx->pending, input);
    }

  // Pending holds all the message we have received so far, incl. what parts we
  // might have received in previous callbacks
  plain = evbuffer_pullup(conn_ctx->pending, -1);
  plain_len = evbuffer_get_length(conn_ctx->pending);

  ret = rtsp_parse(&msg, plain, plain_len);
  if (ret < 0)
    {
      printf("Could not parse RTSP message\n");
      goto error;
    }
  else if (ret == 1)
    return; // Message incomplete, wait for more data

  ret = response_send(output, conn_ctx, &msg);
  if (ret < 0)
    {
      goto error;
    }

 error:
  rtsp_clear(&msg);
  evbuffer_drain(conn_ctx->pending, evbuffer_get_length(conn_ctx->pending));
  return;
}

static void
in_event_cb(struct bufferevent *bev, short events, void *arg)
{
  struct connection_ctx *conn_ctx = arg;

  if (events & BEV_EVENT_ERROR)
    printf("Error from bufferevent: %s\n", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));

  if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
    bufferevent_free(bev);

  connection_free(conn_ctx);
}


/*-------------------------  General server stuff ----------------------------*/

static void
in_accept_cb(struct evconnlistener *listener, evutil_socket_t sock, struct sockaddr *address, int socklen, void *ctx)
{
  struct event_base *base = evconnlistener_get_base(listener);
  struct bufferevent *bev = bufferevent_socket_new(base, sock, BEV_OPT_CLOSE_ON_FREE);
  struct connection_ctx *conn_ctx;

  conn_ctx = calloc(1, sizeof(struct connection_ctx));
  conn_ctx->pending = evbuffer_new();

  bufferevent_setcb(bev, in_read_cb, NULL, in_event_cb, conn_ctx);
  bufferevent_enable(bev, EV_READ | EV_WRITE);

  printf("New connection accepted\n");
}

static void
in_error_cb(struct evconnlistener *listener, void *ctx)
{
  int err = EVUTIL_SOCKET_ERROR();
  printf("Error occured %d (%s) on the listener\n", err, evutil_socket_error_to_string(err));
}

static struct evconnlistener *
listen_add(struct event_base *evbase, evconnlistener_cb req_cb, evconnlistener_errorcb err_cb, unsigned short port)
{
  struct evconnlistener *listener;
  struct addrinfo hints = { 0 };
  struct addrinfo *servinfo;
  char strport[8];
  int ret;

  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_PASSIVE;

  snprintf(strport, sizeof(strport), "%hu", port);
  ret = getaddrinfo(NULL, strport, &hints, &servinfo);
  if (ret < 0)
    {
      printf("getaddrinf() failed: %s\n", gai_strerror(ret));
      return NULL;
    }

  listener = evconnlistener_new_bind(evbase, req_cb, NULL, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1, servinfo->ai_addr, servinfo->ai_addrlen);
  freeaddrinfo(servinfo);
  if (!listener)
    {
      printf("Could not create listener for port %hu\n", port);
      return NULL;
    }

  evconnlistener_set_error_cb(listener, err_cb);

  return listener;
}

int
main(int argc, char * argv[])
{
  struct event_base *evbase;
  struct evconnlistener *listener;

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

  listener = listen_add(evbase, in_accept_cb, in_error_cb, LISTEN_PORT);
  if (!listener)
    return -1;

  printf("Listening for pairing requests on port %d\n", LISTEN_PORT);

  event_base_dispatch(evbase);

  evconnlistener_free(listener);
  event_base_free(evbase);

  return 0;
}
