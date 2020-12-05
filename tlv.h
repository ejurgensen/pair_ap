#ifndef __TLV_H__
#define __TLV_H__

#define TLV_ERROR_MEMORY -1
#define TLV_ERROR_INSUFFICIENT_SIZE -2

typedef enum {
    TLVType_Method = 0,        // (integer) Method to use for pairing. See PairMethod
    TLVType_Identifier = 1,    // (UTF-8) Identifier for authentication
    TLVType_Salt = 2,          // (bytes) 16+ bytes of random salt
    TLVType_PublicKey = 3,     // (bytes) Curve25519, SRP public key or signed Ed25519 key
    TLVType_Proof = 4,         // (bytes) Ed25519 or SRP proof
    TLVType_EncryptedData = 5, // (bytes) Encrypted data with auth tag at end
    TLVType_State = 6,         // (integer) State of the pairing process. 1=M1, 2=M2, etc.
    TLVType_Error = 7,         // (integer) Error code. Must only be present if error code is
                               // not 0. See TLVError
    TLVType_RetryDelay = 8,    // (integer) Seconds to delay until retrying a setup code
    TLVType_Certificate = 9,   // (bytes) X.509 Certificate
    TLVType_Signature = 10,    // (bytes) Ed25519
    TLVType_Permissions = 11,  // (integer) Bit value describing permissions of the controller
                               // being added.
                               // None (0x00): Regular user
                               // Bit 1 (0x01): Admin that is able to add and remove
                               // pairings against the accessory
    TLVType_FragmentData = 13, // (bytes) Non-last fragment of data. If length is 0,
                               // it's an ACK.
    TLVType_FragmentLast = 14, // (bytes) Last fragment of data
    TLVType_Separator = 0xff,
} TLVType;


typedef enum {
  TLVMethod_PairSetup = 1,
  TLVMethod_PairVerify = 2,
  TLVMethod_AddPairing = 3,
  TLVMethod_RemovePairing = 4,
  TLVMethod_ListPairings = 5,
} TLVMethod;


typedef enum {
  TLVError_Unknown = 1,         // Generic error to handle unexpected errors
  TLVError_Authentication = 2,  // Setup code or signature verification failed
  TLVError_Backoff = 3,         // Client must look at the retry delay TLV item and
                                // wait that many seconds before retrying
  TLVError_MaxPeers = 4,        // Server cannot accept any more pairings
  TLVError_MaxTries = 5,        // Server reached its maximum number of
                                // authentication attempts
  TLVError_Unavailable = 6,     // Server pairing method is unavailable
  TLVError_Busy = 7,            // Server is busy and cannot accept a pairing
                                // request at this time
} TLVError;


// Public header

typedef unsigned char byte;

typedef struct _tlv {
    struct _tlv *next;
    byte type;
    byte *value;
    size_t size;
} tlv_t;


typedef struct {
    tlv_t *head;
} tlv_values_t;


tlv_values_t *tlv_new();

void tlv_free(tlv_values_t *values);

int tlv_add_value(tlv_values_t *values, byte type, const byte *value, size_t size);
int tlv_add_string_value(tlv_values_t *values, byte type, const char *value);
int tlv_add_integer_value(tlv_values_t *values, byte type, size_t size, int value);
int tlv_add_tlv_value(tlv_values_t *values, byte type, tlv_values_t *value);

tlv_t *tlv_get_value(const tlv_values_t *values, byte type);
int tlv_get_integer_value(const tlv_values_t *values, byte type, int def);
tlv_values_t *tlv_get_tlv_value(const tlv_values_t *values, byte type);

int tlv_format(const tlv_values_t *values, byte *buffer, size_t *size);

int tlv_parse(const byte *buffer, size_t length, tlv_values_t *values);


// Private header

typedef void (*tlv_flush_callback)(uint8_t *buffer, size_t size, void *context);


typedef struct {
    uint8_t *buffer;
    size_t size;
    size_t pos;

    tlv_flush_callback on_flush;
    void *context;
} tlv_stream_t;


int tlv_stream_init(tlv_stream_t *tlv, byte *buffer, size_t size, tlv_flush_callback on_flush, void *context);
tlv_stream_t *tlv_stream_new(size_t size, tlv_flush_callback on_flush, void *context);
void tlv_stream_free(tlv_stream_t *tlv);
void tlv_stream_set_context(tlv_stream_t *tlv, void *context);

void tlv_stream_flush(tlv_stream_t *tlv);
void tlv_stream_reset(tlv_stream_t *tlv);

int tlv_stream_add_value(tlv_stream_t *tlv, byte type, const byte *data, size_t size);
int tlv_stream_add_string_value(tlv_stream_t *tlv, byte type, const char *value);
int tlv_stream_add_integer_value(tlv_stream_t *tlv, byte type, size_t size, int value);
int tlv_stream_add_tlv_value(tlv_stream_t *tlv, byte type, tlv_values_t *value);


#endif // __TLV_H__
