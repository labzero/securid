#ifndef SECURID_H_
#define SECURID_H_

extern ID securid_id_session;

// The internal storage used by RSA::SecurID::Session instances
typedef struct {
  SDI_HANDLE handle;
} securid_session_t;

#endif