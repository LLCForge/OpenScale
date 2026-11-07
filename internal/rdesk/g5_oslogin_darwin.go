//go:build darwin && cgo

package rdesk

/*
#cgo LDFLAGS: -lpam
#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	const char *pw;
	size_t len;
} os_secret;

// os_conv answers the password prompt of the PAM modules with the secret
// and every other prompt with nothing.
static int os_conv(int n, const struct pam_message **msg, struct pam_response **resp, void *data) {
	os_secret *s = (os_secret *)data;
	if (n <= 0 || n > 32) {
		return PAM_CONV_ERR;
	}
	struct pam_response *r = calloc((size_t)n, sizeof(struct pam_response));
	if (r == NULL) {
		return PAM_BUF_ERR;
	}
	for (int i = 0; i < n; i++) {
		if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
			char *c = malloc(s->len + 1);
			if (c == NULL) {
				for (int j = 0; j < i; j++) {
					if (r[j].resp != NULL) {
						memset(r[j].resp, 0, strlen(r[j].resp));
						free(r[j].resp);
					}
				}
				free(r);
				return PAM_BUF_ERR;
			}
			memcpy(c, s->pw, s->len);
			c[s->len] = 0;
			r[i].resp = c;
		}
	}
	*resp = r;
	return PAM_SUCCESS;
}

// os_pam_check returns 0 for a valid account, 1 for a refused one and -1
// when PAM could not run.
static int os_pam_check(const char *user, const char *pw, size_t len) {
	os_secret s = { pw, len };
	struct pam_conv conv = { os_conv, &s };
	pam_handle_t *h = NULL;
	int rc = pam_start("authorization", user, &conv, &h);
	if (rc != PAM_SUCCESS) {
		return -1;
	}
	rc = pam_authenticate(h, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK);
	if (rc == PAM_SUCCESS) {
		rc = pam_acct_mgmt(h, PAM_SILENT);
	}
	pam_end(h, rc);
	switch (rc) {
	case PAM_SUCCESS:
		return 0;
	case PAM_AUTH_ERR:
	case PAM_USER_UNKNOWN:
	case PAM_ACCT_EXPIRED:
	case PAM_NEW_AUTHTOK_REQD:
	case PAM_MAXTRIES:
	case PAM_PERM_DENIED:
	case PAM_CRED_INSUFFICIENT:
		return 1;
	}
	return -1;
}
*/
import "C"

import (
	"context"
	"strings"
	"unsafe"
)

// macOS account check through PAM's "authorization" service, which asks
// Open Directory (ADR-0198). Not tried on a real Mac: this repository is
// built and tested on Windows.

// NewSystemVerifier returns the operating system's account check.
func NewSystemVerifier() (OSVerifier, error) {
	return OSVerifierFunc(verifyDarwinAccount), nil
}

func verifyDarwinAccount(ctx context.Context, user string, password []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if user == "" || len(user) > maxLoginUser || strings.ContainsAny(user, "\x00/:") || len(password) == 0 {
		return ErrOSLoginFailed
	}
	for _, b := range password {
		if b == 0 {
			return ErrOSLoginFailed
		}
	}
	cUser := C.CString(user)
	defer C.free(unsafe.Pointer(cUser))
	// C memory for the secret, wiped before it is freed.
	cPw := C.CBytes(password)
	defer func() {
		C.memset(cPw, 0, C.size_t(len(password)))
		C.free(cPw)
	}()
	switch C.os_pam_check(cUser, (*C.char)(cPw), C.size_t(len(password))) {
	case 0:
		return nil
	case 1:
		return ErrOSLoginFailed
	}
	return ErrOSLoginUnavailable
}
