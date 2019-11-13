package selfservice

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/x/urlx"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/session"
)

func TestRequest(t *testing.T) {
	type i interface {
		Valid() error
		GetID() string
	}
	type f func(exp time.Duration) i

	for _, r := range []f{
		func(exp time.Duration) i {
			return NewLoginRequest(exp, &http.Request{URL: urlx.ParseOrPanic("/")})
		},
		func(exp time.Duration) i {
			return NewRegistrationRequest(exp, &http.Request{URL: urlx.ParseOrPanic("/")})
		},
	} {
		assert.NotEmpty(t, r(0).GetID())
		assert.NoError(t, r(time.Minute).Valid())
		assert.Error(t, r(-time.Minute).Valid())
	}
}

func TestProfileRequest(t *testing.T) {
	for k, tc := range []struct {
		r         *ProfileManagementRequest
		s         *session.Session
		expectErr bool
	}{
		{
			r: NewProfileRequest(
				time.Hour,
				&http.Request{URL: urlx.ParseOrPanic("http://foo/bar/baz"), Host: "foo"},
				&session.Session{Identity: &identity.Identity{ID: "alice"}},
			),
			s: &session.Session{Identity: &identity.Identity{ID: "alice"}},
		},
		{
			r: NewProfileRequest(
				time.Hour,
				&http.Request{URL: urlx.ParseOrPanic("http://foo/bar/baz"), Host: "foo"},
				&session.Session{Identity: &identity.Identity{ID: "alice"}},
			),
			s:         &session.Session{Identity: &identity.Identity{ID: "malice"}},
			expectErr: true,
		},
		{
			r: NewProfileRequest(
				-time.Hour,
				&http.Request{URL: urlx.ParseOrPanic("http://foo/bar/baz"), Host: "foo"},
				&session.Session{Identity: &identity.Identity{ID: "alice"}},
			),
			s:         &session.Session{Identity: &identity.Identity{ID: "alice"}},
			expectErr: true,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			err := tc.r.Valid(tc.s)
			if tc.expectErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}
