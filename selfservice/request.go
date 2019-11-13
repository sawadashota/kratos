package selfservice

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/ory/herodot"
	"github.com/pkg/errors"

	"github.com/ory/x/urlx"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/session"
)

type RequestMethodConfig interface {
	Reset()
	AddError(err *FormError)
	GetFormFields() FormFields
}

type RequestMethod interface {
	GetConfig() RequestMethodConfig
}

type DefaultRequestMethod struct {
	Method identity.CredentialsType `json:"method"`
	Config RequestMethodConfig      `json:"config"`
}

// swagger:model registrationRequest
type RegistrationRequest struct{ *Request }

func NewRegistrationRequest(exp time.Duration, r *http.Request) *RegistrationRequest {
	return &RegistrationRequest{Request: newRequestFromHTTP(exp, r)}
}

func (r *RegistrationRequest) Valid() error {
	if r.ExpiresAt.Before(time.Now()) {
		return errors.WithStack(ErrRegistrationRequestExpired.WithReasonf("The registration request expired %.2f minutes ago, please try again.", time.Since(r.ExpiresAt).Minutes()))
	}
	return nil
}

// swagger:model loginRequest
type LoginRequest struct{ *Request }

func NewLoginRequest(exp time.Duration, r *http.Request) *LoginRequest {
	return &LoginRequest{Request: newRequestFromHTTP(exp, r)}
}

func (r *LoginRequest) Valid() error {
	if r.ExpiresAt.Before(time.Now()) {
		return errors.WithStack(ErrLoginRequestExpired.WithReasonf("The login request expired %.2f minutes ago, please try again.", time.Since(r.ExpiresAt).Minutes()))
	}
	return nil
}

// ProfileManagementRequest presents a profile management request
//
// This request is used when an identity wants to update profile information
// (especially traits) in a selfservice manner.
//
// For more information head over to: https://www.ory.sh/docs/kratos/selfservice/profile
//
// swagger:model profileManagementRequest
type ProfileManagementRequest struct {
	ID         string    `json:"id"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	RequestURL string    `json:"request_url"`
	identityID string    `json:"-"`

	Form     *ProfileRequestForm `json:"form"`
	Identity *identity.Identity  `json:"identity"`
}

type ProfileRequestForm struct {
	// Action should be used as the form action URL (<form action="{{ .Action }}" method="post">).
	Action string `json:"action"`

	// Method is the form method (e.g. POST)
	Method string `json:"method"`

	// Errors contains all form errors. These will be duplicates of the individual field errors.
	Errors []FormError `json:"errors,omitempty"`

	// Fields contains the form fields.
	Fields FormFields `json:"fields"`
}

func NewProfileRequest(exp time.Duration, r *http.Request, s *session.Session) *ProfileManagementRequest {
	req := newRequestFromHTTP(exp, r)
	return &ProfileManagementRequest{
		ID:         req.ID,
		IssuedAt:   req.IssuedAt,
		ExpiresAt:  req.ExpiresAt,
		RequestURL: req.RequestURL,
		identityID: s.Identity.ID,
	}
}

func (r *ProfileManagementRequest) Valid(s *session.Session) error {
	if r.ExpiresAt.Before(time.Now()) {
		return errors.WithStack(ErrProfileRequestExpired.WithReasonf("The profile request expired %.2f minutes ago, please try again.", time.Since(r.ExpiresAt).Minutes()))
	}
	if r.identityID != s.Identity.ID {
		return errors.WithStack(herodot.ErrBadRequest.WithReasonf("The profile request expired %.2f minutes ago, please try again", time.Since(r.ExpiresAt).Minutes()))
	}
	return nil
}

type Request struct {
	ID             string                                             `json:"id"`
	IssuedAt       time.Time                                          `json:"issued_at"`
	ExpiresAt      time.Time                                          `json:"expires_at"`
	RequestURL     string                                             `json:"request_url"`
	RequestHeaders http.Header                                        `json:"headers"`
	Active         identity.CredentialsType                           `json:"active,omitempty"`
	Methods        map[identity.CredentialsType]*DefaultRequestMethod `json:"methods" faker:"-"`
}

func (r *Request) GetID() string {
	return r.ID
}

// Declassify returns a copy of the Request where all sensitive information
// such as request headers is removed.
func (r *Request) Declassify() *Request {
	rr := *r
	rr.RequestHeaders = http.Header{}
	return &rr
}

func newRequestFromHTTP(exp time.Duration, r *http.Request) *Request {
	source := urlx.Copy(r.URL)
	source.Host = r.Host

	if len(source.Scheme) == 0 {
		source.Scheme = "http"
		if r.TLS != nil {
			source.Scheme = "https"
		}
	}

	return &Request{
		ID:             uuid.New().String(),
		IssuedAt:       time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(exp),
		RequestURL:     source.String(),
		RequestHeaders: r.Header,
		Methods:        map[identity.CredentialsType]*DefaultRequestMethod{},
	}
}
