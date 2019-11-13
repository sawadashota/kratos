package selfservice

import (
	"net/http"
	"net/url"

	"github.com/julienschmidt/httprouter"
	"github.com/justinas/nosurf"
	"github.com/pkg/errors"

	"github.com/ory/x/urlx"

	"github.com/ory/kratos/driver/configuration"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/errorx"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
)

const (
	BrowserLoginPath                = "/auth/browser/login"
	BrowserLoginRequestsPath        = "/auth/browser/requests/login"
	BrowserRegistrationPath         = "/auth/browser/registration"
	BrowserRegistrationRequestsPath = "/auth/browser/requests/registration"
	BrowserLogoutPath               = "/auth/browser/logout"
	BrowserProfilePath              = "/profiles"
	BrowserProfileRequestPath       = "/profiles/requests"
)

type StrategyHandlerDependencies interface {
	StrategyProvider

	LoginExecutionProvider
	RegistrationExecutionProvider

	LoginRequestManagementProvider
	RegistrationRequestManagementProvider
	ProfileRequestManagementProvider

	RequestErrorHandlerProvider

	identity.PoolProvider
	identity.ValidationProvider

	session.ManagementProvider
	session.HandlerProvider
	errorx.ManagementProvider
	x.WriterProvider

	x.CSRFProvider
}

type StrategyHandler struct {
	c  configuration.Provider
	d  StrategyHandlerDependencies
	cg CSRFGenerator
}

type StrategyHandlerProvider interface {
	StrategyHandler() *StrategyHandler
}

func NewStrategyHandler(d StrategyHandlerDependencies, c configuration.Provider) *StrategyHandler {
	return &StrategyHandler{
		cg: nosurf.Token,
		d:  d,
		c:  c,
	}
}

func (h *StrategyHandler) RegisterPublicRoutes(public *x.RouterPublic) {
	public.GET(BrowserLoginPath, h.d.SessionHandler().IsNotAuthenticated(h.initLoginRequest, session.RedirectOnAuthenticated(h.c)))
	public.GET(BrowserLoginRequestsPath, h.fetchLoginRequest)

	public.GET(BrowserRegistrationPath, h.d.SessionHandler().IsNotAuthenticated(h.initRegistrationRequest, session.RedirectOnAuthenticated(h.c)))
	public.GET(BrowserRegistrationRequestsPath, h.fetchRegistrationRequest)

	public.GET(BrowserLogoutPath, h.logout)

	public.GET(BrowserProfilePath, h.d.SessionHandler().IsAuthenticated(h.initUpdateProfile, session.RedirectOnUnauthenticated(h.c)))
	public.GET(BrowserProfileRequestPath, h.d.SessionHandler().IsAuthenticated(h.fetchUpdateProfileRequest, session.RedirectOnUnauthenticated(h.c)))
	public.POST(BrowserProfilePath, h.d.SessionHandler().IsAuthenticated(h.completeProfileManagementFlow, session.RedirectOnUnauthenticated(h.c)))
	public.PUT(BrowserProfilePath, h.d.SessionHandler().IsAuthenticated(h.completeProfileManagementFlow, session.RedirectOnUnauthenticated(h.c)))

	for _, s := range h.d.SelfServiceStrategies() {
		s.SetRoutes(public)
	}
}

func (h *StrategyHandler) NewLoginRequest(w http.ResponseWriter, r *http.Request, redir func(request *LoginRequest) string) error {
	a := NewLoginRequest(h.c.SelfServiceLoginRequestLifespan(), r)
	for _, s := range h.d.SelfServiceStrategies() {
		if err := s.PopulateLoginMethod(r, a); err != nil {
			return err
		}
	}

	if err := h.d.LoginExecutor().PreLoginHook(w, r, a); err != nil {
		if errors.Cause(err) == ErrBreak {
			return nil
		}
		return err
	}

	if err := h.d.LoginRequestManager().CreateLoginRequest(r.Context(), a); err != nil {
		return err
	}

	http.Redirect(w,
		r,
		redir(a),
		http.StatusFound,
	)

	return nil
}

func (h *StrategyHandler) NewRegistrationRequest(w http.ResponseWriter, r *http.Request, redir func(*RegistrationRequest) string) error {
	a := NewRegistrationRequest(h.c.SelfServiceRegistrationRequestLifespan(), r)
	for _, s := range h.d.SelfServiceStrategies() {
		if err := s.PopulateRegistrationMethod(r, a); err != nil {
			return err
		}
	}

	if err := h.d.RegistrationExecutor().PreRegistrationHook(w, r, a); err != nil {
		if errors.Cause(err) == ErrBreak {
			return nil
		}
		return err
	}

	if err := h.d.RegistrationRequestManager().CreateRegistrationRequest(r.Context(), a); err != nil {
		return err
	}

	http.Redirect(w,
		r,
		redir(a),
		http.StatusFound,
	)

	return nil
}

// swagger:route GET /auth/browser/login public initializeLoginFlow
//
// Initialize a Login Flow
//
// This endpoint initializes a login flow. This endpoint **should not be called from a programatic API**
// but instead for the, for example, browser. It will redirect the user agent (e.g. browser) to the
// configured login UI, appending the login challenge.
//
// If the user-agent already has a valid authentication session, the server will respond with a 302
// code redirecting to the config value of `urls.default_return_to`.
//
// For an in-depth look at ORY Krato's login flow, head over to: https://www.ory.sh/docs/kratos/selfservice/login
//
//     Schemes: http, https
//
//     Responses:
//       302: emptyResponse
//       500: genericError
func (h *StrategyHandler) initLoginRequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if err := h.NewLoginRequest(w, r, func(a *LoginRequest) string {
		return urlx.CopyWithQuery(h.c.LoginURL(), url.Values{"request": {a.ID}}).String()
	}); err != nil {
		h.d.ErrorManager().ForwardError(r.Context(), w, r, err)
		return
	}
}

// swagger:route GET /auth/browser/requests/login public getLoginRequest
//
// Get Login Request
//
// This endpoint returns a login request's context with, for example, error details and
// other information.
//
// For an in-depth look at ORY Krato's login flow, head over to: https://www.ory.sh/docs/kratos/selfservice/login
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: loginRequest
//       302: emptyResponse
//       500: genericError
func (h *StrategyHandler) fetchLoginRequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ar, err := h.d.LoginRequestManager().GetLoginRequest(r.Context(), r.URL.Query().Get("request"))
	if err != nil {
		h.d.Writer().WriteError(w, r, err)
		return
	}

	h.d.Writer().Write(w, r, ar.Declassify())
}

func (h *StrategyHandler) logout(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	_ = h.d.CSRFHandler().RegenerateToken(w, r)

	if err := h.d.SessionManager().PurgeFromRequest(r.Context(), w, r); err != nil {
		h.d.ErrorManager().ForwardError(r.Context(), w, r, err)
		return
	}

	http.Redirect(w, r, h.c.SelfServiceLogoutRedirectURL().String(), http.StatusFound)
}

// swagger:route GET /auth/browser/registration public initializeRegistrationFlow
//
// Initialize a Registration Flow
//
// This endpoint initializes a registration flow. This endpoint **should not be called from a programatic API**
// but instead for the, for example, browser. It will redirect the user agent (e.g. browser) to the
// configured registration UI, appending the registration challenge.
//
// For an in-depth look at ORY Krato's registration flow, head over to: https://www.ory.sh/docs/kratos/selfservice/registration
//
//     Schemes: http, https
//
//     Responses:
//       302: emptyResponse
//       404: genericError
//       500: genericError
func (h *StrategyHandler) initRegistrationRequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if err := h.NewRegistrationRequest(w, r, func(a *RegistrationRequest) string {
		return urlx.CopyWithQuery(h.c.RegisterURL(), url.Values{"request": {a.ID}}).String()
	}); err != nil {
		h.d.ErrorManager().ForwardError(r.Context(), w, r, err)
		return
	}
}

// swagger:route GET /auth/browser/requests/registration public getRegistrationRequest
//
// Get Registration Request
//
// This endpoint returns a registration request's context with, for example, error details and
// other information.
//
// For an in-depth look at ORY Krato's registration flow, head over to: https://www.ory.sh/docs/kratos/selfservice/registration
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: registrationRequest
//       404: genericError
//       500: genericError
func (h *StrategyHandler) fetchRegistrationRequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ar, err := h.d.RegistrationRequestManager().GetRegistrationRequest(r.Context(), r.URL.Query().Get("request"))
	if err != nil {
		h.d.Writer().WriteError(w, r, err)
		return
	}

	h.d.Writer().Write(w, r, ar.Declassify())
}
