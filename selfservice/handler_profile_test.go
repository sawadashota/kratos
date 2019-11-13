package selfservice_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/viper"
	"github.com/ory/x/httpx"
	"github.com/ory/x/urlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/driver/configuration"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/sdk/go/kratos/client"
	"github.com/ory/kratos/sdk/go/kratos/client/public"
	"github.com/ory/kratos/sdk/go/kratos/models"
	. "github.com/ory/kratos/selfservice"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
)

func init() {
	internal.RegisterFakes()
}

func TestUpdateProfile(t *testing.T) {
	_, reg := internal.NewMemoryRegistry(t)

	kratos, sess := func() (*httptest.Server, *session.Session) {
		router := x.NewRouterPublic()
		reg.StrategyHandler().RegisterPublicRoutes(router)
		route, sess := session.MockSessionCreateHandler(t, reg)
		router.GET("/setSession", route)

		other, _ := session.MockSessionCreateHandler(t, reg)
		router.GET("/setSession/other-user", other)

		return httptest.NewServer(router), sess
	}()
	defer kratos.Close()

	ui := func() *httptest.Server {
		router := httprouter.New()
		router.GET("/profile", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
			w.WriteHeader(http.StatusNoContent)
		})
		router.GET("/login", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
			w.WriteHeader(http.StatusUnauthorized)
		})
		return httptest.NewServer(router)
	}()
	defer ui.Close()

	viper.Set(configuration.ViperKeyURLsSelfPublic, kratos.URL)
	viper.Set(configuration.ViperKeyURLsProfile, ui.URL+"/profile")
	viper.Set(configuration.ViperKeyURLsLogin, ui.URL+"/login")

	t.Run("description=call endpoints without session set results in an error", func(t *testing.T) {
		for k, tc := range []*http.Request{
			httpx.MustNewRequest("GET", kratos.URL+BrowserProfilePath, nil, ""),
			httpx.MustNewRequest("GET", kratos.URL+BrowserProfileRequestPath, nil, ""),
			httpx.MustNewRequest("PUT", kratos.URL+BrowserProfilePath, strings.NewReader(url.Values{"foo": {"bar"}}.Encode()), "application/x-www-form-urlencoded"),
			httpx.MustNewRequest("PUT", kratos.URL+BrowserProfilePath, strings.NewReader(`{"foo":"bar"}`), "application/json"),
		} {
			t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
				res, err := http.DefaultClient.Do(tc)
				require.NoError(t, err)
				assert.EqualValues(t, 401, res.StatusCode)
			})
		}
	})

	primaryUser := func() *http.Client {
		c := session.MockCookieClient(t)
		session.MockHydrateCookieClient(t, c, kratos.URL+"/setSession")
		return c
	}()

	otherUser := func() *http.Client {
		c := session.MockCookieClient(t)
		session.MockHydrateCookieClient(t, c, kratos.URL+"/setSession/other-user")
		return c
	}()

	kratosClient := client.NewHTTPClientWithConfig(
		nil,
		&client.TransportConfig{Host: urlx.ParseOrPanic(kratos.URL).Host, BasePath: "/", Schemes: []string{"http"}},
	)

	t.Run("description=fetching a non-existent request should return a 404 error", func(t *testing.T) {
		_, err := kratosClient.Public.GetProfileManagementRequest(
			public.NewGetProfileManagementRequestParams().WithHTTPClient(otherUser).WithRequest("i-do-not-exist"),
		)
		require.Error(t, err)
		assert.Equal(t, http.StatusNotFound, err.(*runtime.APIError).Code)
	})

	t.Run("description=should fail to fetch request if identity changed", func(t *testing.T) {
		res, err := primaryUser.Get(kratos.URL + BrowserProfilePath)
		require.NoError(t, err)

		rid := res.Request.URL.Query().Get("request")
		require.NotEmpty(t, rid)

		rs, err := kratosClient.Public.GetProfileManagementRequest(
			public.NewGetProfileManagementRequestParams().WithHTTPClient(otherUser).WithRequest(rid),
		)
		require.Error(t, err, "%s: %+v", rid, rs)
	})

	t.Run("description=should redirect and return a proper request response", func(t *testing.T) {
		res, err := primaryUser.Get(kratos.URL + BrowserProfilePath)
		require.NoError(t, err)

		assert.Equal(t, ui.URL, res.Request.URL.Scheme+"://"+res.Request.URL.Host)
		assert.Equal(t, "/profile", res.Request.URL.Path, "should end up at the profile URL")

		rid := res.Request.URL.Query().Get("request")
		require.NotEmpty(t, rid)

		pr, err := kratosClient.Public.GetProfileManagementRequest(
			public.NewGetProfileManagementRequestParams().WithHTTPClient(primaryUser).WithRequest(rid),
		)
		require.NoError(t, err, "%s", rid)

		assert.Equal(t, rid, pr.Payload.ID)
		assert.NotEmpty(t, pr.Payload.Identity)
		assert.Empty(t, pr.Payload.Identity.Credentials)
		assert.Equal(t, sess.Identity.ID, *(pr.Payload.Identity.ID))
		assert.JSONEq(t, string(sess.Identity.Traits), x.MustEncodeJSON(t, pr.Payload.Identity.Traits))
		assert.Equal(t, sess.Identity.TraitsSchemaURL, pr.Payload.Identity.TraitsSchemaURL)
		assert.Equal(t, kratos.URL+BrowserProfilePath, pr.Payload.RequestURL)

		assert.Equal(t, &models.ProfileRequestForm{
			Action: kratos.URL + BrowserProfilePath,
			Method: "POST",
			Fields: models.FormFields{
				"traits.baz": models.FormField{Name: "traits.baz", Required: false, Type: "text", Value: "bar", Error: nil},
				"traits.bar": models.FormField{Name: "traits.bar", Required: false, Type: "number", Value: json.Number("2.5"), Error: nil},
				"traits.foo": models.FormField{Name: "traits.foo", Required: false, Type: "checkbox", Value: true, Error: nil},
			},
		}, pr.Payload.Form)
	})

	t.Run("description=should redirect and come back with a form error", func(t *testing.T) {
	})
}
