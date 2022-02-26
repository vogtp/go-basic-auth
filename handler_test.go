package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type userPass struct {
	user, pass string
}

var creds = []userPass{
	{"asda", "zfjdz"},
	{"adsfdf", "ctfjhtthcrtvrrstvetrv"},
	{"dsf", "sctrcetrtctr"},
	{"xyvc", "scct4rctrc"},
	{"asdfsaf", "sct4rrtcr"},
}

func TestBasicAuthHandler(t *testing.T) {
	u0NoPw := creds[0]
	u0NoPw.pass = ""
	tests := []struct {
		name      string
		userAllow []userPass
		userAuth  userPass
		succ      bool
	}{
		{"creds: u0", creds, creds[0], true},
		{"creds: u1", creds, creds[1], true},
		{"creds[3:]: u3", creds[3:], creds[3], true},
		{"creds[3:]: u2", creds[3:], creds[2], false},
		{"creds[2:]: u0", creds[2:], creds[0], false},
		{"creds[1:]: u3", creds[1:], creds[3], true},
		{"creds[]: u0NoPw", creds, u0NoPw, false},
		{"creds[0:]: u0", creds[:0], creds[0], false},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.SetBasicAuth(tc.userAuth.user, tc.userAuth.pass)

			rr := httptest.NewRecorder()
			allow := make(map[string]string)
			for _, c := range tc.userAllow {
				allow[c.user] = c.pass
			}
			ba := BasicAuth(WithInMemory(allow), Debug())
			hanlderCalled := false
			handler := http.HandlerFunc(ba.Handler(func(rw http.ResponseWriter, r *http.Request) { hanlderCalled = true }))

			handler.ServeHTTP(rr, req)
			if hanlderCalled != tc.succ {
				t.Errorf("test case %d: handler called: %v", i, tc.succ)
			}
			wantStatus := http.StatusOK
			if !tc.succ {
				wantStatus = http.StatusUnauthorized
			}
			if status := rr.Code; status != wantStatus {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, http.StatusOK)
			}
		})
	}

}

func TestGinHandler(t *testing.T) {
	u0NoPw := creds[0]
	u0NoPw.pass = ""
	tests := []struct {
		name      string
		userAllow []userPass
		userAuth  userPass
		succ      bool
	}{
		{"creds: u0", creds, creds[0], true},
		{"creds: u1", creds, creds[1], true},
		{"creds[3:]: u3", creds[3:], creds[3], true},
		{"creds[3:]: u2", creds[3:], creds[2], false},
		{"creds[2:]: u0", creds[2:], creds[0], false},
		{"creds[1:]: u3", creds[1:], creds[3], true},
		{"creds[]: u0NoPw", creds, u0NoPw, false},
		{"creds[0:]: u0", creds[:0], creds[0], false},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.SetBasicAuth(tc.userAuth.user, tc.userAuth.pass)

			rr := httptest.NewRecorder()
			allow := make(map[string]string)
			for _, c := range tc.userAllow {
				allow[c.user] = c.pass
			}
			ba := New(WithInMemory(allow), Debug())
			g := gin.Default()
			g.Use(ba.GinHandler())
			hanlderCalled := false
			g.GET("/", func(c *gin.Context) { hanlderCalled = true })

			g.ServeHTTP(rr, req)
			if hanlderCalled != tc.succ {
				t.Errorf("test case %d: handler called: %v", i, tc.succ)
			}
			wantStatus := http.StatusOK
			if !tc.succ {
				wantStatus = http.StatusUnauthorized
			}
			if status := rr.Code; status != wantStatus {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, http.StatusOK)
			}
		})
	}

}
