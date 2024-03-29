package auth

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
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
		userAuth  *userPass
		succ      bool
	}{
		{"creds: u0", creds, &creds[0], true},
		{"creds: u1", creds, &creds[1], true},
		{"creds[3:]: u3", creds[3:], &creds[3], true},
		{"creds[3:]: u2", creds[3:], &creds[2], false},
		{"creds[2:]: u0", creds[2:], &creds[0], false},
		{"creds[1:]: u3", creds[1:], &creds[3], true},
		{"creds[]: u0NoPw", creds, &u0NoPw, false},
		{"creds[0:]: u0", creds[:0], &creds[0], false},
		{"creds: nouser", creds, nil, false},
		{"nil: u0", nil, &creds[0], false},
		{"nil", nil, nil, false},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.userAuth != nil {
				req.SetBasicAuth(tc.userAuth.user, tc.userAuth.pass)
			}

			rr := httptest.NewRecorder()
			allow := make(map[string]string)
			for _, c := range tc.userAllow {
				allow[c.user] = c.pass
			}
			ba := New(WithInMemory(allow))
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
	// with groups
	tc := tests[0]
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
	ba := New(WithInMemory(allow), WithGroup("grp"), WithFailMsg("test fail"), WithLdap("server", "db", "domain"))
	hanlderCalled := false
	handler := http.HandlerFunc(ba.Handler(func(rw http.ResponseWriter, r *http.Request) { hanlderCalled = true }))

	handler.ServeHTTP(rr, req)
	if hanlderCalled != tc.succ {
		t.Errorf("test case with groups: handler called: %v", tc.succ)
	}
	wantStatus := http.StatusOK
	if !tc.succ {
		wantStatus = http.StatusUnauthorized
	}
	if status := rr.Code; status != wantStatus {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
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
			auth := New(WithInMemory(allow), Debug())
			g := gin.Default()
			g.Use(auth.Gin())
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

func TestNewWithoutBackend(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			return
		}
		t.Error("should have paniced")
	}()
	New()
}

func TestGenerateKey(t *testing.T) {
	for klen := 2; klen < 1024; klen *= 2 {
		name := fmt.Sprintf("Key length %d", klen)
		t.Run(name, func(t *testing.T) {

			k := generateKey(klen)
			if len(k) != klen {
				t.Errorf("Wrong key lenth %d wanted %d", len(k), klen)
			}
		})
	}
	testKey := []byte("someKey")
	os.Remove(keyFile)
	err := ioutil.WriteFile(keyFile, testKey, fs.ModeAppend)
	if err != nil {
		t.Fatalf("Cannot write %s: %v", keyFile, err)
	}
	defer func() { os.Remove(keyFile) }()
	k := generateKey(len(keyFile))
	if reflect.DeepEqual(k, testKey) {
		t.Error("did not read the key from file")
	}
	k = generateKey(len(keyFile) * 2)
	if reflect.DeepEqual(k, testKey) {
		t.Error("this key should not have been used (wrong size)")
	}

	defer func() {
		if r := recover(); r != nil {
			return
		}
		t.Error("should have paniced")
	}()
	// this should panic
	generateKey(1844674407370955161)
}
