package backend

import (
	"fmt"
	"testing"
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

func TestInMemory(t *testing.T) {
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
	for _, tc := range tests {
		t.Run("memory"+tc.name, func(t *testing.T) {

			allow := make(map[string]string)
			for _, c := range tc.userAllow {
				allow[c.user] = c.pass
			}
			mem := NewInMemory(allow)

			auth, err := mem.Authenticate(tc.userAuth.user, tc.userAuth.pass, nil)
			if tc.succ && err != nil {
				t.Errorf("Auth err: %v", err)
			}
			if !tc.succ && err == nil {
				t.Errorf("Usuccessfull auth should report as an error")
			}
			if auth != tc.succ {
				t.Errorf("Auth went wrong: %v!=%v", tc.succ, auth)
			}

		})
	}
}

type mockLdap struct {
	mem *InMemory
}

func (l mockLdap) Authenticate(name string, password string, authGroups []string) (status bool, userGroups []string, err error) {
	status, err = l.mem.Authenticate(name, password, authGroups)
	return status, nil, err
}

func TestAdLdap(t *testing.T) {
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
	testdomain := "testdomain"
	adLdap := NewAdLdap("mockLdap", 0, "baseDN", testdomain)
	adLdap.Authenticate("", "", nil)
	for _, tc := range tests {
		t.Run("ldap"+tc.name, func(t *testing.T) {

			allow := make(map[string]string)
			for _, c := range tc.userAllow {
				u := fmt.Sprintf("%s\\%s", testdomain, c.user)
				allow[u] = c.pass
			}
			adLdap.ldap = mockLdap{mem: NewInMemory(allow)}

			auth, err := adLdap.Authenticate(tc.userAuth.user, tc.userAuth.pass, nil)
			if tc.succ && err != nil {
				t.Errorf("Auth err: %v", err)
			}
			if !tc.succ && err == nil {
				t.Errorf("Usuccessfull auth should report as an error")
			}
			if auth != tc.succ {
				t.Errorf("Auth went wrong: %v!=%v", tc.succ, auth)
			}

		})
	}
	allow := make(map[string]string)
	for _, c := range creds {
		u := fmt.Sprintf("%s\\%s", testdomain, c.user)
		allow[u] = c.pass
	}
	adLdap.ldap = mockLdap{mem: NewInMemory(allow)}

	auth, err := adLdap.Authenticate(creds[0].user, creds[0].pass, []string{"myGroup"})
	if err == nil {
		t.Errorf("Usuccessfull auth should report as an error")
	}
	if auth {
		t.Errorf("Auth should go wrong there are no groups")
	}

}
