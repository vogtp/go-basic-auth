package backend

import (
	"fmt"
	"strings"

	ad "github.com/korylprince/go-ad-auth/v3"
	"github.com/vogtp/go-hcl"
)

var log = hcl.LibraryLogger("basic-auth.ldap")

type ldap interface {
	Authenticate(name string, password string, authGroups []string) (status bool, userGroups []string, err error)
}

// Ldap is a backend to do LDAP authentication
type Ldap struct {
	server     string
	domainName string
	ldap       ldap
}

// NewLdap returns a new ldap backend based on go-ad-auth/v3
func NewLdap(server string, port int, baseDN string, domainName string) *Ldap {
	ldap := adLdap{
		cfg: &ad.Config{
			Server:   server,
			Port:     port,
			BaseDN:   baseDN,
			Security: ad.SecurityStartTLS,
		},
	}
	return &Ldap{
		server:     server,
		ldap:       ldap,
		domainName: domainName,
	}
}

// Authenticate does the authentication
func (l Ldap) Authenticate(upn string, password string, authGroups []string) (bool, error) {
	if !strings.Contains(upn, "@") && !strings.HasPrefix(upn, l.domainName) {
		s := fmt.Sprintf("%s\\%s", l.domainName, upn)
		log.Printf("prefixing user %s with %s -> %s", upn, l.domainName, s)
		upn = s
	}
	log.Printf("LDAP check %s is groups %v on %s", upn, authGroups, l.server)
	status, groups, err := l.ldap.Authenticate(upn, password, authGroups)
	if err != nil {
		return false, err
	}
	if !status {
		return false, fmt.Errorf("Wrong user %s or password", upn)
	}
	if len(groups) == 0 && len(authGroups) > 0 {
		return false, fmt.Errorf("Not in group %v", authGroups)
	}

	log.Printf("User %s successfully authorised by %v\n", upn, groups)
	return status, nil
}

type adLdap struct {
	cfg *ad.Config
}

func (l adLdap) Authenticate(name string, password string, authGroups []string) (status bool, userGroups []string, err error) {
	status, _, groups, err := ad.AuthenticateExtended(l.cfg, name, password, []string{"SamAccountName"}, authGroups)
	return status, groups, err
}
