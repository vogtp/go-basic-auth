package backend

import (
	"fmt"
	"strings"

	ad "github.com/korylprince/go-ad-auth/v3"
	"github.com/vogtp/go-hcl"
)

var log = hcl.Named("basic-auth.ldap")

type ldap interface {
	Authenticate(name string, password string, authGroups []string) (status bool, userGroups []string, err error)
}

// AdLdap is a backend to do LDAP authentication
type AdLdap struct {
	server     string
	domainName string
	ldap       ldap
}

// NewAdLdap returns a new ldap backend based on go-ad-auth/v3
func NewAdLdap(server string, port int, baseDN string, domainName string) *AdLdap {
	ldap := ldapImp{
		cfg: &ad.Config{
			Server:   server,
			Port:     port,
			BaseDN:   baseDN,
			Security: ad.SecurityStartTLS,
		},
	}
	return &AdLdap{
		server:     server,
		ldap:       ldap,
		domainName: domainName,
	}
}

// Authenticate does the authentication
func (l AdLdap) Authenticate(upn string, password string, authGroups []string) (bool, error) {
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

type ldapImp struct {
	cfg *ad.Config
}

func (l ldapImp) Authenticate(name string, password string, authGroups []string) (status bool, userGroups []string, err error) {
	status, _, groups, err := ad.AuthenticateExtended(l.cfg, name, password, []string{"SamAccountName"}, authGroups)
	return status, groups, err
}
