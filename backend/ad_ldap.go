package backend

import (
	"fmt"
	"log"
	"strings"

	ad "github.com/korylprince/go-ad-auth/v3"
)

// AdLdap is a backend to do LDAP authentication
type AdLdap struct {
	cfg        *ad.Config
	domainName string
}

// NewAdLdap returns a new ldap backend based on go-ad-auth/v3
func NewAdLdap(server string, port int, baseDN string, domainName string) *AdLdap {
	return &AdLdap{
		cfg: &ad.Config{
			Server:   server,
			Port:     port,
			BaseDN:   baseDN,
			Security: ad.SecurityStartTLS,
		},
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
	log.Printf("LDAP check %s is groups %v on %s", upn, authGroups, l.cfg.Server)
	status, _, groups, err := ad.AuthenticateExtended(l.cfg, upn, password, []string{"SamAccountName"}, authGroups)
	if err != nil {
		return false, err
	}

	if !status {
		return false, fmt.Errorf("Wrong user or password")
	}
	if len(groups) == 0 && len(authGroups) > 0 {
		return false, fmt.Errorf("Not in group %v", authGroups)
	}

	log.Printf("User %s successfully authorised by %v\n", upn, groups)
	return true, nil
}
