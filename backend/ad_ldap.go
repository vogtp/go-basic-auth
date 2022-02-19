package backend

import (
	"fmt"
	"log"
	"strings"

	ad "github.com/korylprince/go-ad-auth/v3"
)

type ldapBackend struct {
	cfg        *ad.Config
	domainName string
}

func NewAdLdap(server, baseDN, domainName string) *ldapBackend {
	return &ldapBackend{
		cfg: &ad.Config{
			Server:   server,
			Port:     389,
			BaseDN:   baseDN,
			Security: ad.SecurityStartTLS,
		},
		domainName: domainName,
	}
}

func (l ldapBackend) Authenticate(upn string, password string, authGroups []string) (bool, error) {
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
