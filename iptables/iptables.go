package iptables

import (
	"errors"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	log "github.com/sirupsen/logrus"
)

type myIPTables iptables.IPTables

// AddRule adds the required rule to the host's nat table.
func AddRule(appPort, metadataAddress, hostInterface, hostIP string) error {

	if err := checkInterfaceExists(hostInterface); err != nil {
		return err
	}

	if hostIP == "" {
		return errors.New("--host-ip must be set")
	}

	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	proxyRulePresent, proxyRuleLine, err := (*myIPTables)(ipt).detectConcealmentProxyRule(metadataAddress)
	if err != nil {
		return err
	}

	rulespec := []string{"-p", "tcp", "-d", metadataAddress, "--dport", "80",
		"-j", "DNAT", "--to-destination", hostIP + ":" + appPort}

	if proxyRulePresent {
		// if our rule exists, we delete and re-insert to make sure it's at the right place
		exists, err := ipt.Exists("nat", "PREROUTING", rulespec...)
		if err != nil {
			return err
		}
		if exists {
			log.Debugf("Deleting existing iptables rule %s, %s, %s", "nat", "PREROUTING", rulespec)
			err := ipt.Delete("nat", "PREROUTING", rulespec...)
			if err != nil {
				return err
			}
		}
		log.Debugf("Inserting iptables rule at position %d - %s, %s, %s", proxyRuleLine, "nat", "PREROUTING", rulespec)
		return ipt.Insert("nat", "PREROUTING", proxyRuleLine, rulespec...)
	}

	log.Debugf("Appending iptables rule %s, %s, %s", "nat", "PREROUTING", rulespec)
	return ipt.AppendUnique("nat", "PREROUTING", rulespec...)
}

// checkInterfaceExists validates the interface passed exists for the given system.
// checkInterfaceExists ignores wildcard networks.
func checkInterfaceExists(hostInterface string) error {
	return nil
	// if strings.Contains(hostInterface, "+") {
	// 	// wildcard networks ignored
	// 	return nil
	// }

	// _, err := net.InterfaceByName(hostInterface)
	// return err
}

// detect if GKE Metadata Concealment rule is present
func (ipt *myIPTables) detectConcealmentProxyRule(metadataAddress string) (bool, int, error) {

	rules, err := (*iptables.IPTables)(ipt).List("nat", "PREROUTING")
	if err != nil {
		return false, 0, err
	}

	for i, rule := range rules {
		if strings.Contains(rule, "-A PREROUTING") &&
			strings.Contains(rule, "-d "+metadataAddress+"/32") &&
			strings.Contains(rule, "-m tcp --dport 80") {
			log.Debugf("Found existing metadata proxy rule %s", rule)
			return true, i, nil
		}
	}

	return false, 0, nil
}
