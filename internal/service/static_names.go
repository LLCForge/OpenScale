package service

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/node"
)

// SplitStaticEndpoints parses static endpoints that may be given as
// "IP:port" or, for a dynamic DNS name, "name:port" (#387). IP entries are
// checked like ParseStaticEndpoints; names like node.New. The total is
// bounded by the candidate limit.
func SplitStaticEndpoints(in []string) ([]netip.AddrPort, []string, error) {
	if len(in) > control.MaxCandidates {
		return nil, nil, fmt.Errorf("en fazla %d statik uç nokta tanımlanabilir", control.MaxCandidates)
	}
	var ips, names []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if _, err := netip.ParseAddrPort(s); err == nil || strings.HasPrefix(s, "[") {
			ips = append(ips, s)
			continue
		}
		if _, _, err := node.ValidStaticEndpointName(s); err != nil {
			if !strings.Contains(s, ":") {
				return nil, nil, fmt.Errorf("statik uç nokta %q IP:port veya ad:port biçiminde olmalı", s)
			}
			return nil, nil, err
		}
		names = append(names, s)
	}
	eps, err := ParseStaticEndpoints(ips)
	if err != nil {
		return nil, nil, err
	}
	return eps, names, nil
}
