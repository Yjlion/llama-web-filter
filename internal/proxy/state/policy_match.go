package state

import (
	"net"
	"strings"
	"time"

	"github.com/yjlion/llama-web-filter/internal/models"
)

const (
	PolicyMatchNone     = "none"
	PolicyMatchMAC      = "mac"
	PolicyMatchExactIP  = "exact_ip"
	PolicyMatchCIDR     = "cidr"
	PolicyMatchCatchAll = "catch_all"
)

// PolicyMatch explains the same policy-selection decision Runtime.GetPolicy
// makes. It exists so diagnostic tools can show which tier matched instead of
// forcing operators to infer that from logs.
type PolicyMatch struct {
	PolicyIndex      int      `json:"policy_index"`
	PolicyName       string   `json:"policy_name,omitempty"`
	Tier             string   `json:"tier"`
	Source           string   `json:"source,omitempty"`
	ResolvedMAC      string   `json:"resolved_mac,omitempty"`
	InactivePolicies []string `json:"inactive_policies,omitempty"`
}

// MatchPolicy matches a client IP to a policy by specificity, most specific
// first: MAC, exact IP, CIDR, then catch-all. It mirrors Runtime.GetPolicy but
// takes an explicit time and MAC lookup function for tests and simulations.
//
// Within each tier, a policy with an active time schedule (Schedule.Enabled
// && currently inside a window) takes priority over a policy without one -
// the schedule-less policy acts as the fallback for the rest of the time.
// Administratively inactive policies (Inactive) and schedule-inactive
// policies are excluded from every tier entirely.
func MatchPolicy(policies []models.Policy, clientIP string, now time.Time, lookupMAC func(string) string) PolicyMatch {
	result := PolicyMatch{PolicyIndex: -1, Tier: PolicyMatchNone}
	if idx := strings.IndexByte(clientIP, '%'); idx != -1 {
		clientIP = clientIP[:idx]
	}
	addr := net.ParseIP(strings.TrimSpace(clientIP))
	if addr == nil {
		return result
	}
	inactive := inactivePolicyNames(policies, now)

	hasMacPolicy := false
	for i := range policies {
		if len(policies[i].SourceMACs) > 0 {
			hasMacPolicy = true
			break
		}
	}
	if hasMacPolicy && lookupMAC != nil {
		if mac := lookupMAC(clientIP); mac != "" {
			result.ResolvedMAC = mac
			scheduled, fallback := -1, -1
			for i := range policies {
				p := &policies[i]
				if p.Inactive || !p.Schedule.IsActiveAt(now) {
					continue
				}
				if !containsString(p.SourceMACs, mac) {
					continue
				}
				if p.Schedule.Enabled {
					if scheduled < 0 {
						scheduled = i
					}
				} else if fallback < 0 {
					fallback = i
				}
			}
			if idx := firstOf(scheduled, fallback); idx >= 0 {
				return matchedPolicy(idx, policies[idx], PolicyMatchMAC, mac, result.ResolvedMAC, inactive)
			}
		}
	}

	{
		scheduled, fallback := -1, -1
		scheduledSrc, fallbackSrc := "", ""
		for i := range policies {
			p := &policies[i]
			if p.Inactive || !p.Schedule.IsActiveAt(now) {
				continue
			}
			for _, src := range p.SourceIPs {
				if strings.Contains(src, "/") {
					continue
				}
				target := net.ParseIP(strings.TrimSpace(src))
				if target == nil || !addr.Equal(target) {
					continue
				}
				if p.Schedule.Enabled {
					if scheduled < 0 {
						scheduled, scheduledSrc = i, src
					}
				} else if fallback < 0 {
					fallback, fallbackSrc = i, src
				}
				break
			}
		}
		if scheduled >= 0 {
			return matchedPolicy(scheduled, policies[scheduled], PolicyMatchExactIP, scheduledSrc, result.ResolvedMAC, inactive)
		}
		if fallback >= 0 {
			return matchedPolicy(fallback, policies[fallback], PolicyMatchExactIP, fallbackSrc, result.ResolvedMAC, inactive)
		}
	}

	{
		bestScheduledIndex, bestScheduledPrefix := -1, -1
		bestScheduledSrc := ""
		bestFallbackIndex, bestFallbackPrefix := -1, -1
		bestFallbackSrc := ""
		for i := range policies {
			p := &policies[i]
			if p.Inactive || !p.Schedule.IsActiveAt(now) {
				continue
			}
			for _, src := range p.SourceIPs {
				if !strings.Contains(src, "/") {
					continue
				}
				_, ipnet, err := net.ParseCIDR(strings.TrimSpace(src))
				if err != nil || !ipnet.Contains(addr) {
					continue
				}
				ones, _ := ipnet.Mask.Size()
				if p.Schedule.Enabled {
					if ones > bestScheduledPrefix {
						bestScheduledIndex, bestScheduledPrefix, bestScheduledSrc = i, ones, src
					}
				} else if ones > bestFallbackPrefix {
					bestFallbackIndex, bestFallbackPrefix, bestFallbackSrc = i, ones, src
				}
			}
		}
		if bestScheduledIndex >= 0 {
			return matchedPolicy(bestScheduledIndex, policies[bestScheduledIndex], PolicyMatchCIDR, bestScheduledSrc, result.ResolvedMAC, inactive)
		}
		if bestFallbackIndex >= 0 {
			return matchedPolicy(bestFallbackIndex, policies[bestFallbackIndex], PolicyMatchCIDR, bestFallbackSrc, result.ResolvedMAC, inactive)
		}
	}

	{
		scheduled, fallback := -1, -1
		for i := range policies {
			p := &policies[i]
			if p.Inactive || len(p.SourceIPs) != 0 || !p.Schedule.IsActiveAt(now) {
				continue
			}
			if p.Schedule.Enabled {
				if scheduled < 0 {
					scheduled = i
				}
			} else if fallback < 0 {
				fallback = i
			}
		}
		if idx := firstOf(scheduled, fallback); idx >= 0 {
			return matchedPolicy(idx, policies[idx], PolicyMatchCatchAll, "", result.ResolvedMAC, inactive)
		}
	}

	result.InactivePolicies = inactive
	return result
}

func firstOf(scheduled, fallback int) int {
	if scheduled >= 0 {
		return scheduled
	}
	return fallback
}

func matchedPolicy(index int, p models.Policy, tier, source, mac string, inactive []string) PolicyMatch {
	return PolicyMatch{PolicyIndex: index, PolicyName: p.Name, Tier: tier, Source: source, ResolvedMAC: mac, InactivePolicies: inactive}
}

func inactivePolicyNames(policies []models.Policy, now time.Time) []string {
	out := []string{}
	for i := range policies {
		if policies[i].Inactive || !policies[i].Schedule.IsActiveAt(now) {
			out = append(out, policies[i].Name)
		}
	}
	return out
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
