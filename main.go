/**
Converts selected lists from v2fly/domain-list-community into:
- Clash domain RULE-SETs (*.yaml)
- One Shadowrocket .conf (shadowrocket.conf)

It correctly handles "include: ... @attr / @-attr" filtering and brand TLDs.
*/

package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const baseURL = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/"

type target struct {
	name    string
	sources []string
	policy  string
}

// Order matters (mirrors the insertion order of the Python dict).
var targets = []target{
	{"apple", []string{"apple"}, "DIRECT"},
	{"iran", []string{"category-ir"}, "DIRECT"},
	{"ads", []string{"category-ads-all"}, "REJECT"},
}

// ------------------------------------------------------------
// Shadowrocket [General] defaults
// ------------------------------------------------------------

const generalConf = `[General]
bypass-system = true
skip-proxy = 127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,captive.apple.com, *.apple.com, *.icloud.com, *.icloud-content.com
tun-excluded-routes = 100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32
dns-server = 1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.9,149.112.112.112,208.67.222.222,208.67.220.220
fallback-dns-server = system
ipv6 = false
prefer-ipv6 = false
dns-direct-system = true
icmp-auto-reply = true
# update-url will be filled automatically if you host the file

[Host]
localhost = 127.0.0.1`

const finalRule = `IP-CIDR,192.168.0.0/16,DIRECT
IP-CIDR,172.16.0.0/12,DIRECT
IP-CIDR,127.0.0.0/8,DIRECT
DOMAIN-SUFFIX,ir,DIRECT
DOMAIN-SUFFIX,1000click.ir,REJECT
DOMAIN-SUFFIX,ad.utop.ir,REJECT
DOMAIN-SUFFIX,adad.ir,REJECT
DOMAIN-SUFFIX,ads.4ml.ir,REJECT
DOMAIN-SUFFIX,ads.baadesaba.ir,REJECT
DOMAIN-SUFFIX,analytics.tapsi.cab,REJECT
DOMAIN-SUFFIX,biz.varzesh3.com,REJECT
DOMAIN-SUFFIX,biz-cdn.varzesh3.com,REJECT
DOMAIN-SUFFIX,clickyab.com,REJECT
DOMAIN-SUFFIX,metrix.ir,REJECT
DOMAIN-SUFFIX,tapsell.com,REJECT
DOMAIN-SUFFIX,1000click.ir,REJECT
DOMAIN-SUFFIX,1000click.ir,REJECT
DOMAIN-SUFFIX,chabokan.net,DIRECT
DOMAIN-SUFFIX,hamravesh.com,DIRECT
DOMAIN-SUFFIX,snapp.market,DIRECT
DOMAIN-SUFFIX,push.apple.com,DIRECT
DOMAIN-KEYWORD,apple.com,DIRECT
DOMAIN-SUFFIX,lcdn-registration.apple.com,DIRECT
DOMAIN-SUFFIX,ls.apple.com,DIRECT
DOMAIN,ca.iadsdk.apple.com,DIRECT
DOMAIN,cf.iadsdk.apple.com,DIRECT
DOMAIN,news.iadsdk.apple.com,DIRECT
DOMAIN,tr.iadsdk.apple.com,DIRECT
DOMAIN,ut.iadsdk.apple.com,DIRECT
DOMAIN,notes-analytics-events.apple.com,DIRECT
DOMAIN,stocks-analytics-events.apple.com,DIRECT
DOMAIN,weather-analytics-events.apple.com,DIRECT
#GEOIP,IR,DIRECT
FINAL,PROXY`

// ------------------------------------------------------------
// Rule types
// ------------------------------------------------------------

type ruleKind string

const (
	kindFull    ruleKind = "full"
	kindKeyword ruleKind = "keyword"
	kindRegexp  ruleKind = "regexp"
	kindDomain  ruleKind = "domain"
)

type rule struct {
	kind ruleKind
	val  string
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

func fetch(name string) (string, error) {
	url := baseURL + name
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d for %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// parseAttrs splits tokens like "@cn" / "@-ads" / "@!ads" into
// a "must have" set and a "must not have" set.
func parseAttrs(tokens []string) (must, ban map[string]bool) {
	must = map[string]bool{}
	ban = map[string]bool{}
	for _, t := range tokens {
		if !strings.HasPrefix(t, "@") {
			continue
		}
		attr := t[1:]
		if strings.HasPrefix(attr, "-") || strings.HasPrefix(attr, "!") {
			ban[attr[1:]] = true
		} else {
			must[attr] = true
		}
	}
	return must, ban
}

func ruleMatches(ruleAttrs, must, ban map[string]bool) bool {
	if len(must) > 0 {
		for a := range must {
			if !ruleAttrs[a] {
				return false
			}
		}
	}
	if len(ban) > 0 {
		for a := range ban {
			if ruleAttrs[a] {
				return false
			}
		}
	}
	if len(must) > 0 && len(ruleAttrs) == 0 {
		return false
	}
	return true
}

func mergeSets(a, b map[string]bool) map[string]bool {
	out := make(map[string]bool, len(a)+len(b))
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func isAlpha(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

// parseList recursively parses a domain-list-community file, following
// "include:" directives and applying inherited @attr / @-attr filters.
// seen de-duplicates (include name + effective filters) pairs, same as
// the Python version's `seen` set.
func parseList(content string, seen map[string]bool, mustAttrs, banAttrs map[string]bool) []rule {
	var rules []rule

	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "include:") {
			rest := strings.TrimSpace(line[len("include:"):])
			parts := strings.Fields(rest)
			if len(parts) == 0 {
				continue
			}
			includeName := parts[0]
			childMust, childBan := parseAttrs(parts[1:])

			combinedMust := mergeSets(mustAttrs, childMust)
			combinedBan := mergeSets(banAttrs, childBan)

			key := fmt.Sprintf("%s|%s|%s", includeName,
				strings.Join(sortedKeys(combinedMust), ","),
				strings.Join(sortedKeys(combinedBan), ","))
			if seen[key] {
				continue
			}
			seen[key] = true

			childContent, err := fetch(includeName)
			if err != nil {
				fmt.Printf("  Warning: cannot fetch %s: %v\n", includeName, err)
				continue
			}
			rules = append(rules, parseList(childContent, seen, combinedMust, combinedBan)...)
			continue
		}

		tokens := strings.Fields(line)
		first := tokens[0]
		attrs := map[string]bool{}
		for _, t := range tokens[1:] {
			if strings.HasPrefix(t, "@") {
				attrs[t[1:]] = true
			}
		}

		if !ruleMatches(attrs, mustAttrs, banAttrs) {
			continue
		}

		switch {
		case strings.HasPrefix(first, "full:"):
			rules = append(rules, rule{kindFull, first[len("full:"):]})
		case strings.HasPrefix(first, "keyword:"):
			rules = append(rules, rule{kindKeyword, first[len("keyword:"):]})
		case strings.HasPrefix(first, "regexp:"):
			rules = append(rules, rule{kindRegexp, first[len("regexp:"):]})
		case strings.HasPrefix(first, "domain:"):
			rules = append(rules, rule{kindDomain, first[len("domain:"):]})
		default:
			domain := first
			if domain != "" && (strings.Contains(domain, ".") || isAlpha(domain)) {
				rules = append(rules, rule{kindDomain, domain})
			}
		}
	}

	return rules
}

type dedupKey struct {
	kind ruleKind
	val  string
}

func generateOne(name string, sources []string) ([]rule, error) {
	fmt.Printf("\n=== Generating %s ===\n", name)
	seen := map[string]bool{}
	var allRules []rule

	for _, src := range sources {
		fmt.Printf("  Processing %s ...\n", src)
		content, err := fetch(src)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", src, err)
		}
		allRules = append(allRules, parseList(content, seen, nil, nil)...)
	}

	// Deduplicate, preserving first-seen order.
	seenKeys := map[dedupKey]bool{}
	unique := make([]rule, 0, len(allRules))
	for _, r := range allRules {
		key := dedupKey{r.kind, strings.ToLower(r.val)}
		if !seenKeys[key] {
			seenKeys[key] = true
			unique = append(unique, r)
		}
	}

	// ----- Clash YAML -----
	lines := []string{"payload:"}
	for _, r := range unique {
		switch r.kind {
		case kindFull:
			lines = append(lines, fmt.Sprintf("  - '%s'", r.val))
		case kindDomain:
			lines = append(lines, fmt.Sprintf("  - '+.%s'", r.val))
		default:
			lines = append(lines, fmt.Sprintf("  # unsupported %s: %s", r.kind, r.val))
		}
	}

	outPath := fmt.Sprintf("clash-%s.yaml", name)
	if err := os.WriteFile(outPath, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		return nil, fmt.Errorf("write %s: %w", outPath, err)
	}
	fmt.Printf("  \u2192 %s  (%d entries)\n", outPath, len(unique))

	return unique, nil
}

func policyPriority(p string) int {
	switch p {
	case "REJECT":
		return 0
	case "DIRECT":
		return 1
	default:
		return 2
	}
}

func generateShadowrocket(results map[string][]rule, policies map[string]string) error {
	now := time.Now().UTC().Format("2006-01-02 15:04 UTC")

	names := make([]string, 0, len(results))
	for name := range results {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		pi, pj := policyPriority(policies[names[i]]), policyPriority(policies[names[j]])
		if pi != pj {
			return pi < pj
		}
		return names[i] < names[j]
	})

	var conf []string
	conf = append(conf, fmt.Sprintf("# Generated on %s", now))
	conf = append(conf, "# Source: v2fly/domain-list-community")
	conf = append(conf, "")
	conf = append(conf, generalConf)
	conf = append(conf, "")
	conf = append(conf, "[Rule]")
	conf = append(conf, "# ---------- Auto-generated rules ----------")

	for _, name := range names {
		rules := results[name]
		policy := policies[name]
		conf = append(conf, "")
		conf = append(conf, fmt.Sprintf("# ===== %s \u2192 %s =====", name, policy))
		for _, r := range rules {
			switch r.kind {
			case kindFull:
				conf = append(conf, fmt.Sprintf("DOMAIN,%s,%s", r.val, policy))
			case kindDomain:
				conf = append(conf, fmt.Sprintf("DOMAIN-SUFFIX,%s,%s", r.val, policy))
				// keyword / regexp are skipped (or add DOMAIN-KEYWORD if you want)
			}
		}
	}

	conf = append(conf, "")
	conf = append(conf, "# ---------- Final fallback ----------")
	conf = append(conf, finalRule)
	conf = append(conf, "")

	if err := os.WriteFile("shadowrocket.conf", []byte(strings.Join(conf, "\n")), 0644); err != nil {
		return err
	}
	fmt.Println("\n\u2192 shadowrocket.conf generated")
	return nil
}

func main() {
	results := map[string][]rule{}
	policies := map[string]string{}

	for _, t := range targets {
		rules, err := generateOne(t.name, t.sources)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating %s: %v\n", t.name, err)
			os.Exit(1)
		}
		results[t.name] = rules
		policies[t.name] = t.policy
	}

	if err := generateShadowrocket(results, policies); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing shadowrocket.conf: %v\n", err)
		os.Exit(1)
	}
}
