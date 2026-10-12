/**
Converts selected lists from v2fly/domain-list-community into:
- Clash domain RULE-SETs (*.yaml)
- One Shadowrocket .conf (shadowrocket.conf)
- Xray routing config (xray-routing.json)
- v2rayNG-style ruleset list (xray-rulesets.json), importable by URL
- Streisand deep link (streisand-link.txt), a streisand://... import link

It correctly handles "include: ... @attr / @-attr" filtering and brand TLDs.
*/

package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
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
DOMAIN-SUFFIX,chabokan.net,DIRECT
DOMAIN-SUFFIX,hamravesh.com,DIRECT
DOMAIN-SUFFIX,snapp.market,DIRECT
DOMAIN-SUFFIX,sdb247.com,DIRECT
DOMAIN-SUFFIX,telewebion.net,DIRECT
DOMAIN-SUFFIX,s3mer.net,DIRECT
DOMAIN-SUFFIX,push.apple.com,DIRECT
DOMAIN-KEYWORD,apple.com,DIRECT
DOMAIN-SUFFIX,lcdn-registration.apple.com,DIRECT
DOMAIN-SUFFIX,ls.apple.com,DIRECT
DOMAIN,ca.iadsdk.apple.com,DIRECT
DOMAIN,cf.iadsdk.apple.com,DIRECT
DOMAIN,news.iadsdk.apple.com,DIRECT
DOMAIN,tr.iadsdk.apple.com,DIRECT
DOMAIN,ut.iadsdk.apple.com,DIRECT
DOMAIN,safebrowsing.googleapis.com,DIRECT
DOMAIN,apple-safebrowsing.googleapis.com,DIRECT
DOMAIN,notes-analytics-events.apple.com,DIRECT
DOMAIN,stocks-analytics-events.apple.com,DIRECT
DOMAIN,weather-analytics-events.apple.com,DIRECT
#GEOIP,IR,DIRECT
FINAL,PROXY`

// ------------------------------------------------------------
// Xray manual rules (mirror of finalRule above, in Xray syntax)
// ------------------------------------------------------------

var xrayPrivateIPs = []string{
	"192.168.0.0/16",
	"172.16.0.0/12",
	"127.0.0.0/8",
	"10.0.0.0/8",
}

var xrayManualBlock = []string{
	"domain:1000click.ir",
	"domain:ad.utop.ir",
	"domain:adad.ir",
	"domain:ads.4ml.ir",
	"domain:ads.baadesaba.ir",
	"domain:analytics.tapsi.cab",
	"domain:biz.varzesh3.com",
	"domain:biz-cdn.varzesh3.com",
	"domain:clickyab.com",
	"domain:metrix.ir",
	"domain:tapsell.com",
}

var xrayManualDirect = []string{
	"domain:ir",
	"domain:chabokan.net",
	"domain:hamravesh.com",
	"domain:snapp.market",
	"domain:sdb247.com",
	"domain:telewebion.net",
	"domain:s3mer.net",
	"domain:push.apple.com",
	"keyword:apple.com",
	"domain:lcdn-registration.apple.com",
	"domain:ls.apple.com",
	"full:ca.iadsdk.apple.com",
	"full:cf.iadsdk.apple.com",
	"full:news.iadsdk.apple.com",
	"full:tr.iadsdk.apple.com",
	"full:ut.iadsdk.apple.com",
	"full:safebrowsing.googleapis.com",
	"full:apple-safebrowsing.googleapis.com",
	"full:notes-analytics-events.apple.com",
	"full:stocks-analytics-events.apple.com",
	"full:weather-analytics-events.apple.com",
}

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

// ------------------------------------------------------------
// Xray
// ------------------------------------------------------------

// xrayRule is one entry of routing.rules in an Xray config.
type xrayRule struct {
	Type        string   `json:"type"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Network     string   `json:"network,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

type xrayRouting struct {
	DomainStrategy string     `json:"domainStrategy"`
	Rules          []xrayRule `json:"rules"`
}

type xrayConfig struct {
	Routing xrayRouting `json:"routing"`
}

// v2rayNGRuleset is one item of the custom ruleset list that
// v2rayNG-like clients can import from a URL.
type v2rayNGRuleset struct {
	Remarks     string   `json:"remarks"`
	Type        string   `json:"type"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	OutboundTag string   `json:"outboundTag"`
	Enabled     bool     `json:"enabled"`
	Locked      bool     `json:"locked"`
}

// xrayTag maps the Shadowrocket policy to an Xray outbound tag.
// Make sure your Xray outbounds use the tags: proxy, direct, block.
func xrayTag(policy string) string {
	switch policy {
	case "REJECT":
		return "block"
	case "DIRECT":
		return "direct"
	default:
		return "proxy"
	}
}

// xrayDomain converts one rule into Xray domain syntax.
// Xray supports full:, domain:, keyword: and regexp: natively.
func xrayDomain(r rule) string {
	switch r.kind {
	case kindFull:
		return "full:" + r.val
	case kindKeyword:
		return "keyword:" + r.val
	case kindRegexp:
		return "regexp:" + r.val
	default:
		return "domain:" + r.val
	}
}

// uniqueStrings removes duplicates (case-insensitive), keeping order.
func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		k := strings.ToLower(s)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	return out
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}

func generateXray(results map[string][]rule, policies map[string]string) error {
	// Collect domains per outbound tag, in the same priority order as
	// Shadowrocket (block first, then direct), manual rules first.
	block := append([]string{}, xrayManualBlock...)
	direct := append([]string{}, xrayManualDirect...)

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

	var proxy []string
	for _, name := range names {
		for _, r := range results[name] {
			d := xrayDomain(r)
			switch xrayTag(policies[name]) {
			case "block":
				block = append(block, d)
			case "direct":
				direct = append(direct, d)
			default:
				proxy = append(proxy, d)
			}
		}
	}
	block = uniqueStrings(block)
	direct = uniqueStrings(direct)
	proxy = uniqueStrings(proxy)

	// ----- Full routing section -----
	// Xray uses the first matching rule, so order is important:
	// private IPs -> block -> direct -> (proxy list) -> catch-all proxy.
	rules := []xrayRule{
		{Type: "field", IP: xrayPrivateIPs, OutboundTag: "direct"},
		{Type: "field", Domain: block, OutboundTag: "block"},
		{Type: "field", Domain: direct, OutboundTag: "direct"},
	}
	if len(proxy) > 0 {
		rules = append(rules, xrayRule{Type: "field", Domain: proxy, OutboundTag: "proxy"})
	}
	rules = append(rules, xrayRule{Type: "field", Network: "tcp,udp", OutboundTag: "proxy"})

	cfg := xrayConfig{Routing: xrayRouting{DomainStrategy: "IPIfNonMatch", Rules: rules}}
	if err := writeJSON("xray-routing.json", cfg); err != nil {
		return fmt.Errorf("write xray-routing.json: %w", err)
	}

	// ----- v2rayNG-style ruleset list (import by URL) -----
	rulesets := []v2rayNGRuleset{
		{Remarks: "Private IPs", Type: "field", IP: xrayPrivateIPs, OutboundTag: "direct", Enabled: true},
		{Remarks: "Block (ads)", Type: "field", Domain: block, OutboundTag: "block", Enabled: true},
		{Remarks: "Direct (Iran + Apple)", Type: "field", Domain: direct, OutboundTag: "direct", Enabled: true},
	}
	if len(proxy) > 0 {
		rulesets = append(rulesets, v2rayNGRuleset{Remarks: "Proxy", Type: "field", Domain: proxy, OutboundTag: "proxy", Enabled: true})
	}
	if err := writeJSON("xray-rulesets.json", rulesets); err != nil {
		return fmt.Errorf("write xray-rulesets.json: %w", err)
	}

	fmt.Printf("\n\u2192 xray-routing.json generated (block: %d, direct: %d, proxy: %d)\n", len(block), len(direct), len(proxy))
	fmt.Println("\u2192 xray-rulesets.json generated")

	return nil
}

// ------------------------------------------------------------
// Streisand deep link
//
// Streisand imports routes from a deep link:
//   streisand:// + base64( "import/route://" + base64( binary plist ) )
// The plist is {name, uuid, domainStrategy, rules:[...]}.
// Rules use geosite:/geoip: tags (resolved by the app's own geo files),
// so the link stays short and the lists update with the app.
// ------------------------------------------------------------

// pdict is a dictionary that keeps its keys in the order they are written.
// Streisand's own links use a fixed key order (name, uuid, domainStrategy,
// rules), so we keep the same order instead of sorting the keys.
type pair struct {
	key string
	val any
}

type pdict []pair

type bpObj struct {
	kind  byte // 's' string, 'a' array, 'd' dict
	str   string
	items []int // array items, or dict keys followed by dict values
}

type bpBuilder struct {
	objs    []bpObj
	strings map[string]int
}

func (b *bpBuilder) add(v any) (int, error) {
	switch x := v.(type) {
	case string:
		if i, ok := b.strings[x]; ok {
			return i, nil
		}
		for _, r := range x {
			if r > 127 {
				return 0, fmt.Errorf("non-ASCII string %q is not supported", x)
			}
		}
		b.objs = append(b.objs, bpObj{kind: 's', str: x})
		i := len(b.objs) - 1
		b.strings[x] = i
		return i, nil
	case []any:
		idx := len(b.objs)
		b.objs = append(b.objs, bpObj{kind: 'a'})
		refs := make([]int, 0, len(x))
		for _, e := range x {
			r, err := b.add(e)
			if err != nil {
				return 0, err
			}
			refs = append(refs, r)
		}
		b.objs[idx].items = refs
		return idx, nil
	case pdict:
		idx := len(b.objs)
		b.objs = append(b.objs, bpObj{kind: 'd'})
		refs := make([]int, 0, 2*len(x))
		for _, kv := range x {
			r, err := b.add(kv.key)
			if err != nil {
				return 0, err
			}
			refs = append(refs, r)
		}
		for _, kv := range x {
			r, err := b.add(kv.val)
			if err != nil {
				return 0, err
			}
			refs = append(refs, r)
		}
		b.objs[idx].items = refs
		return idx, nil
	}
	return 0, fmt.Errorf("unsupported plist type %T", v)
}

func putUint(buf *bytes.Buffer, v uint64, size int) {
	for i := size - 1; i >= 0; i-- {
		buf.WriteByte(byte(v >> (8 * uint(i))))
	}
}

func bpHeader(buf *bytes.Buffer, marker byte, n int) {
	if n < 15 {
		buf.WriteByte(marker<<4 | byte(n))
		return
	}
	buf.WriteByte(marker<<4 | 0x0F)
	switch {
	case n < 1<<8:
		buf.WriteByte(0x10)
		putUint(buf, uint64(n), 1)
	case n < 1<<16:
		buf.WriteByte(0x11)
		putUint(buf, uint64(n), 2)
	default:
		buf.WriteByte(0x12)
		putUint(buf, uint64(n), 4)
	}
}

// encodeBinaryPlist writes a minimal Apple binary plist (bplist00).
// Supports only string, []any and pdict (all that Streisand needs).
func encodeBinaryPlist(root any) ([]byte, error) {
	b := &bpBuilder{strings: map[string]int{}}
	if _, err := b.add(root); err != nil {
		return nil, err
	}

	n := len(b.objs)
	refSize := 1
	if n > 0xFF {
		refSize = 2
	}
	if n > 0xFFFF {
		refSize = 4
	}

	var buf bytes.Buffer
	buf.WriteString("bplist00")
	offsets := make([]int, n)
	for i, o := range b.objs {
		offsets[i] = buf.Len()
		switch o.kind {
		case 's':
			bpHeader(&buf, 0x5, len(o.str))
			buf.WriteString(o.str)
		case 'a':
			bpHeader(&buf, 0xA, len(o.items))
			for _, r := range o.items {
				putUint(&buf, uint64(r), refSize)
			}
		case 'd':
			bpHeader(&buf, 0xD, len(o.items)/2)
			for _, r := range o.items {
				putUint(&buf, uint64(r), refSize)
			}
		}
	}

	offTable := buf.Len()
	offSize := 1
	if offTable > 0xFF {
		offSize = 2
	}
	if offTable > 0xFFFF {
		offSize = 4
	}
	for _, off := range offsets {
		putUint(&buf, uint64(off), offSize)
	}

	// Trailer: 6 unused bytes, offset size, ref size, object count,
	// root object index (0), offset table position.
	buf.Write(make([]byte, 6))
	buf.WriteByte(byte(offSize))
	buf.WriteByte(byte(refSize))
	putUint(&buf, uint64(n), 8)
	putUint(&buf, 0, 8)
	putUint(&buf, uint64(offTable), 8)
	return buf.Bytes(), nil
}

// stableUUID gives the same UUID on every run, so re-importing the link
// updates the same route instead of creating a new one.
func stableUUID(seed string) string {
	h := md5.Sum([]byte(seed))
	h[6] = (h[6] & 0x0f) | 0x30
	h[8] = (h[8] & 0x3f) | 0x80
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16]))
}

func toAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// Streisand crashed on links longer than ~2000 characters in testing
// (a 1916-char link imported fine, a 2240-char one crashed the app).
const streisandMaxLink = 1900

// pruneRedundant drops "full:" / "domain:" entries that another entry in the
// same list already matches (a keyword inside the host, or a parent domain).
// The routing result stays the same, but the link gets shorter.
func pruneRedundant(list []string) []string {
	var keywords, parents []string
	for _, e := range list {
		switch {
		case strings.HasPrefix(e, "keyword:"):
			keywords = append(keywords, strings.TrimPrefix(e, "keyword:"))
		case strings.HasPrefix(e, "domain:"):
			parents = append(parents, strings.TrimPrefix(e, "domain:"))
		}
	}

	out := make([]string, 0, len(list))
	for _, e := range list {
		isFull := strings.HasPrefix(e, "full:")
		isDomain := strings.HasPrefix(e, "domain:")
		if !isFull && !isDomain {
			out = append(out, e)
			continue
		}
		host := e[strings.Index(e, ":")+1:]

		redundant := false
		for _, k := range keywords {
			if strings.Contains(host, k) {
				redundant = true
			}
		}
		for _, d := range parents {
			if strings.HasSuffix(host, "."+d) || (isFull && host == d) {
				redundant = true
			}
		}
		if !redundant {
			out = append(out, e)
		}
	}
	return out
}

func generateStreisand() error {
	var block, direct, proxy []string
	for _, t := range targets {
		for _, s := range t.sources {
			tag := "geosite:" + s
			switch xrayTag(t.policy) {
			case "block":
				block = append(block, tag)
			case "direct":
				direct = append(direct, tag)
			default:
				proxy = append(proxy, tag)
			}
		}
	}
	block = uniqueStrings(append(block, xrayManualBlock...))
	direct = uniqueStrings(append(append([]string{"geosite:private"}, direct...), xrayManualDirect...))
	block = pruneRedundant(block)
	direct = pruneRedundant(direct)

	// First match wins. Anything that matches nothing goes to the
	// default outbound (the proxy), so no catch-all rule is needed.
	rules := []any{
		pdict{{"ip", toAny([]string{"geoip:private"})}, {"outboundTag", "direct"}},
		pdict{{"domain", toAny(block)}, {"outboundTag", "block"}},
		pdict{{"domain", toAny(direct)}, {"outboundTag", "direct"}},
	}
	if len(proxy) > 0 {
		rules = append(rules, pdict{{"domain", toAny(uniqueStrings(proxy))}, {"outboundTag", "proxy"}})
	}

	route := pdict{
		{"name", "Domain Rules"},
		{"uuid", stableUUID("domain-rules")},
		{"domainStrategy", "AsIs"},
		{"rules", rules},
	}

	plist, err := encodeBinaryPlist(route)
	if err != nil {
		return err
	}
	inner := "import/route://" + base64.StdEncoding.EncodeToString(plist)
	link := "streisand://" + base64.StdEncoding.EncodeToString([]byte(inner))
	if len(link) > streisandMaxLink {
		fmt.Fprintf(os.Stderr, "Warning: Streisand link is %d characters; links above ~%d may crash the app\n", len(link), streisandMaxLink)
	}

	if err := os.WriteFile("streisand-link.txt", []byte(link+"\n"), 0644); err != nil {
		return err
	}
	fmt.Println("\n→ streisand-link.txt generated")
	fmt.Printf("Streisand import link:\n  %s\n", link)
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

	if err := generateXray(results, policies); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing xray config: %v\n", err)
		os.Exit(1)
	}

	if err := generateStreisand(); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing streisand link: %v\n", err)
		os.Exit(1)
	}
}