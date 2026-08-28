package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	baseDomain   = "protonvpn.net"
	versionURL   = "https://account.protonvpn.com/assets/yandex-browser-manifest.json"
	refreshURL   = "https://account.proton.me/api/auth/refresh"
	logicalsURL  = "https://account.protonvpn.com/api/vpn/logicals"
	crtShURL     = "https://crt.sh/json?q=" + baseDomain
	peeringDBURL = "https://www.peeringdb.com/api/net?name_search=Proton"
	announcedURL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d"
	asnTableURL  = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
	userAgent    = "ProtonVPN-IPs (+https://github.com/tn3w/ProtonVPN-IPs)"

	subdomainsPath = "protonvpn_subdomains.json"
)

var client = &http.Client{Timeout: 5 * time.Minute}

type session struct {
	uid, auth, refresh, id string
}

type logicals struct {
	LogicalServers []struct {
		ExitCountry string
		Servers     []struct{ EntryIP, ExitIP string }
	}
}

type asnRange struct {
	first, last netip.Addr
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func fetch(method, url string, headers map[string]string) (*http.Response, error) {
	request, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Set("User-Agent", userAgent)
	for name, value := range headers {
		request.Header.Set(name, value)
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("%s: %s", url, response.Status)
	}

	return response, nil
}

func getJSON(url string, headers map[string]string, target any) error {
	response, err := fetch("GET", url, headers)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	return json.NewDecoder(response.Body).Decode(target)
}

func appVersion() string {
	var manifest struct{ Version string }
	if err := getJSON(versionURL, nil, &manifest); err != nil {
		fatal("app version: %v", err)
	}

	return "web-vpn-settings@" + manifest.Version
}

func cookieValue(response *http.Response, name string) string {
	for _, cookie := range response.Cookies() {
		if cookie.Name == name {
			return cookie.Value
		}
	}

	return ""
}

func refreshSession(current session, version string) session {
	headers := map[string]string{
		"x-pm-appversion": version,
		"x-pm-uid":        current.uid,
		"Cookie":          fmt.Sprintf("REFRESH-%s=%s", current.uid, current.refresh),
	}

	response, err := fetch("POST", refreshURL, headers)
	if err != nil {
		fmt.Println("token refresh failed, reusing current tokens:", err)
		return current
	}
	defer response.Body.Close()

	rotated := session{
		uid:     current.uid,
		auth:    cookieValue(response, "AUTH-"+current.uid),
		refresh: cookieValue(response, "REFRESH-"+current.uid),
		id:      cookieValue(response, "Session-Id"),
	}
	if rotated.auth == "" || rotated.refresh == "" || rotated.id == "" {
		fmt.Println("token refresh returned no cookies, reusing current tokens")
		return current
	}

	fmt.Println("refreshed authentication tokens")
	return rotated
}

func persistSession(active session) {
	path := os.Getenv("TOKEN_FILE")
	if path == "" {
		return
	}

	content := fmt.Sprintf("AUTH_TOKEN=%s\nREFRESH_TOKEN=%s\nSESSION_ID=%s\n",
		active.auth, active.refresh, active.id)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		fatal("writing %s: %v", path, err)
	}
}

func fetchLogicals(active session, version string) []byte {
	headers := map[string]string{
		"x-pm-appversion": version,
		"x-pm-uid":        active.uid,
		"Accept":          "application/vnd.protonmail.v1+json",
		"Cookie": fmt.Sprintf("AUTH-%s=%s; Session-Id=%s",
			active.uid, active.auth, active.id),
	}

	response, err := fetch("GET", logicalsURL, headers)
	if err != nil {
		fatal("logicals: %v", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		fatal("logicals: %v", err)
	}

	return body
}

func exitAddresses(data logicals) []netip.Addr {
	unique := map[netip.Addr]bool{}
	for _, logical := range data.LogicalServers {
		for _, server := range logical.Servers {
			if address, err := netip.ParseAddr(server.ExitIP); err == nil {
				unique[address] = true
			}
		}
	}

	return sortedAddresses(unique)
}

func subdomains() []string {
	var entries []struct {
		NameValue string `json:"name_value"`
	}

	for attempt := 1; attempt <= 5 && len(entries) == 0; attempt++ {
		if err := getJSON(crtShURL, nil, &entries); err != nil {
			fmt.Printf("crt.sh attempt %d/5: %v\n", attempt, err)
		}
		if len(entries) == 0 && attempt < 5 {
			time.Sleep(30 * time.Second)
		}
	}

	unique := map[string]bool{}
	for _, entry := range entries {
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			if strings.HasSuffix(name, "."+baseDomain) && !strings.Contains(name, "*") {
				unique[name] = true
			}
		}
	}
	if len(unique) == 0 {
		fmt.Println("crt.sh unavailable, reusing the committed hostnames")
		return committedSubdomains()
	}

	return slices.Sorted(maps.Keys(unique))
}

func committedSubdomains() []string {
	content, err := os.ReadFile(subdomainsPath)
	if err != nil {
		fatal("no hostnames from crt.sh and no %s: %v", subdomainsPath, err)
	}

	var names []string
	if err := json.Unmarshal(content, &names); err != nil {
		fatal("%s: %v", subdomainsPath, err)
	}

	return names
}

func resolve(hostnames []string) []netip.Addr {
	var mutex sync.Mutex
	var group sync.WaitGroup
	slots := make(chan struct{}, 20)
	unique := map[netip.Addr]bool{}

	for _, hostname := range hostnames {
		group.Add(1)
		slots <- struct{}{}

		go func() {
			defer group.Done()
			defer func() { <-slots }()

			texts, err := net.LookupHost(hostname)
			if err != nil {
				return
			}

			mutex.Lock()
			defer mutex.Unlock()
			for _, text := range texts {
				if address, err := netip.ParseAddr(text); err == nil {
					unique[address] = true
				}
			}
		}()
	}

	group.Wait()
	return sortedAddresses(unique)
}

func asnTable() []asnRange {
	response, err := fetch("GET", asnTableURL, nil)
	if err != nil {
		fatal("asn table: %v", err)
	}
	defer response.Body.Close()

	stream, err := gzip.NewReader(response.Body)
	if err != nil {
		fatal("asn table: %v", err)
	}

	var ranges []asnRange
	scanner := bufio.NewScanner(stream)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 3 || fields[2] == "0" {
			continue
		}

		first, firstErr := netip.ParseAddr(fields[0])
		last, lastErr := netip.ParseAddr(fields[1])
		if firstErr == nil && lastErr == nil {
			ranges = append(ranges, asnRange{first, last})
		}
	}

	slices.SortFunc(ranges, func(a, b asnRange) int { return a.first.Compare(b.first) })
	return ranges
}

func announcedFor(ranges []asnRange, addresses []netip.Addr) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, address := range addresses {
		index, exact := slices.BinarySearchFunc(ranges, address,
			func(entry asnRange, target netip.Addr) int {
				return entry.first.Compare(target)
			})
		if !exact {
			index--
		}
		if index < 0 {
			continue
		}

		holder := ranges[index]
		if holder.last.Compare(address) >= 0 {
			prefixes = append(prefixes, summarize(holder.first, holder.last)...)
		}
	}

	return prefixes
}

func protonASNPrefixes(known []netip.Addr) []netip.Prefix {
	var networks struct {
		Data []struct {
			ASN  int
			Name string
		}
	}
	if err := getJSON(peeringDBURL, nil, &networks); err != nil {
		fmt.Println("peeringdb lookup failed, skipping:", err)
		return nil
	}

	var prefixes []netip.Prefix
	for _, network := range networks.Data {
		announced := announcedPrefixes(network.ASN)
		if !containsAny(announced, known) {
			fmt.Printf("AS%d %s: holds no ProtonVPN IP, skipped\n", network.ASN, network.Name)
			continue
		}

		fmt.Printf("AS%d %s: %d prefixes\n", network.ASN, network.Name, len(announced))
		prefixes = append(prefixes, announced...)
	}

	return prefixes
}

func announcedPrefixes(asn int) []netip.Prefix {
	var response struct {
		Data struct {
			Prefixes []struct{ Prefix string }
		}
	}
	if err := getJSON(fmt.Sprintf(announcedURL, asn), nil, &response); err != nil {
		fmt.Printf("AS%d announced prefixes: %v\n", asn, err)
		return nil
	}

	var prefixes []netip.Prefix
	for _, entry := range response.Data.Prefixes {
		if prefix, err := netip.ParsePrefix(entry.Prefix); err == nil {
			prefixes = append(prefixes, prefix.Masked())
		}
	}

	return prefixes
}

func containsAny(prefixes []netip.Prefix, addresses []netip.Addr) bool {
	for _, prefix := range prefixes {
		for _, address := range addresses {
			if prefix.Contains(address) {
				return true
			}
		}
	}

	return false
}

func blocks24(addresses []netip.Addr) []netip.Prefix {
	unique := map[netip.Prefix]bool{}
	for _, address := range addresses {
		if address.Is4() {
			unique[netip.PrefixFrom(address, 24).Masked()] = true
		}
	}

	return sortedPrefixes(unique)
}

func summarize(first, last netip.Addr) []netip.Prefix {
	bits := first.BitLen()
	start := new(big.Int).SetBytes(first.AsSlice())
	end := new(big.Int).SetBytes(last.AsSlice())
	one := big.NewInt(1)

	var prefixes []netip.Prefix
	for start.Cmp(end) <= 0 {
		length := bits
		for length > 0 {
			size := new(big.Int).Lsh(one, uint(bits-length+1))
			stop := new(big.Int).Sub(new(big.Int).Add(start, size), one)
			if new(big.Int).Mod(start, size).Sign() != 0 || stop.Cmp(end) > 0 {
				break
			}
			length--
		}

		address, _ := netip.AddrFromSlice(start.FillBytes(make([]byte, bits/8)))
		prefixes = append(prefixes, netip.PrefixFrom(address, length))
		start.Add(start, new(big.Int).Lsh(one, uint(bits-length)))
	}

	return prefixes
}

func sortedAddresses(unique map[netip.Addr]bool) []netip.Addr {
	addresses := slices.Collect(maps.Keys(unique))
	slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })

	return addresses
}

func sortedPrefixes(unique map[netip.Prefix]bool) []netip.Prefix {
	prefixes := slices.Collect(maps.Keys(unique))
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if order := a.Addr().Compare(b.Addr()); order != 0 {
			return order
		}
		return a.Bits() - b.Bits()
	})

	return prefixes
}

func uniquePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	unique := map[netip.Prefix]bool{}
	for _, prefix := range prefixes {
		unique[prefix] = true
	}

	return sortedPrefixes(unique)
}

func addressTexts(addresses []netip.Addr) []string {
	texts := make([]string, len(addresses))
	for index, address := range addresses {
		texts[index] = address.String()
	}

	return texts
}

func prefixTexts(prefixes []netip.Prefix) []string {
	texts := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		texts[index] = prefix.String()
	}

	return texts
}

func writeFile(path string, content []byte) {
	if err := os.WriteFile(path, content, 0o644); err != nil {
		fatal("writing %s: %v", path, err)
	}
	fmt.Println("wrote", path)
}

func writeJSON(path string, value any) {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fatal("encoding %s: %v", path, err)
	}

	writeFile(path, append(content, '\n'))
}

func writeIndentedJSON(path string, raw []byte) {
	var buffer bytes.Buffer
	if err := json.Indent(&buffer, raw, "", "  "); err != nil {
		fatal("encoding %s: %v", path, err)
	}

	writeFile(path, append(buffer.Bytes(), '\n'))
}

func writeList(path, description string, lines []string) {
	header := fmt.Sprintf("#\n# %s\n# https://github.com/tn3w/ProtonVPN-IPs\n#\n# %s\n#\n",
		path, description)

	writeFile(path, []byte(header+strings.Join(lines, "\n")+"\n"))
}

func main() {
	active := session{
		uid:     os.Getenv("AUTH_PM_UID"),
		auth:    os.Getenv("AUTH_TOKEN"),
		refresh: os.Getenv("REFRESH_TOKEN"),
		id:      os.Getenv("SESSION_ID"),
	}
	if active.uid == "" || active.refresh == "" {
		fatal("AUTH_PM_UID and REFRESH_TOKEN are required")
	}

	version := appVersion()
	active = refreshSession(active, version)
	persistSession(active)

	raw := fetchLogicals(active, version)
	var data logicals
	if err := json.Unmarshal(raw, &data); err != nil {
		fatal("logicals: %v", err)
	}

	exitIPs := exitAddresses(data)
	exitBlocks := blocks24(exitIPs)
	hostnames := subdomains()
	entryIPs := resolve(hostnames)
	entryPrefixes := uniquePrefixes(slices.Concat(
		announcedFor(asnTable(), entryIPs),
		protonASNPrefixes(slices.Concat(exitIPs, entryIPs)),
	))

	writeIndentedJSON("protonvpn_logicals.json", raw)
	writeJSON("protonvpn_ips.json", addressTexts(exitIPs))
	writeJSON("protonvpn_entry_ips.json", addressTexts(entryIPs))
	writeJSON(subdomainsPath, hostnames)
	writeList("protonvpn_ips.txt",
		"Exit IPs ProtonVPN advertises, the address a site sees.",
		addressTexts(exitIPs))
	writeList("protonvpn_ip_ranges.txt",
		"The /24 block of every advertised IPv4, covering NAT egress addresses.",
		prefixTexts(exitBlocks))
	writeList("protonvpn_entry_ips.txt",
		"Entry IPs clients connect to, resolved from ProtonVPN hostnames.",
		addressTexts(entryIPs))
	writeList("protonvpn_entry_ip_ranges.txt",
		"Announced prefixes holding an entry IP, plus every prefix of ProtonVPN's ASNs.",
		prefixTexts(entryPrefixes))

	renderOverview(data, []stat{
		{len(exitIPs), "exit IPs"},
		{len(exitBlocks), "/24 blocks"},
		{len(entryIPs), "entry IPs"},
		{len(hostnames), "hostnames"},
		{len(entryPrefixes), "entry prefixes"},
	})
}
