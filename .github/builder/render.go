package main

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

const (
	font       = "ui-sans-serif, -apple-system, Segoe UI, Helvetica, Arial, sans-serif"
	width      = 880
	padding    = 28
	gutter     = 96
	valueSpace = 62
	rowHeight  = 26
	barHeight  = 13
	barTop     = 152
	topRows    = 10
)

var themes = map[string]map[string]string{
	"light": {"ink": "#1f2328", "muted": "#59636e", "bar": "#6d4aff", "rule": "#d1d9e0"},
	"dark":  {"ink": "#f0f6fc", "muted": "#9198a1", "bar": "#8b6dff", "rule": "#3d444d"},
}

type stat struct {
	value int
	label string
}

func thousands(value int) string {
	text := fmt.Sprint(value)
	for start := len(text) - 3; start > 0; start -= 3 {
		text = text[:start] + "," + text[start:]
	}

	return text
}

func label(x, y int, content, fill string, size int, weight string) string {
	return fmt.Sprintf(
		`<text x="%d" y="%d" fill="%s" font-family="%s" font-size="%d" `+
			`font-weight="%s">%s</text>`,
		x, y, fill, font, size, weight, content)
}

func bar(x, y, length int, fill string) string {
	radius := min(4, length)
	return fmt.Sprintf(
		`<g fill="%s"><path d="M%d %dh%da%d %d 0 0 1 %d %dv%da%d %d 0 0 1 %d %dh%dz"/></g>`,
		fill, x, y, length-radius, radius, radius, radius, radius,
		barHeight-2*radius, radius, radius, -radius, radius, -(length - radius))
}

func exitIPsByCountry(data logicals) map[string]int {
	counts := map[string]int{}
	for _, logical := range data.LogicalServers {
		for _, server := range logical.Servers {
			if server.ExitIP != "" && logical.ExitCountry != "" {
				counts[logical.ExitCountry]++
			}
		}
	}

	return counts
}

func countryRows(counts map[string]int, theme map[string]string) []string {
	codes := slices.SortedFunc(maps.Keys(counts), func(a, b string) int {
		if counts[a] != counts[b] {
			return counts[b] - counts[a]
		}
		return strings.Compare(a, b)
	})
	codes = codes[:min(topRows, len(codes))]

	span := width - padding - gutter - valueSpace
	rows := make([]string, 0, len(codes)*3)
	for index, code := range codes {
		y := barTop + index*rowHeight
		length := max(2, span*counts[code]/counts[codes[0]])
		rows = append(rows,
			label(padding, y+11, code, theme["ink"], 13, "500"),
			bar(gutter, y, length, theme["bar"]),
			label(gutter+length+10, y+11, thousands(counts[code]), theme["muted"], 12, "400"))
	}

	return rows
}

func overview(stats []stat, counts map[string]int, theme map[string]string) string {
	height := barTop + min(topRows, len(counts))*rowHeight + 14
	caption := fmt.Sprintf("Exit IPs by country, top %d of %d",
		min(topRows, len(counts)), len(counts))

	body := []string{}
	step := (width - 2*padding) / len(stats)
	for index, entry := range stats {
		x := padding + index*step
		body = append(body,
			label(x, 52, thousands(entry.value), theme["ink"], 28, "600"),
			label(x, 76, entry.label, theme["muted"], 13, "400"))
	}

	body = append(body, fmt.Sprintf(
		`<line x1="%d" y1="100" x2="%d" y2="100" stroke="%s" stroke-width="1"/>`,
		padding, width-padding, theme["rule"]))
	body = append(body, label(padding, 130, caption, theme["muted"], 13, "400"))
	body = append(body, countryRows(counts, theme)...)

	return fmt.Sprintf(
		`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" `+
			`viewBox="0 0 %d %d" role="img" aria-label="%s">%s</svg>`+"\n",
		width, height, width, height, caption, strings.Join(body, ""))
}

func renderOverview(data logicals, stats []stat) {
	counts := exitIPsByCountry(data)
	for name, theme := range themes {
		writeFile(fmt.Sprintf(".github/assets/overview-%s.svg", name),
			[]byte(overview(stats, counts, theme)))
	}
}
