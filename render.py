#!/usr/bin/env python3
import json
from collections import Counter

COUNTRY_NAMES = {
    "AR": "Argentina", "AT": "Austria", "AU": "Australia", "BE": "Belgium",
    "BR": "Brazil", "CA": "Canada", "CH": "Switzerland", "CL": "Chile",
    "CZ": "Czechia", "DE": "Germany", "DK": "Denmark", "ES": "Spain",
    "FI": "Finland", "FR": "France", "HK": "Hong Kong", "IE": "Ireland",
    "IL": "Israel", "IN": "India", "IS": "Iceland", "IT": "Italy",
    "JP": "Japan", "KR": "South Korea", "MX": "Mexico", "MY": "Malaysia",
    "NL": "Netherlands", "NO": "Norway", "NZ": "New Zealand", "PL": "Poland",
    "PT": "Portugal", "RO": "Romania", "SE": "Sweden", "SG": "Singapore",
    "TR": "Turkey", "TW": "Taiwan", "UK": "United Kingdom",
    "US": "United States", "ZA": "South Africa",
}

THEMES = {
    "light": {
        "ink": "#1f2328", "muted": "#59636e",
        "bar": "#6d4aff", "rule": "#d1d9e0",
    },
    "dark": {
        "ink": "#f0f6fc", "muted": "#9198a1",
        "bar": "#8b6dff", "rule": "#3d444d",
    },
}

FONT = "ui-sans-serif, -apple-system, Segoe UI, Helvetica, Arial, sans-serif"
WIDTH = 880
PADDING = 28
GUTTER = 132
VALUE_SPACE = 62
ROW_HEIGHT = 26
BAR_HEIGHT = 13
BAR_TOP = 152
TOP_COUNTRIES = 10


def read_json(path):
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def count_ranges(path):
    with open(path, encoding="utf-8") as file:
        return sum(1 for line in file if line.strip() and not line.startswith("#"))


def exit_ips_by_country(logicals):
    counts = Counter()
    for logical in logicals["LogicalServers"]:
        servers = [s for s in logical.get("Servers", []) if s.get("ExitIP")]
        counts[logical.get("ExitCountry")] += len(servers)
    counts.pop(None, None)
    return counts


def text(x, y, content, fill, size, weight="400", anchor="start"):
    return (
        f'<text x="{x}" y="{y}" fill="{fill}" font-family="{FONT}" '
        f'font-size="{size}" font-weight="{weight}" text-anchor="{anchor}">'
        f"{content}</text>"
    )


def bar_path(x, y, width, height, radius=4):
    if width <= radius:
        return f'<path d="M{x} {y}h{width}v{height}h{-width}z"/>'
    straight = width - radius
    return (
        f'<path d="M{x} {y}h{straight}a{radius} {radius} 0 0 1 {radius} {radius}'
        f"v{height - 2 * radius}a{radius} {radius} 0 0 1 {-radius} {radius}"
        f'h{-straight}z"/>'
    )


def stat_tiles(stats, theme):
    parts = []
    step = (WIDTH - 2 * PADDING) / len(stats)
    for index, (value, label) in enumerate(stats):
        x = PADDING + index * step
        parts.append(text(x, 52, f"{value:,}", theme["ink"], 30, "600"))
        parts.append(text(x, 76, label, theme["muted"], 13))
    return parts


def country_rows(counts, theme):
    top = counts.most_common(TOP_COUNTRIES)
    largest = top[0][1]
    span = WIDTH - PADDING - GUTTER - VALUE_SPACE
    parts = []
    for index, (code, count) in enumerate(top):
        y = BAR_TOP + index * ROW_HEIGHT
        width = max(2, round(span * count / largest))
        name = COUNTRY_NAMES.get(code, code)
        parts.append(text(PADDING, y + 11, name, theme["ink"], 13))
        parts.append(f'<g fill="{theme["bar"]}">{bar_path(GUTTER, y, width, BAR_HEIGHT)}</g>')
        parts.append(
            text(GUTTER + width + 10, y + 11, f"{count:,}", theme["muted"], 12)
        )
    return parts


def render(stats, counts, theme_name):
    theme = THEMES[theme_name]
    height = BAR_TOP + TOP_COUNTRIES * ROW_HEIGHT + 14
    caption = f"Exit IPs by country, top {TOP_COUNTRIES} of {len(counts)}"
    body = [
        *stat_tiles(stats, theme),
        f'<line x1="{PADDING}" y1="100" x2="{WIDTH - PADDING}" y2="100" '
        f'stroke="{theme["rule"]}" stroke-width="1"/>',
        text(PADDING, 130, caption, theme["muted"], 13),
        *country_rows(counts, theme),
    ]
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" '
        f'height="{height}" viewBox="0 0 {WIDTH} {height}" '
        f'role="img" aria-label="{caption}">' + "".join(body) + "</svg>\n"
    )


def main():
    logicals = read_json("protonvpn_logicals.json")
    counts = exit_ips_by_country(logicals)
    stats = [
        (len(read_json("protonvpn_ips.json")), "exit IPs"),
        (len(read_json("protonvpn_entry_ips.json")), "entry IPs"),
        (len(read_json("protonvpn_subdomains.json")), "hostnames"),
        (count_ranges("protonvpn_entry_ip_ranges.txt"), "ASN ranges"),
    ]
    for theme_name in THEMES:
        path = f"assets/overview-{theme_name}.svg"
        with open(path, "w", encoding="utf-8") as file:
            file.write(render(stats, counts, theme_name))
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
