import glob


def load_url_seeds(pattern="reports/urls_*.txt"):
    """URLs persisted by URL Intelligence / Crawler, deduplicated in discovery order."""
    seeds = []
    for path in sorted(glob.glob(pattern)):
        with open(path, "r", encoding="utf-8") as f:
            seeds.extend(line.strip() for line in f if line.strip().startswith("http"))
    return list(dict.fromkeys(seeds))
