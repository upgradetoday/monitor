# upgradetoday

**Do I need to upgrade today?** One page showing the latest WordPress and Drupal releases, and only the *critical* vulnerabilities each latest release fixes.

Live at [upgradetoday.io](https://upgradetoday.io).

## How it works

A GitHub Action runs `upgradetoday.py` every hour. It builds a single static `index.html` and publishes it with GitHub Pages. There is no server.

| Data | Source |
|---|---|
| Latest versions | [endoflife.date](https://endoflife.date) API |
| WordPress critical fixes | [Wordfence Intelligence](https://www.wordfence.com/threat-intel/) API, filtered to core entries rated Critical whose patched versions include the latest release |
| Drupal critical fixes | [drupal.org core security advisories](https://www.drupal.org/security), filtered to *Critical* and *Highly critical* advisories that name the latest release as the fix |

## Run it yourself

Requires Python 3 only. There are no dependencies.

```bash
export WORDFENCE_API_KEY="your-free-key"   # from wordfence.com → Account → Integrations
python3 upgradetoday.py                    # preview at http://localhost:8000
python3 upgradetoday.py --build site/index.html   # or write the static page
```

## Credits

Idea and design by Ben. Code written with Claude (Anthropic).
