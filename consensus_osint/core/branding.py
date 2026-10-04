"""OSINT Experts Society identity shared by offline human-facing output."""
from __future__ import annotations

import base64
from functools import lru_cache
from pathlib import Path

ORGANIZATION = "OSINT Experts Society"
SLOGAN = "One platform. The strength of many."
DESCRIPTION = (
    "Consensus combines lookup modules and site lists from major OSINT tools into one reverse lookup platform "
    "for emails, usernames and phone numbers. Its rules and algorithms reconcile overlapping checks, assess "
    "evidence strength and bring available account and profile details into one clear view, helping you "
    "identify the strongest leads."
)
UPDATE_NOTE = (
    "Weekly catalogue updates: we review the major lookup repositories on GitHub for newly supported "
    "sites and update Consensus's combined list."
)
ACCENT = "#ff6a00"
PROJECT_REPOSITORY = "https://github.com/OSINT-Experts-Society/Consensus-OSINT"
ACCENT_LIGHT = "#a94300"  # readable orange on a light report background
BACKGROUND = "#0e0f11"
LINKS = (
    ("Website", "https://osint.ngo/"),
    ("LinkedIn", "https://www.linkedin.com/groups/13047129/"),
    ("Reddit", "https://www.reddit.com/r/OSINTExperts/"),
)
HEALTH_WARNING = (
    "Bugs and incorrect results can and do occur. Always validate using test accounts you control. "
    "Use Consensus only for lawful, authorized purposes; respect privacy and service terms. "
    "Verify findings before acting on them."
)
# Terminal adaptation of the README mark: three source paths, one result.
TERMINAL_MARK = "●──╮   \n●──┼──◎\n●──╯   "
MENU = (
    ("Username", 'consensus user "YOUR_USERNAME"'),
    ("Email", 'consensus email "YOUR_EMAIL"'),
    ("Phone", 'consensus phone "+COUNTRY_CODE_NUMBER"'),
    ("Save report", 'consensus email "YOUR_EMAIL" -o report.html'),
    ("Show Examples", "consensus examples"),
    ("Help", "consensus scan --help"),
    ("All options", "consensus scan --help-all"),
)
QUERY_GUIDANCE = "Replace the quoted placeholders with your username, email or phone. Keep the quotes."
PHONE_GUIDANCE = 'Phone: include + and the country code, for example "+44 7700 900123".'
EXAMPLES = (
    ("Username", 'consensus user "YOUR_USERNAME"', "Search a username across the selected sites."),
    ("Quick username", 'consensus user "YOUR_USERNAME" --fast', "Limit the main site list to 300 entries; other eligible checks may still run."),
    ("Email + shared details", 'consensus email "YOUR_EMAIL" --details', "Expand the evidence for details shared by multiple sites. All returned fields are already shown by default."),
    ("Email without breaches", 'consensus email "YOUR_EMAIL" --no-breach', "Look up the email while excluding breach and infostealer checks."),
    ("Phone", 'consensus phone "+COUNTRY_CODE_NUMBER"', "Analyze an international phone number and run eligible phone checks."),
    ("Choose sites", 'consensus user "YOUR_USERNAME" --site github,gitlab', "Check only the selected services."),
    ("HTML report", 'consensus email "YOUR_EMAIL" -a -o report.html', "Save all outcomes, including inconclusive checks, in a browser report."),
    ("Compact final table", 'consensus user "YOUR_USERNAME" --summary-limit 20', "Limit the final table to 20 rows per query; all matches are shown by default."),
    ("Counters from the start", 'consensus user "YOUR_USERNAME" --live-limit 0', "Use the default loading view: counters without scrolling result rows, followed by the full final table."),
    ("Several queries", 'consensus scan "YOUR_USERNAME" "YOUR_EMAIL"', "Detect each identifier type and keep the results grouped by query."),
    ("File of queries", 'consensus scan -i queries.txt -a -o scan.json', "Read one identifier per line and preserve all outcomes for later reporting. A line may start with username:, email: or phone: to fix its type; # starts a comment line."),
    ("Queries from another program", 'consensus scan -i - -a -o scan.json', "Read the identifier list from standard input (a pipe) instead of a file."),
    ("Compare related queries", 'consensus scan -i queries.txt --compare-queries -a -o report.html', "Find shared profile details and sites across related identifiers. Queries stay separate without this option."),
    ("Open saved results", 'consensus report scan.json -a -o report.html', "Create HTML from a saved scan, without running another search."),
    ("Evidence graph", 'consensus report scan.json -a -o evidence.graph.html', "Create an offline, interactive graph of queries, sites and returned details from a saved scan. A link shows what a site returned, not who owns an account."),
    ("Compare saved results", 'consensus report scan.json --compare-queries -a -o report.html', "Compare queries in a saved scan without making new requests; use only when the identifiers are related."),
    ("Quiet output", 'consensus email "YOUR_EMAIL" -q -o report.html', "Show a short summary and save the report without live result tables."),
)


@lru_cache(maxsize=1)
def logo_data_uri() -> str:
    """Embed the shipped, owner-supplied logo; reports never fetch it remotely."""
    path = Path(__file__).resolve().parents[1] / "templates" / "society-logo.png"
    return "data:image/png;base64," + base64.b64encode(path.read_bytes()).decode("ascii")


@lru_cache(maxsize=1)
def project_mark_data_uri() -> str:
    """Reuse the installed Consensus tab mark without a remote image request."""
    path = Path(__file__).resolve().parents[1] / "templates" / "consensus-icon.png"
    return "data:image/png;base64," + base64.b64encode(path.read_bytes()).decode("ascii")


def report_identity() -> dict:
    return {"name": ORGANIZATION, "slogan": SLOGAN, "description": DESCRIPTION, "update_note": UPDATE_NOTE,
            "links": LINKS, "repository": PROJECT_REPOSITORY, "warning": HEALTH_WARNING, "logo": logo_data_uri(),
            "project_mark": project_mark_data_uri(),
            "menu": MENU, "query_guidance": QUERY_GUIDANCE, "phone_guidance": PHONE_GUIDANCE}
