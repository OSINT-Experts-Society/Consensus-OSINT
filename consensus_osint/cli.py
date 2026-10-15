"""Consensus command-line interface.

    consensus <query> [<query> ...]        auto-detects username / e-mail / phone
    consensus user <username>              force username scan
    consensus email <address>              force e-mail scan
    consensus phone <number>               force phone scan
    consensus sites list|info|tags         browse the site database
    consensus modules                      list code modules
consensus report <results.json> -o report.html   re-render a saved scan
    consensus keys set <name> <value>      store API keys
    consensus mcp                          run the MCP server (AI agents)
"""
from __future__ import annotations

import argparse
import asyncio
import codecs
import json
import logging
import math
import os
import sys
import time
import unicodedata
import webbrowser
from contextvars import ContextVar
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .core.config import KNOWN_DEFAULTS, config_path, get_config, set_key, unused_settings
from .core.console import Printer
from .core.http import Http
from .core.models import Finding, QueryType, ScanSummary, Status, dedupe_findings
from .core.modules import Context, all_modules
from .core.sitesdb import SiteDB, save_override, site_keys

log = logging.getLogger("consensus")

SUBCOMMANDS = {'about', 'email', 'examples', 'info', 'keys', 'mcp', 'modules', 'phone', 'report', 'scan', 'shell', 'sites', 'terminal', 'update', 'user', 'username', 'version'}

# First words people type expecting a command. Each used to be looked up as a username on every site,
# together with any word after it; `consensus user WORD` still searches for the word itself.
NOT_A_SEARCH = {'investigations': 'run consensus, then choose Investigations in its menu', 'followup': 'run consensus, then use followup in its interactive session', 'continue': 'run consensus, then use continue in its interactive session', 'new-sources': 'run consensus, then use new-sources in its interactive session', 'recheck': 'run consensus, then use recheck in its interactive session', 'changes': 'run consensus, then use changes in its interactive session', 'search': 'consensus scan "YOUR_QUERY"', 'find': 'consensus scan "YOUR_QUERY"', 'lookup': 'consensus scan "YOUR_QUERY"', 'check': 'consensus scan "YOUR_QUERY"', 'mail': 'consensus email "YOUR_EMAIL"', 'tel': 'consensus phone "+COUNTRY_CODE_NUMBER"', 'site': 'consensus sites list', 'list': 'consensus sites list', 'key': 'consensus keys list', 'config': 'consensus keys path', 'settings': 'consensus keys path', 'module': 'consensus modules', 'reports': 'consensus report SAVED.json -o REPORT.html', 'upgrade': 'consensus update', 'install': 'consensus update', 'uninstall': "the README's uninstall section", 'status': 'consensus version', 'quit': 'nothing: there is no session to leave here', 'exit': 'nothing: there is no session to leave here', 'registry': 'consensus --help', 'selfcheck': 'consensus --help', 'test': 'consensus --help'}


def redact_proxy(proxy: str | None) -> str | None:
    """Mask user:password in a proxy URL before it is stored or displayed."""
    if not proxy or "@" not in proxy:
        return proxy
    scheme, _, rest = proxy.partition("://")
    userinfo, _, host = rest.rpartition("@")
    user = userinfo.split(":", 1)[0]
    shown = user[:4] + "…" if len(user) > 4 else "…"
    return f"{scheme}://{shown}:***@{host}"


PROXY_SCHEMES = ("http", "https", "socks5", "socks5h")


def _positive_int(value: str) -> int:
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _phone_region(value: str) -> str:
    import phonenumbers

    region = value.strip().upper()
    if region not in phonenumbers.SUPPORTED_REGIONS:
        raise argparse.ArgumentTypeError("use a two-letter country code, such as GB for the UK or US for the USA")
    return region


def _nonempty_selector(value: str) -> str:
    if not any(part.strip() for part in value.split(",")):
        raise argparse.ArgumentTypeError("give at least one name; separate multiple names with commas")
    return value


def _nonnegative_int(value: str) -> int:
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("must be a non-negative integer") from None
    if number < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return number


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("must be a finite positive number") from None
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return number


def _nonnegative_float(value: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("must be a finite non-negative number") from None
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError("must be a finite non-negative number")
    return number


def _proxy_arg(value: str) -> str:
    """argparse type for --proxy: reject a malformed URL up front, without echoing a password."""
    try:
        u = urlparse(value)
        ok = u.scheme.lower() in PROXY_SCHEMES and bool(u.hostname)
        if u.port is not None and u.port == 0:
            ok = False
    except Exception:  # noqa: BLE001
        ok = False
    if not ok:
        raise argparse.ArgumentTypeError(
            "invalid proxy URL; expected scheme://[user:pass@]host:port with scheme http, https, socks5 or socks5h")
    return value


def _module_keys(m) -> set:
    """Every name ``--site`` / ``--exclude`` may use for a module: id, name, host and its words."""
    from .core.sitesdb import domain_words

    host = (m.url_main or "").lower().replace("https://", "").replace("http://", "").strip("/")
    return {m.id.lower(), m.name.lower(), host} | domain_words(host.split("/")[0])


MODULE_FAMILIES = ["rules", "user-scanner", "holehe", "socialscan", "ignorant", "numint", "extras"]


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------
def add_scan_options(p: argparse.ArgumentParser, *, full_help: bool = False) -> None:
    p.add_argument("--help-all", action="help", help="show every scan option")
    g = p.add_argument_group("output")
    g.add_argument("-o", "--output", action=_SingleOutput, help="save results to FILE (format from extension or -f)")
    g.add_argument("-f", "--format", choices=["txt", "json", "jsonl", "csv", "md", "html", "pdf", "neo4j", "xmind", "graph-html"],
                   help="report format for -o")
    g.add_argument("-a", "--all", action="store_true", help="show/save every result, not only found ones")
    g.add_argument("--jsonl", action="store_true", help="stream results as JSON lines to stdout")
    g.add_argument("-q", "--quiet", action="store_true", help="no per-result output (summary only)")
    g.add_argument("--no-color", action="store_true", help="use plain output without colours")
    g.add_argument("--no-update-check", action="store_true", help="skip the startup application update check")
    g.add_argument("--no-footer", action="store_true", help="run without the pinned terminal footer")
    g.add_argument("--no-animation", action="store_true", help="disable footer and terminal-tab animations")
    g.add_argument("-v", "--verbose", action="store_true", help="also show blocked / error results")
    g.add_argument("--details", action="store_true", help="expand comparison evidence; all returned fields are already shown")
    g.add_argument("--phone-region", type=_phone_region, metavar="COUNTRY",
                   help="country for a national phone number, e.g. GB for the UK; international + numbers need no region")
    g.add_argument("--compare-queries", action=argparse.BooleanOptionalAction, default=False,
                   help="also compare returned details across different queries; use when researching related identifiers")
    g.add_argument("--summary-limit", type=_nonnegative_int, default=0, metavar="N",
                   help="maximum final table rows per query (default 0: all)")
    g.add_argument("--live-limit", type=_nonnegative_int, default=0, metavar="N",
                   help="opt into printing N live matches (default 0: progress only; V toggles a temporary preview)")
    g.add_argument("--debug", action="store_true")
    g.add_argument("--browse", action="store_true", help="open found profiles in the browser")
    g.add_argument("--ai", action="store_true", help="AI summary of the results (needs an OpenAI-compatible key)")

    n = p.add_argument_group("network")
    n.add_argument("-c", "--concurrency", type=_positive_int, default=None, help="parallel requests (default 100)")
    n.add_argument("-t", "--timeout", type=_positive_float, default=None, help="seconds to wait for a site to respond (default 15)")
    n.add_argument("--delay", type=_nonnegative_float, default=0.0, help="delay between request starts (seconds)")
    n.add_argument("--proxy", type=_proxy_arg, help="proxy URL, e.g. socks5://127.0.0.1:9050 or http://user:pass@host:port")
    n.add_argument("--tor", action="store_true", help="route through Tor (socks5://127.0.0.1:9050); enables .onion sites")
    n.add_argument("--no-verify", action="store_true", help="disable TLS certificate verification")
    n.add_argument("--no-impersonate", action="store_true", help="never use browser TLS impersonation (curl_cffi)")
    n.add_argument("--browser", action="store_true",
                   help="re-fetch challenge pages (Cloudflare, PoW, DataDome, 403) with a real headless browser (Playwright + installed Chrome/Edge)")
    n.add_argument("--browser-pages", type=_positive_int, default=4, help="parallel browser pages for --browser (default 4)")
    n.add_argument("--browser-visible", action="store_true", help="show the browser window (debugging)")
    n.add_argument("--flaresolverr", metavar="URL", help="FlareSolverr endpoint for challenge pages, e.g. http://localhost:8191")

    s = p.add_argument_group("scope")
    s.add_argument("--type", choices=["auto", "username", "email", "phone"], default="auto", help="identifier type")
    s.add_argument("--site", type=_nonempty_selector, action=_JoinedSelector, help="search only these sites; separate names or domains with commas")
    s.add_argument("--exclude", type=_nonempty_selector, action=_JoinedSelector, help="skip these sites (comma-separated)")
    s.add_argument("--tags", type=_nonempty_selector, action=_JoinedSelector, help="only sites with these tags/categories (comma-separated), e.g. social,coding")
    s.add_argument("--exclude-tags", type=_nonempty_selector, action=_JoinedSelector, help="skip sites with these tags")
    s.add_argument("--top", type=_positive_int, help="maximum checks per username/email; aim for 50/50 sites/modules, filling unused slots; background analysis is separate")
    speed = s.add_mutually_exclusive_group()
    speed.add_argument("--fast", action="store_true",
                       help="up to 300 username/email lookups; --top overrides this limit")
    speed.add_argument("--full", action="store_false", dest="fast",
                       help="all eligible username/email checks (no Quick limit)")
    s.add_argument("--nsfw", action="store_true", help="include NSFW sites and modules")
    s.add_argument("--all-sites", action="store_true", help="also list disabled sites, as skipped results with the reason; they are not contacted")
    s.add_argument("--source", type=_nonempty_selector, action=_JoinedSelector, help="only sites from these upstream lists (sherlock,maigret,wmn,...)")
    s.add_argument("--no-sites", action="store_true", help="skip the data-driven site database")
    s.add_argument("--no-modules", action="store_true", help="skip code modules (user-scanner, holehe, socialscan ...)")
    s.add_argument("--all-modules", action="store_true",
                   help="run every module even where several families check the same service (default: one per service)")
    s.add_argument("--per-host", type=_positive_int, default=4, metavar="N",
                   help="simultaneous requests allowed to any one host (default 4; be polite)")
    s.add_argument("--family", type=_nonempty_selector, action=_JoinedSelector, help="only these module families: " + ",".join(MODULE_FAMILIES))
    s.add_argument("--allow-loud", action="store_true",
                   help="run modules that may notify the target (password-reset e-mails, SMS codes)")
    s.add_argument("--no-breach", action="store_true", help="skip breach / infostealer lookups")
    s.add_argument("--no-extract", action="store_true", help="do not extract profile metadata from found pages")

    x = p.add_argument_group("pivoting")
    x.add_argument("-r", "--recursive", action="store_true",
                   help="cross-scan: follow usernames, e-mails and profile links discovered in results")
    x.add_argument("--depth", type=_nonnegative_int, default=1, help="recursion depth for -r (default 1)")
    x.add_argument("--max-pivots", type=_nonnegative_int, default=10, help="max new identifiers per round (default 10)")
    x.add_argument("--search-engines", action="store_true", help="also collect profile links from web search engines")
    x.add_argument("--mailcat", action="store_true", help="username -> discover existing e-mail addresses at mail providers")
    x.add_argument("-P", "--permute", metavar="PATTERN",
                   help="expand a pattern into many queries, e.g. 'john[0-9]{0-2}' or '[jJ]ohn[_.]doe'")
    x.add_argument("--variants", action="store_true", help="also scan common alias variants (fred_, fred123, realfred ...)")
    x.add_argument("--names", metavar="PARTS", help="permute name parts, e.g. 'john doe 1990' -> johndoe, doe_john ...")
    x.add_argument("--max-permutations", type=_positive_int, default=100)
    x.add_argument("-i", "--input", help="read queries from FILE or - for stdin; optional username:/email:/phone: prefix per line")

    if not full_help:
        common = {"help", "help_all", "queries", "output", "all", "quiet", "verbose", "details", "no_color", "compare_queries",
                  "site", "top", "fast", "proxy", "timeout", "input"}
        for action in p._actions:
            if action.dest not in common:
                action.help = argparse.SUPPRESS
        p.epilog = "Examples: consensus email person@example.com -o report.html | consensus handle --fast\nMore options: consensus scan --help-all"


def _unsupported_email_reason(email: str) -> str | None:
    """An internationalised address is unsupported here, not malformed: say so and offer its ASCII domain."""
    local, separator, domain = email.strip().rpartition("@")
    if not separator or email.isascii():
        return None
    if local.isascii():
        try:
            ascii_domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            ascii_domain = ""
        if ascii_domain:
            return ("internationalised domains are not supported as typed; skipping remote checks. "
                    f"Search the equivalent address instead: {local}@{ascii_domain}")
    return "addresses with non-ASCII characters before the @ are not supported; skipping remote checks"


def _option_hint(message: str, root: argparse.ArgumentParser) -> str:
    """Name the nearest real option when one was mistyped."""
    if not message.startswith("unrecognized arguments:"):
        return ""
    import difflib

    known, stack = set(), [root]
    while stack:
        parser = stack.pop()
        for action in parser._actions:
            known.update(option for option in action.option_strings if option.startswith("--"))
            if isinstance(action, argparse._SubParsersAction):
                stack.extend(action.choices.values())
    hints, elsewhere = [], []
    for token in message.split(":", 1)[1].split():
        name = token.split("=")[0]
        if name in known:                   # a real option of another command: "--json -> --json" helped nobody
            elsewhere.append(name)
            continue
        match = difflib.get_close_matches(name, known, n=1, cutoff=0.75) if name.startswith("--") else []
        if not match and name.startswith("--") and len(name) > 5:     # --region for --phone-region
            match = sorted(option for option in known if option.endswith(name[1:]) or name[2:] in option.split("-"))[:1]
        if match and f"{name} -> {match[0]}" not in hints:
            hints.append(f"{name} -> {match[0]}")
    text = f"\nDid you mean: {', '.join(hints)}? Every option: consensus scan --help-all" if hints else ""
    if elsewhere:
        text += (f"\n{', '.join(dict.fromkeys(elsewhere))} belongs to another command and is not accepted here. "
                 "To see this command's options, add --help to it.")
    return text


def build_parser(*, full_help: bool = False, color: bool = True, scan_defaults=None,
                 compact_errors: bool = False) -> argparse.ArgumentParser:
    class HelpParser(argparse.ArgumentParser):
        def __init__(self, *args, **kwargs):
            # Consensus's Printer owns colour. Python 3.14's formatter probes
            # stdout even while constructing the parser; terminal proxies may
            # have no file descriptor. Cover direct formatter construction in
            # add_subparsers as well as ArgumentParser._get_formatter.
            formatter = kwargs.pop("formatter_class", argparse.HelpFormatter)

            class PlainFormatter(formatter):
                def _set_color(self, color):
                    super()._set_color(False)

            super().__init__(*args, formatter_class=PlainFormatter, **kwargs)

        def print_help(self, file=None):
            Printer(color=color, stream=file).help(self)

        def error(self, message):
            message += _option_hint(message, p)
            if compact_errors:
                raise ValueError(message)
            super().error(message)

    p = HelpParser(prog="consensus", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action=_VersionAction, nargs=0, help="show the version and the database build")
    p.add_argument("--help-all", action="help", help="list all commands; use COMMAND --help-all for all scan options")
    sub = p.add_subparsers(dest="cmd")
    examples = sub.add_parser("examples", help="show copyable search examples and explain what they do")
    examples.add_argument("--no-color", action="store_true", help="use plain output without colours")
    shell = sub.add_parser("shell", help="keep Consensus open with menus and short commands")
    shell.add_argument("--no-color", action="store_true", help="use plain output without colours")
    shell.add_argument("--no-footer", action="store_true", help="keep the menu without the pinned footer")
    shell.add_argument("--no-animation", action="store_true", help="disable footer and terminal-tab animations")
    info = sub.add_parser("info", help="show working folder, report location, version and repository")
    info.add_argument("--no-color", action="store_true", help="use plain output without colours")
    about = sub.add_parser("about", help="show the Society, project links and responsible-use guidance")
    about.add_argument("--no-color", action="store_true", help="use plain output without colours")
    terminal = sub.add_parser("terminal", help="set up the Consensus icon in a dedicated Windows Terminal tab")
    terminal.add_argument("action", nargs="?", choices=("show", "install", "remove"), default="show")

    for name, help_ in (("scan", "scan identifiers (type auto-detected)"), ("user", "scan a username"),
                        ("email", "scan an e-mail address"), ("phone", "scan a phone number")):
        sp = sub.add_parser(name, help=help_, formatter_class=argparse.RawDescriptionHelpFormatter)
        sp.add_argument("queries", nargs="*", help="identifier(s) to look up; start one with username:, email: or phone: to state its type")
        add_scan_options(sp, full_help=full_help)
        if scan_defaults:
            sp.set_defaults(**scan_defaults)

    st = sub.add_parser("sites", help="browse the site database")
    st.add_argument("action", choices=['list', 'info', 'tags', 'stats', 'disable', 'enable'], nargs="?", default="stats")
    st.add_argument("args", nargs="*", help="list: words to look for in the id, name or address; "
                                            "info, disable, enable: one or more site ids or names")
    st.add_argument("--tags", type=_nonempty_selector, action=_JoinedSelector, help="list: only sites with these tags or categories (comma-separated)")
    st.add_argument("--source", type=_nonempty_selector, action=_JoinedSelector, help="list: only sites from these upstream lists (comma-separated)")
    st.add_argument("--nsfw", action="store_true", help="list: include adult sites")
    st.add_argument("--all-sites", action="store_true", help="list: include disabled sites")
    st.add_argument("--json", action="store_true", help="machine-readable output")

    md = sub.add_parser("modules", help="list code modules")
    md.add_argument("--kind", choices=["username", "email", "phone"])
    md.add_argument("--family", type=_nonempty_selector, action=_JoinedSelector)
    md.add_argument("--json", action="store_true")




    rp = sub.add_parser("report", help="render a saved JSON scan into another format")
    rp.add_argument("json_file", help="saved scan results: a .json (or .jsonl) file written by scan -o")
    rp.add_argument("-o", "--output", required=True, action=_SingleOutput,
                    help="report to write; the extension selects the format, e.g. report.html or evidence.graph.html")
    rp.add_argument("-f", "--format", choices=["txt", "json", "jsonl", "csv", "md", "html", "pdf", "neo4j", "xmind", "graph-html"],
                    help="report format, when the output extension does not select one")
    rp.add_argument("-a", "--all", action="store_true", help="include every saved result, not only found ones")
    rp.add_argument("--compare-queries", action=argparse.BooleanOptionalAction, default=None,
                    help="compare across saved queries, or use --no-compare-queries to keep them separate")

    ks = sub.add_parser("keys", help="manage API keys (hibp, numverify, abstractapi, openai ...)")
    ks.add_argument("action", choices=["set", "remove", "list", "path"],
                    help="set NAME VALUE stores a key; remove NAME deletes it; list shows the names in use, never "
                         "the values; path shows the settings file")
    ks.add_argument("args", nargs="*", help="NAME and VALUE for set; NAME for remove")


    mc = sub.add_parser("mcp", help="run the Model Context Protocol server for AI agents")
    mc.add_argument("--transport", default="stdio", choices=["stdio", "sse", "streamable-http"])
    sub.add_parser("version")
    upd = sub.add_parser("update", help="install the latest Consensus release")
    upd.add_argument("--check", action="store_true", help="check the application version without installing")
    upd.add_argument("--catalogue", action="store_true", help="check the signed catalogue build without installing")
    upd.add_argument("--json", action="store_true", help="check only; return version information as JSON")
    recovery = upd.add_mutually_exclusive_group()
    recovery.add_argument("--repair", action="store_true", help="reinstall the active version using its verified cached wheel")
    recovery.add_argument("--rollback", action="store_true", help="restore the previous validated version")
    recovery.add_argument("--feed", help="install from a private bundle directory")
    return p


def pasted_form_hint(query: str, kind: str) -> str | None:
    """The identifier probably meant when one was pasted with its wrapping. The search itself is not
    changed: the typed text is still looked up, because a wrapped form can be a real identifier."""
    import re

    text = query.strip()
    if kind == "email":
        found = re.search(r"[^\s<>()\[\],;:\"']+@[^\s<>()\[\],;:\"']+\.[^\s<>()\[\],;:\"'.]+", text)
        likely, how = (found.group(0) if found else None), "email"
    elif kind == "username":
        how = "user"
        likely = text.strip("\"'<>()[]").rstrip(".,;:!?")
        if "://" in likely or re.match(r"^(?:www\.)?[\w-]+(?:\.[\w-]+)+/", likely):
            likely = likely.split("?")[0].split("#")[0].rstrip("/").rsplit("/", 1)[-1]
        elif re.match(r"^[ur]/[^/]+$", likely):
            likely = likely[2:]
        likely = likely.lstrip("@")
    else:
        return None
    if not likely or likely == text or any(char.isspace() or char in ":/" for char in likely):
        return None
    return (f'"{text}" looks like a pasted {"address" if kind == "email" else "profile link or handle"}; it is searched exactly '
            f'as typed. If you meant {likely}, run: consensus {how} "{likely}"')


def _not_a_search(word: str) -> int:
    print(f'consensus: "{word}" is not a command, and searching for it as a username would start a full lookup.\n'
          f"Did you mean: {NOT_A_SEARCH[word.lower()]}\n"
          f"To search for the word itself: consensus user {word}    All commands: consensus --help", file=sys.stderr)
    return 2


def normalise_argv(argv: list) -> list:
    if not argv:
        return ["--help"]
    first = argv[0]
    if first.lower() == "help":
        # "consensus help [anything]" used to look the words up as usernames on every
        # site. The name itself stays searchable: consensus user help
        return [*[word for word in argv[1:2] if word in SUBCOMMANDS], "--help"]
    if first.lower() in NOT_A_SEARCH:
        raise SystemExit(_not_a_search(first))
    if first in SUBCOMMANDS or first in ("-h", "--help", "--help-all", "--version"):
        if first == "username":
            return ["user"] + argv[1:]
        return argv
    return ["scan"] + argv


# ---------------------------------------------------------------------------
# scan engine
def _route(args: argparse.Namespace) -> tuple[str | None, bool]:
    """The proxy and Tor choice for every command that contacts sites: option, then environment, then settings.

    Every scan must honour the configured route to avoid exposing the
    user's address through the others.
    """
    cfg = get_config().get("defaults", {})
    proxy = getattr(args, "proxy", None) or os.environ.get("CONSENSUS_PROXY") or cfg.get("proxy")
    if proxy:
        try:
            proxy = _proxy_arg(proxy)
        except argparse.ArgumentTypeError as exc:
            origin = ("--proxy" if getattr(args, "proxy", None) else "the CONSENSUS_PROXY environment variable"
                      if os.environ.get("CONSENSUS_PROXY") else "defaults.proxy in the configuration file")
            raise ValueError(f"{exc} (from {origin})") from exc
    return proxy, bool(getattr(args, "tor", False) or cfg.get("tor") is True)


# ---------------------------------------------------------------------------
class Scanner:
    def __init__(self, args: argparse.Namespace, printer: Printer):
        self.args = args
        self.printer = printer
        cfg = get_config().get("defaults", {})
        self.concurrency = _positive_int(args.concurrency if args.concurrency is not None else cfg.get("concurrency", 100))
        self.timeout = _positive_float(args.timeout if args.timeout is not None else cfg.get("timeout", 15))
        proxy, tor = _route(args)
        self.tor = tor
        if unused := unused_settings():
            printer.warn(f"settings with no effect in {config_path()}: {', '.join(unused)}. Recognised defaults: "
                         f"{', '.join(KNOWN_DEFAULTS)}.")
        self.http = Http(timeout=self.timeout, proxy=proxy, tor=tor, verify=not args.no_verify,
                         max_connections=max(50, self.concurrency * 2),
                         per_host=max(1, getattr(args, "per_host", 4) or 4),
                         impersonate=None if args.no_impersonate else "chrome")
        if printer.terminal_ui:
            printer.terminal_ui.refresh_network(self.http.proxy)
        if getattr(args, "flaresolverr", None):
            from .core.flaresolverr import FlareSolverr

            self.http.flaresolverr = FlareSolverr(args.flaresolverr, proxy=self.http.proxy)
        if getattr(args, "browser", False):
            from .core.browser import BrowserFetcher

            self.http.browser = BrowserFetcher(proxy=self.http.proxy, max_pages=args.browser_pages,
                                               headless=not args.browser_visible, timeout=self.timeout + 20)
        self.ctx = Context(client=self.http.client, http=self.http, timeout=self.timeout, proxy=self.http.proxy,
                           allow_loud=args.allow_loud, options={"nsfw": args.nsfw, "extract": not args.no_extract})
        self.db: SiteDB | None = None
        self.matcher = None
        options = {k: v for k, v in vars(args).items() if k not in ("queries",) and not k.startswith("_")}
        options["proxy"] = redact_proxy(self.http.proxy)  # never write credentials into reports
        self.summary = ScanSummary(options=options)
        self._streamed: list = []   # every finding as it arrives, so an interrupted scan keeps them
        self.unchecked: list = []   # queries whose filters left nothing to run: not a negative result
        self.seen: set = set()
        self.site_index: dict = {}
        self._coverage = None
        self._query_context = ContextVar("query_relationship", default=None)
        self.continuation = getattr(args, "_continuation", None)

    # ------------------------------------------------------------- helpers
    def sites_db(self) -> SiteDB:
        if self.db is None:
            self.db = SiteDB.load()
            self.site_index = {s.id: s for s in self.db.sites}
        return self.db

    def _csv(self, v: str | None) -> list | None:
        return [x.strip() for x in v.split(",") if x.strip()] if v else None

    def select_sites(self, id_type: str = "username") -> list:
        if self.args.no_sites:
            return []
        db = self.sites_db()
        return db.select(ids=self._csv(self.args.site), exclude=self._csv(self.args.exclude), tags=self._csv(self.args.tags),
                         exclude_tags=self._csv(self.args.exclude_tags), include_nsfw=self.args.nsfw,
                         include_disabled=self.args.all_sites, id_type=id_type,
                         sources=self._csv(self.args.source), tor=self.tor)

    def select_modules(self, kind: str) -> list:
        if self.args.no_modules:
            return []
        from .core.sitesdb import overrides_disabled_ids

        fams = self._csv(self.args.family)
        mods = all_modules(kind=kind, families=fams)
        if not getattr(self.args, "all_sites", False):
            off = overrides_disabled_ids()
            mods = [m for m in mods if m.id not in off]
        only = {x.lower() for x in (self._csv(self.args.site) or [])}
        skip = {x.lower() for x in (self._csv(self.args.exclude) or [])}
        tags = {x.lower() for x in (self._csv(self.args.tags) or [])}
        xtags = {x.lower() for x in (self._csv(self.args.exclude_tags) or [])}
        out = []
        for m in mods:
            if m.disabled_reason and not only and not getattr(self.args, "all_sites", False):
                continue
            keys = _module_keys(m)
            if only and not (keys & only):
                continue
            if keys & skip:
                continue
            if m.nsfw and not self.args.nsfw and not only:
                continue
            if self.args.no_breach and m.category == "breach":
                continue
            if tags and not ({m.category} | set(m.tags)) & tags:
                continue
            if xtags and ({m.category} | set(m.tags)) & xtags:
                continue
            out.append(m)
        # After every other filter, so that if a family's check has been disabled by
        # configuration, the duplicate from another family steps in for it.
        if not getattr(self.args, "all_modules", False):
            from .core.modules import dedupe_modules

            out, _ = dedupe_modules(out)
        if hasattr(self, "summary"):
            self.summary.options.setdefault("breach_plan", {})[kind] = {
                "selected": [m.id for m in out if m.category == "breach"],
                "held": [{"site": m.name, "reason": m.disabled_reason} for m in mods
                         if m.category == "breach" and m.disabled_reason],
            }
        return out

    def _finish(self, findings: list, query: str, depth: int, parent: str | None) -> list:
        from .core.confidence import base_confidence

        for f in findings:
            f.depth = depth
            if parent and not f.parent:
                f.parent = parent
            if f.status is Status.FOUND and f.confidence is None:
                site = self.site_index.get(f.site_id) if f.source == "sites-db" else None
                f.confidence = base_confidence(f, site)
        return findings

    # ------------------------------------------------------------- scans
    async def scan_username(self, username: str, depth: int = 0, parent: str | None = None, id_type: str = "username") -> list:
        from .core.modules import limit_plan
        from .core.runner import run_all

        sites = self.select_sites(id_type=id_type)
        modules = self.select_modules("username") if id_type == "username" else []
        paired = []
        # an explicit --site selection is the user's plan; otherwise ask each service once
        if sites and modules and not getattr(self.args, "all_modules", False) and not self.args.site:
            from .core.modules import reconcile_plan

            sites, modules, paired = reconcile_plan(sites, modules, ctx=self.ctx, query=username)
        if self.continuation:
            sites = self.continuation.select(username, id_type, sites, "site:")
            modules = self.continuation.select(username, id_type, modules, "module:")
            sites, modules = self.continuation.exclude_completed_alternatives(username, id_type, sites, modules, paired)
        limit = self.args.top or (300 if getattr(self.args, "fast", False) else None)
        if limit:
            sites, modules = limit_plan(sites, modules, limit, self.sites_db().sites, paired)
        total = len(sites) + len(modules)
        # Switching every check off (--no-sites --no-modules) is a deliberate dry run;
        # a filter that happens to select nothing is a mistake worth explaining.
        if not total and depth == 0 and not self.args.no_sites and not self.continuation:
            self.unchecked.append(username)
            self.printer.warn(f"Nothing was checked for {username}: the chosen filters (--site, --tags, --exclude, --source "
                              "and similar) leave no sites or modules for this search. This is not a negative result.")
        self.printer.message(f"{total} sites being scanned for this {id_type}", "dim")
        self.printer.activity("Scanning", self._tool_names(sites, modules))
        self.printer.start_progress(total, f"scanning {username}")
        try:
            findings = await run_all(username, sites=sites, modules=modules, http=self.http, ctx=self.ctx,
                                     concurrency=self.concurrency, on_result=self._collect,
                                     extract=not self.args.no_extract, query_type=id_type, delay=self.args.delay,
                                     per_host=max(1, getattr(self.args, "per_host", 4) or 4))
        finally:
            self.printer.stop_progress()
        findings = self._finish(findings, username, depth, parent)

        if id_type == "username" and self.args.search_engines and not self.continuation:
            findings += await self._search_engines(username, depth, parent)
        if id_type == "username" and self.args.mailcat and not self.continuation:
            findings += await self._mailcat(username, depth, parent)
        return findings

    async def _search_engines(self, username: str, depth: int, parent: str | None) -> list:
        from .core.scan_control import checkpoint

        await checkpoint()
        try:
            from .core.searchengines import search_username, to_findings
        except Exception as exc:  # noqa: BLE001
            self.printer.warn(f"search engines unavailable: {exc}")
            return []
        self.printer.message(f"-- search engines for {username} --", "cyan")
        try:
            results = await search_username(username, self.http)
        except Exception as exc:  # noqa: BLE001
            self.printer.warn(f"search engines failed: {exc}")
            return []
        # Keep profile leads and engine issues; generic search mentions are omitted.
        fs = [f for f in to_findings(username, results) if f.status is Status.FOUND or f.error]
        for f in fs:
            self._collect(f)
            if f.error:
                self.printer.warn(f"{f.site}: {f.error}")
        if not fs:
            self.printer.message("   no profile links found via search engines", "dim")
        return self._finish(fs, username, depth, parent)

    async def _mailcat(self, username: str, depth: int, parent: str | None) -> list:
        from .core.scan_control import checkpoint

        await checkpoint()
        try:
            from .core.mailcat import find_emails
        except Exception as exc:  # noqa: BLE001
            self.printer.warn(f"mailcat unavailable: {exc}")
            return []
        self.printer.message(f"-- mailbox discovery for {username} --", "cyan")
        try:
            fs = await find_emails(username, self.http, timeout=self.timeout)
        except Exception as exc:  # noqa: BLE001
            self.printer.warn(f"mailcat failed: {exc}")
            return []
        for f in fs:
            self._collect(f)
        return self._finish(fs, username, depth, parent)

    async def scan_email(self, email: str, depth: int = 0, parent: str | None = None) -> list:
        from .core.emailinfo import async_dns_info, local_analysis, to_finding
        from .core.runner import run_modules

        continuation = getattr(self, "continuation", None)
        modules = None
        if continuation:
            modules = continuation.select(email, "email", self.select_modules("email"), "module:")
            if not modules and continuation.mode != "recheck":
                return []

        self.printer.message("   analysing address and domain…", "dim")
        self.printer.activity("Analysing email domain", ["Consensus"])
        info = await asyncio.to_thread(local_analysis, email, resolve_dns=False)
        local = to_finding(info, email)
        if continuation and continuation.mode != "recheck":
            # Keep the original domain evidence and its collection time when
            # only adding lookup coverage; do not replace it with partial data.
            import copy
            previous = next((f for f in continuation.previous.findings
                             if f.query == email and f.query_type == "email" and f.site_id == local.site_id), None)
            if previous:
                local = copy.deepcopy(previous)
        # Machine streams cannot revise an emitted row. Delay their background
        # record until DNS finishes (or cancellation retains the partial data).
        if not self.printer.jsonl or not info.get("valid_syntax"):
            self._collect(local)
        if not info.get("valid_syntax"):
            self.printer.warn(_unsupported_email_reason(email) or "invalid e-mail syntax; skipping remote checks")
            return self._finish([local], email, depth, parent)
        if info.get("disposable"):
            self.printer.warn("disposable e-mail domain")
        if modules is None:
            modules = self.select_modules("email")
        limit = getattr(self.args, "top", None) or (300 if getattr(self.args, "fast", False) else None)
        if limit:
            from .core.modules import limit_plan

            _, modules = limit_plan([], modules, limit, self.sites_db().sites)
        self.printer.activity("Scanning", self._tool_names([], modules))
        self.printer.message(f"   {len(modules)} sites being scanned for this email", "cyan")
        self.printer.start_progress(len(modules), f"checking {email}")
        async def domain_analysis():
            from .core.scan_control import checkpoint

            await checkpoint()
            if continuation and continuation.mode != "recheck":
                return
            if not continuation or continuation.mode == "recheck":
                info.update(await async_dns_info(info["domain"]))
            # Update the already collected background finding in place. It is
            # not a second site result and must not increment progress counters.
            updated = to_finding(info, email)
            local.status = updated.status
            local.extra.update(updated.extra)

        dns_task = asyncio.create_task(domain_analysis())
        try:
            findings = await run_modules(email, modules, self.ctx, concurrency=min(self.concurrency, 60),
                                         on_result=self._collect, delay=self.args.delay, per_host=self.args.per_host)
            if not dns_task.done():
                self.printer.activity("Finishing email domain analysis", ["Consensus"])
            await dns_task
        finally:
            if not dns_task.done():
                dns_task.cancel()
            await asyncio.gather(dns_task, return_exceptions=True)
            self.printer.stop_progress()
            if self.printer.jsonl:
                self._collect(local)
        return self._finish([local] + findings, email, depth, parent)

    async def scan_phone(self, number: str, depth: int = 0, parent: str | None = None) -> list:
        from .core.runner import run_modules
        from .core.scan_control import checkpoint

        self.printer.activity("Analysing phone number", ["Consensus"])
        findings: list = []
        try:
            from .core import phone as phone_mod
        except Exception as exc:  # noqa: BLE001
            self.printer.warn(f"phone analysis unavailable: {exc}")
            phone_mod = None
        e164 = number
        if phone_mod is not None:
            info = phone_mod.parse_number(number, getattr(self.args, "phone_region", None))
            for f in phone_mod.to_findings(info, number):
                self._collect(f)
                findings.append(f)
            if not info.get("valid"):
                # A number that parsed but is unassigned is not "unparseable": give the recorded reason.
                self.printer.warn(f"number not valid: {info.get('error') or info.get('validation') or 'not an assigned number'}")
                return self._finish(findings, number, depth, parent)
            if info.get("online_allowed") is False:
                self.printer.warn("Online phone lookups were not run because no country was supplied. "
                                  "Enter + and the country code, or use --phone-region GB for a UK number. "
                                  "The displayed number analysis is offline; suggested search links have not been searched.")
                return self._finish(findings, number, depth, parent)
            e164 = info.get("e164") or number
            scoped = any((self.args.site, self.args.exclude, self.args.tags, self.args.exclude_tags))
            service_options = {"selected": phone_mod.select_services(
                ids=self._csv(self.args.site), exclude=self._csv(self.args.exclude),
                tags=self._csv(self.args.tags), exclude_tags=self._csv(self.args.exclude_tags),
            )} if scoped else {}
            if self.continuation:
                selected = service_options.get("selected", set(phone_mod.SERVICES))
                service_options["selected"] = {key for key in selected
                    if self.continuation.allows(number, "phone", "phone:" + key)}
            try:
                await checkpoint()
                self.printer.activity("Checking phone reputation")
                rep = await phone_mod.reputation(info, self.http, **service_options)
                for f in rep:
                    self._collect(f)
                findings += rep
            except Exception as exc:  # noqa: BLE001
                self.printer.warn(f"reputation lookups failed: {exc}")
            try:
                await checkpoint()
                self.printer.activity("Checking configured phone services")
                api = await phone_mod.api_lookups(info, self.http, **service_options)
                for f in api:
                    self._collect(f)
                findings += api
            except Exception as exc:  # noqa: BLE001
                self.printer.warn(f"API lookups failed: {exc}")
        modules = self.select_modules("phone")
        if self.continuation:
            modules = self.continuation.select(number, "phone", modules, "module:")
        self.printer.activity("Scanning", self._tool_names([], modules))
        self.printer.message(f"   {len(modules)} sites being scanned for this phone number", "cyan")
        self.printer.start_progress(len(modules), f"checking {e164}")
        def collect_phone(finding):
            # Send the normalized number, but keep every result under the user's
            # submitted query, including streamed and interrupted results.
            if finding.query_type == "phone" and finding.query == e164 and e164 != number:
                finding.extra["_normalized_query"] = e164
                finding.query = number
            self._collect(finding)

        try:
            findings += await run_modules(e164, modules, self.ctx, concurrency=min(self.concurrency, 20),
                                          on_result=collect_phone, delay=self.args.delay, per_host=self.args.per_host)
        finally:
            self.printer.stop_progress()
        return self._finish(findings, number, depth, parent)

    async def scan_query(self, query: str, qtype: str, depth: int = 0, parent: str | None = None) -> list:
        from .core.scan_control import checkpoint

        await checkpoint()
        key = (query, qtype)
        if key in self.seen:
            return []
        self.seen.add(key)
        self.summary.queries.append({"query": query, "type": qtype, "depth": depth, "parent": parent})
        self.printer.query_heading(query, qtype)
        token = self._query_context.set((depth, parent))
        try:
            if qtype == QueryType.EMAIL.value:
                return await self.scan_email(query, depth, parent)
            if qtype == QueryType.PHONE.value:
                return await self.scan_phone(query, depth, parent)
            if qtype == QueryType.USERNAME.value:
                return await self.scan_username(query, depth, parent)
            return await self.scan_username(query, depth, parent, id_type=qtype)
        finally:
            self._query_context.reset(token)

    @staticmethod
    def _tool_names(sites, modules):
        from .core.provenance import REPOSITORIES

        sources = {source for site in sites for source in site.sources}
        for module in modules:
            if module.source == "rules":
                sources.update(tag for tag in module.tags if tag in REPOSITORIES)
            else:
                sources.add(module.source)
        return sorted({REPOSITORIES[source][0] for source in sources if source in REPOSITORIES}
                      | ({"Consensus"} if sources & {"extras", "rules", "bundled"} else set()))

    def _collect(self, f: Finding) -> None:
        if f.source == "phone":
            f.extra.setdefault("_lookup_id", "phone:" + f.site_id)
        context = getattr(self, "_query_context", None)
        relationship = context.get() if context is not None else None
        if relationship is not None:
            f.depth, parent = relationship
            if parent and not f.parent:
                f.parent = parent
        if getattr(self, "_coverage", None) is None:
            from .core.provenance import CoverageIndex

            self._coverage = CoverageIndex.installed(self.sites_db().sites)
        self._coverage.annotate(f)
        self._streamed.append(f)
        self.printer(f)

    def partial_summary(self) -> ScanSummary:
        """What an interrupted scan has so far: every finding already streamed to
        the console, de-duplicated, so a Ctrl-C keeps the work that was done."""
        s = self.summary
        s.findings = dedupe_findings(list(s.findings) + list(self._streamed))
        s.finished = s.finished or time.time()
        s.options["interrupted"] = True
        return s

    async def run(self, queries: list) -> ScanSummary:
        from .core.continuity import inventory
        from .core.recursion import LinkMatcher, extract_pivots, plan_next_queries

        self.summary.options["lookup_inventory"] = inventory(self.sites_db().sites)

        frontier = [(q, t, 0, None) for q, t in queries]
        scheduled = {(q, t) for q, t in queries}
        pivots_per_depth: dict[int, int] = {}
        depth_limit = self.args.depth if self.args.recursive else 0
        while frontier:
            q, t, depth, parent = frontier.pop(0)
            findings = await self.scan_query(q, t, depth, parent)
            self.summary.findings.extend(findings)
            if depth < depth_limit and findings:
                if self.matcher is None:
                    self.matcher = LinkMatcher(self.sites_db())
                piv = extract_pivots(findings, self.matcher, known_queries=scheduled)
                for kind, values in piv.ids.items():
                    piv.ids[kind] = {v for v in values if (v, kind) not in scheduled}
                remaining = max(0, self.args.max_pivots - pivots_per_depth.get(depth + 1, 0))
                nxt = plan_next_queries(piv, max_new=remaining,
                                        known_id_types=set(self.sites_db().id_types()) - {"username"})
                nxt = [(nq, nt, depth + 1, q) for nq, nt, _ in nxt if (nq, nt) not in scheduled]
                if nxt:
                    scheduled.update((nq, nt) for nq, nt, _, _ in nxt)
                    pivots_per_depth[depth + 1] = pivots_per_depth.get(depth + 1, 0) + len(nxt)
                    self.printer.message(f"   pivots from {q}: " + ", ".join(f"{nq} ({nt})" for nq, nt, _, _ in nxt), "cyan")
                    frontier.extend(nxt)
        self.summary.finished = time.time()
        self.summary.findings = dedupe_findings(self.summary.findings)
        try:
            from .core.confidence import apply_consensus

            apply_consensus(self.summary.findings)
        except Exception:  # noqa: BLE001
            pass
        return self.summary

    def solver_stats(self) -> str | None:
        parts = []
        if self.http.flaresolverr is not None:
            s = self.http.flaresolverr.stats
            parts.append(f"flaresolverr: {s['solved']} solved, {s['failed']} failed")
        if self.http.browser is not None:
            s = self.http.browser.stats
            parts.append(f"browser ({self.http.browser.launched_channel or 'not started'}): {s['solved']} pages loaded, "
                         f"{s['still_blocked']} still challenged, {s['errors']} errors")
        return " · ".join(parts) if parts else None

    async def close(self) -> None:
        await self.http.aclose()


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def _read_input_text(path: str | Path) -> str:
    """Read UTF-8 input, also accepting explicit UTF-16/32 byte-order marks."""
    if str(path) == "-":
        stream = getattr(sys.stdin, "buffer", None)
        if stream is None:
            return sys.stdin.read().lstrip("\ufeff")
        data = stream.read()
    else:
        data = Path(path).expanduser().read_bytes()
    # Check UTF-32 first: its little-endian mark starts with the UTF-16 mark.
    if data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return data.decode("utf-32")
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16")
    return data.decode("utf-8-sig")


MAX_QUERY_LENGTH = 320  # longest e-mail address form; no supported identifier is longer

def _query_problem(value: str) -> str | None:
    """Explain why text cannot be an identifier, before anything is looked up."""
    if any(unicodedata.category(ch) == "Cc" for ch in value):
        return "contains control characters; save the list as UTF-8 text with one identifier per line"
    if len(value) > MAX_QUERY_LENGTH:
        return f"is longer than {MAX_QUERY_LENGTH} characters"
    return None


def _bounded(values: list, option: str, args: argparse.Namespace) -> list:
    """Apply --max-permutations and record a notice, so a cut-off list is never searched silently."""
    limit = args.max_permutations
    if len(values) > limit:
        notices = getattr(args, "expansion_notices", None)
        if notices is None:
            notices = args.expansion_notices = []
        notices.append(f"{option} produces more than {limit} names; only the first {limit} are searched. "
                       "Narrow it, or raise --max-permutations.")
    return values[:limit]


def expand_queries(args: argparse.Namespace) -> list:
    from .core.permutations import common_variants, expand_pattern, name_permutations

    entries = []            # (identifier, stated type or None), in the order the user gave them
    for query in args.queries or []:
        problem = _query_problem(query.strip())
        if problem:
            raise ValueError(f"query {problem}")
        value, kind = QueryType.split_typed(query)
        if kind and not value:
            raise ValueError(f"query {query.strip()!r}: {kind} requires an identifier")
        entries.append((value, kind))
    if args.input:
        for number, line in enumerate(_read_input_text(args.input).splitlines(), 1):
            line = line.strip()
            if line and not line.startswith("#"):
                problem = _query_problem(line)
                if problem:
                    raise ValueError(f"input line {number} {problem}")
                value, kind = QueryType.split_typed(line)
                if kind and not value:
                    raise ValueError(f"input line {number}: {kind} requires an identifier")
                entries.append((value, kind))
    if args.permute:
        entries += [(value, None) for value in _bounded(
            expand_pattern(args.permute, args.max_permutations + 1), "--permute", args)]
    if args.names:
        entries += [(value, None) for value in _bounded(
            name_permutations(args.names.split(), limit=args.max_permutations + 1), "--names", args)]
    forced = {"user": "username", "email": "email", "phone": "phone"}.get(args.cmd)
    if args.type != "auto":
        forced = args.type
    typed = []
    for query, kind in entries:
        if kind and forced and kind != forced:
            raise ValueError(f"input type {kind!r} conflicts with selected type {forced!r}")
        if query.strip():
            typed.append((query.strip(), kind or forced or QueryType.detect(query).value))
    if args.variants:
        # An alias keeps its parent's username type, even when adding digits
        # makes it look like a phone number to automatic detection.
        typed += [(alias, kind) for q, kind in typed if kind == "username" for alias in common_variants(q)]
    out, seen, repeats = [], set(), 0
    for q, t in typed:
        q = q.strip()
        if not q:
            continue
        k = (q, t)
        if k in seen:
            repeats += 1
            continue
        seen.add(k)
        out.append((q, t))
    if repeats and args.input:
        # A list that shrinks without a word looks like lost subjects when the totals are reconciled later.
        notices = getattr(args, "expansion_notices", None)
        if notices is None:
            notices = args.expansion_notices = []
        notices.append(f"{repeats} repeated entries were left out: each identifier is searched once "
                       f"({len(out)} searches). Upper and lower case count as different usernames.")
    return out


def _save_problem(exc: Exception, output: str | Path) -> str:
    """Describe a failed save by its destination, not by internal temporary files."""
    if isinstance(exc, PermissionError):
        return (f"could not save report to {output}: access was denied. The file may be read-only or open in "
                "another program, or the folder may not allow new files.")
    if isinstance(exc, OSError) and len(Path(output).name) > 200:
        return (f"could not save report: the file name is too long ({len(Path(output).name)} characters). "
                "Choose a shorter name.")
    if isinstance(exc, OSError) and exc.strerror:
        return f"could not save report to {output}: {exc.strerror}"
    return f"could not save report: {exc}"


def _format_note(output: str | Path, fmt: str | None) -> str | None:
    """Say so when -f overrides what the file ending suggests, because other programs trust the ending."""
    from .core.reports import infer_format

    if not fmt:
        return None
    try:
        implied = infer_format(str(output))
    except ValueError:
        return None
    if implied == fmt:
        return None
    return (f"{Path(output).name} contains {fmt} because -f {fmt} was given; "
            f"its ending suggests {implied}. Leave out -f to let the ending decide.")


class _SingleOutput(argparse.Action):
    """One report per run: a repeated -o used to discard the earlier file name without a word."""

    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"-o was given twice ({getattr(namespace, self.dest)} and {values}). Save one report, then "
                         'create other formats from it: consensus report SAVED.json -o OTHER.html')
        setattr(namespace, self.dest, values)


class _JoinedSelector(argparse.Action):
    """A repeated selector adds to the earlier one: --site a --site b used to search b alone."""

    def __call__(self, parser, namespace, values, option_string=None):
        earlier = getattr(namespace, self.dest, None)
        setattr(namespace, self.dest, f"{earlier},{values}" if earlier else values)


def _rescue_results(summary: ScanSummary, failed: Path) -> Path | None:
    """Keep every result as JSON after a failed save, so the search need not be repeated."""
    from .core.reports import save_report
    from .core.session_info import SessionInfo

    name = f"{failed.stem[:60] or 'results'}-recovered-{time.strftime('%Y%m%d-%H%M%S')}.json"
    for folder in (failed.parent, SessionInfo.current().report_folder):
        try:
            return save_report(summary, folder / name, "json", include_all=True).resolve()
        except Exception:  # noqa: BLE001 - try the next location; the original failure is already reported
            continue
    return None


def cmd_scan(args: argparse.Namespace, *, on_summary=None, in_session=False) -> int:
    from .core.terminal_ui import TerminalUI, current_ui, supported

    if (not in_session and current_ui() is None and not args.no_footer and not args.quiet
            and not args.jsonl and not (args.format and not args.output)
            and supported(color=not args.no_color)):
        return TerminalUI(animate=not args.no_animation, network=True).run(lambda read: cmd_scan(args, on_summary=on_summary))
    try:
        queries = expand_queries(args)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"cannot read scan inputs: {exc}", file=sys.stderr)
        return 2
    if not queries:
        print("nothing to scan: give at least one username, e-mail or phone number", file=sys.stderr)
        return 2
    if args.output and Path(args.output).expanduser().is_dir():
        print("output is a directory: give a report filename, such as reports/results.html", file=sys.stderr)
        return 2
    if args.output:
        for parent in Path(args.output).expanduser().parents:
            if parent.exists() and not parent.is_dir():
                print(f"output parent is not a directory: {parent}", file=sys.stderr)
                return 2
    if args.output and args.input and args.input != "-":
        target, listing = Path(args.output).expanduser(), Path(args.input).expanduser()
        if target.exists() and listing.exists() and target.samefile(listing):
            print(f"{args.output} is the list of identifiers being read (-i); choose another report name so the "
                  "list is kept", file=sys.stderr)
            return 2
    if args.output and not args.format:   # fail before the scan, not after it
        from .core.reports import infer_format

        try:
            infer_format(args.output)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if not args.output and args.format in ("html", "pdf", "neo4j", "xmind", "graph-html"):
        print(f"format {args.format} requires --output", file=sys.stderr)
        return 2
    stdout_report = args.format is not None and not args.output and not args.jsonl
    printer = Printer(show_all=args.all, quiet=args.quiet or stdout_report, jsonl=args.jsonl,
                      color=not args.no_color, verbose=args.verbose,
                      details=args.details, summary_limit=args.summary_limit, live_limit=args.live_limit,
                      stream=sys.stderr if stdout_report else sys.stdout, animate=not args.no_animation)
    scanner = None
    def prepare():
        printer.separator("New search")
        printer.message(f"consensus {__version__} - {len(queries)} quer{'y' if len(queries) == 1 else 'ies'}", "bold")
        if not in_session:
            printer.identity(__version__)
            printer.session_information(args.output)
        _announce_database(printer)
        for notice in getattr(args, "expansion_notices", None) or []:
            printer.warn(notice)
        for value, kind in queries[:20]:
            if hint := pasted_form_hint(value, kind):
                printer.warn(hint)
        if args.no_verify:
            printer.warn("TLS certificate verification is off (--no-verify): replies cannot be tied to the genuine "
                         "service, so treat these results with extra care.")
        if args.site:   # a selector that matches nothing used to be dropped silently
            known: set = set()
            if any(kind == "phone" for _, kind in queries):
                from .core.phone import SERVICES, service_keys

                for service_id in SERVICES:
                    known |= service_keys(service_id)
            for site in scanner.sites_db().sites:
                known |= site_keys(site)
            if not args.no_modules:
                for m in all_modules():
                    known |= _module_keys(m)
            missing = [t for t in scanner._csv(args.site) if t.lower() not in known]
            if missing:
                from .core.rules import load_rules

                superseded = {str(r.get("replaces")).lower(): "rule-" + str(r.get("id")) for r in load_rules() if r.get("replaces")}
                for t in list(missing):
                    if t.lower() in superseded:
                        printer.warn(f"--site {t}: that code module is now the data rule {superseded[t.lower()]} (use that id)")
                        missing.remove(t)
                if missing:
                    printer.warn(f"--site {', '.join(missing)}: no site or module has that id, name or domain "
                                 "(see: consensus sites list)")
        if args.tags and not any(kind == "phone" for _, kind in queries):
            known_tags = {str(tag).lower() for tag in scanner.sites_db().all_tags()}
            if not args.no_modules:
                known_tags |= {str(m.category).lower() for m in all_modules() if m.category}
            unknown = [t for t in scanner._csv(args.tags) if t.lower() not in known_tags]
            if unknown:
                printer.warn(f"--tags {', '.join(unknown)}: no site or module has that tag or category "
                             "(see: consensus sites tags)")
        if not (args.fast or args.top or args.site or args.tags or args.source or args.no_sites or args.quiet or args.jsonl) and any(t == "username" for _, t in queries):
            printer.message("tip: this scans the full site list; add --fast for a quick look at the most popular ones.", "dim")

    solver_line = None

    async def go():
        nonlocal solver_line, scanner
        from .core.scan_control import scan_controls

        try:
            async with scan_controls(printer) as control:
                try:
                    scanner = Scanner(args, printer)
                    prepare()
                    return await scanner.run(queries)
                except asyncio.CancelledError:
                    if control.stopping and scanner is not None:
                        return scanner.partial_summary()
                    raise
        finally:
            if scanner is not None:
                try:
                    solver_line = scanner.solver_stats()
                finally:
                    await scanner.close()

    interrupted = False
    previous_animation = printer.terminal_ui.animate if printer.terminal_ui else None
    try:
        if printer.terminal_ui and args.no_animation:
            printer.terminal_ui.update(animate=False)
        printer.tab_progress.start()
        printer.start_preparation()
        summary = asyncio.run(go())
    except KeyboardInterrupt:
        if scanner is None:
            return 130
        summary = scanner.partial_summary()
        interrupted = True
        n = len(summary.findings)
        printer.warn(f"interrupted - keeping the {n} result{'s' if n != 1 else ''} gathered so far")
    finally:
        try:
            printer.stop_preparation()
        finally:
            printer.tab_progress.clear()
            if printer.terminal_ui:
                printer.terminal_ui.update(animate=previous_animation)
    if solver_line:
        printer.message(solver_line, "dim")
    interrupted = interrupted or bool(summary.options.get("interrupted"))
    if getattr(args, "_continuation", None):
        summary = args._continuation.merge(summary)
    if on_summary is not None:
        on_summary(summary)

    # ---------------------------------------------------------------- summary
    counts = summary.counts()
    found = summary.found
    review_results = in_session and printer.terminal_ui and not printer.quiet and not printer.jsonl and not args.format
    if not review_results:
        printer.finish(summary)
    checked = sum(counts.get(k, 0) for k in ("found", "not_found", "unknown", "blocked", "rate_limited", "error"))
    if checked >= 3 and counts.get("error", 0) >= 0.9 * checked:
        via = " or proxy" if (getattr(args, "proxy", None) or getattr(args, "tor", False)) else ""
        printer.warn(f"{counts.get('error', 0)} of {checked} requests failed with network errors - "
                     f"a 'found 0' here means nothing; check your connection{via} (-v shows the errors)")
    if args.browse:
        for f in found[:50]:
            if f.url and f.url.startswith("http"):
                webbrowser.open(f.url)
    save_failed = False
    if args.output:
        try:
            from .core.reports import save_report

            if printer.terminal_ui:
                printer.terminal_ui.update("Saving report")
            path = save_report(summary, args.output, args.format, include_all=args.all)
            printer.report_saved(path)
            if note := _format_note(args.output, args.format):
                printer.warn(note)
        except Exception as exc:  # noqa: BLE001
            printer.warn(_save_problem(exc, args.output))
            rescued = _rescue_results(summary, Path(args.output).expanduser())
            if rescued is not None:
                printer.warn(f"Your results were kept: {rescued}")
                printer.warn(f'Create a report from them without searching again: consensus report "{rescued}" -a -o NEW_NAME.html')
            save_failed = True
            if args.debug:
                raise
    elif args.format in ("json", "jsonl", "csv", "md", "txt") and not args.jsonl:
        # a format without an output file: render to stdout
        try:
            from .core import reports

            text = reports.render(summary, args.format, include_all=args.all)
            buffer = getattr(sys.stdout, "buffer", None)
            if buffer is not None and not sys.stdout.isatty():
                # Preserve CSV's own CRLF records when redirected on Windows;
                # TextIO newline translation would turn them into CRCRLF.
                sys.stdout.flush()
                buffer.write(text.encode("utf-8"))
                buffer.flush()
            else:
                sys.stdout.write(text)
        except Exception as exc:  # noqa: BLE001
            printer.warn(f"could not render {args.format}: {exc}")
            save_failed = True
    if args.ai:
        try:
            from .core.ai import summarize
            from .core.scan_control import scan_controls

            async def request_summary():
                async with scan_controls(printer) as control:
                    if printer.terminal_ui:
                        printer.terminal_ui.update(found=printer.match_count, enriched=printer.detail_count)
                    printer.activity("Summarizing results", ["AI"])
                    try:
                        return await summarize(summary)
                    except asyncio.CancelledError:
                        if control.stopping:
                            return None
                        raise

            try:
                text = asyncio.run(request_summary())
            except KeyboardInterrupt:
                text = None
            if text is None:
                interrupted = True
                printer.warn("AI summary cancelled; collected search results are retained.")
            else:
                ai_printer = Printer(stream=sys.stderr if args.jsonl or stdout_report else sys.stdout,
                                     color=not args.no_color)
                ai_printer.message("\n== AI summary ==", "bold cyan")
                ai_printer.message(text)
        except Exception as exc:  # noqa: BLE001
            printer.warn(f"AI summary failed: {exc}")
    nothing_checked = bool(getattr(scanner, "unchecked", None)) and not summary.findings and not interrupted
    if nothing_checked:
        printer.warn("No checks ran, so 'no matches' above does not mean that no accounts exist. Correct the filters "
                     "(see: consensus sites list, consensus sites tags) and search again.")
    checks = [f for f in summary.findings if f.category not in ("analysis", "dorks")]
    if checks and not interrupted and all(f.status == Status.SKIPPED for f in checks):
        reasons = list(dict.fromkeys(f.error for f in checks if f.error))[:3]
        printer.warn(f"Every selected check was skipped ({len(checks)}), so no site was contacted and 'no matches' "
                     "does not mean that no accounts exist." + (" Reasons: " + "; ".join(reasons) if reasons else ""))
    if not in_session:
        printer.command_menu()
    if review_results:
        printer.finish(summary, review=True, follow_end=True)
    if interrupted:
        return 130
    if save_failed:
        return 1
    return 2 if nothing_checked else 0


def _no_site_message(db: SiteDB, key: str) -> str:
    """Searches accept a service name that covers several entries; site commands need one exact id."""
    wanted = key.strip().lower()
    candidates = [site.id for site in db.sites if wanted in site_keys(site)]
    if not candidates:
        return f"no site matches {key!r}"
    shown = ", ".join(candidates[:12]) + (f" and {len(candidates) - 12} more" if len(candidates) > 12 else "")
    return f"{key!r} is not one site: --site {key} covers {len(candidates)} entries. Use an exact id: {shown}"


def cmd_sites(args: argparse.Namespace) -> int:
    if args.action in ("info", "enable", "disable") and not args.args:
        print(f"give at least one site id or name: consensus sites {args.action} SITE [SITE ...]", file=sys.stderr)
        return 2

    db = SiteDB.load()
    if args.action == "stats":
        st = db.stats()
        print(json.dumps(st, indent=1) if args.json else "\n".join(
            f"{k.replace('_', ' ')}: {', '.join(map(str, v)) if isinstance(v, (list, tuple, set)) else v}" for k, v in st.items()))
        return 0
    if args.action == "tags":
        tags = db.all_tags()
        print(json.dumps(tags, indent=1) if args.json else "\n".join(f"{t:<20} {n}" for t, n in tags.items()))
        return 0
    if args.action == "list":
        tags = [t.strip() for t in args.tags.split(",")] if args.tags else None
        srcs = [t.strip() for t in args.source.split(",")] if args.source else None
        sites = db.select(tags=tags, include_nsfw=args.nsfw, include_disabled=args.all_sites, sources=srcs)
        words = [word.lower() for word in args.args]
        if words:        # consensus sites list git: the words used to be ignored and every site was printed
            sites = [s for s in sites if all(any(word in text.lower() for text in (s.id, s.name or "", s.url or ""))
                                             for word in words)]
        if args.json:
            print(json.dumps([s.to_dict() for s in sites], ensure_ascii=False, indent=1))
        else:
            for s in sites:
                flag = (f" (restricted: {s.audit_disabled_reason})" if s.audit_disabled_reason
                        else " (disabled)" if s.disabled else "")
                print(f"{s.id:<40} {s.category:<12} {s.url}{flag}")
            print(f"{len(sites)} sites" + (f" matching {' '.join(args.args)}" if words else ""), file=sys.stderr)
        return 0
    if args.action == "info":
        sites = [db.get(key) for key in args.args]
        if args.json:
            results = [site.to_dict() if site else None for site in sites]
            print(json.dumps(results[0] if len(results) == 1 else results, ensure_ascii=False, indent=1))
            for key, site in zip(args.args, sites, strict=True):
                if site is None:
                    print(_no_site_message(db, key), file=sys.stderr)
        else:
            for key, site in zip(args.args, sites, strict=True):
                print(json.dumps(site.to_dict(), ensure_ascii=False, indent=1) if site else _no_site_message(db, key))
        return 1 if any(site is None for site in sites) else 0
    if args.action in ("disable", "enable"):
        sites = [db.get(key) for key in args.args]
        missing = [key for key, site in zip(args.args, sites, strict=True) if site is None]
        if missing:
            for key in missing:
                print(f"{_no_site_message(db, key)}; no overrides changed", file=sys.stderr)
            return 1
        ids = list(dict.fromkeys(site.id for site in sites))
        path = save_override(disable=ids if args.action == "disable" else None, enable=ids if args.action == "enable" else None)
        print(f"{args.action}d {len(ids)} site(s); overrides at {path}")
        return 0
    return 0


def cmd_modules(args: argparse.Namespace) -> int:
    fams = [f.strip() for f in args.family.split(",")] if args.family else None
    unknown = [f for f in fams or [] if f and f.lower() not in MODULE_FAMILIES]
    if unknown:
        print(f"--family {', '.join(unknown)}: no such module family. Choose from: {', '.join(MODULE_FAMILIES)}", file=sys.stderr)
        if len(unknown) == len([f for f in fams if f]):
            return 2
    mods = all_modules(kind=args.kind, families=fams)
    if args.json:
        print(json.dumps([{"id": m.id, "name": m.name, "kind": m.kind, "source": m.source, "category": m.category,
                           "loud": m.loud, "nsfw": m.nsfw, "url": m.url_main,
                           "disabled_reason": m.disabled_reason,
                           "unsupported_proxy": m.unsupported_proxy} for m in mods], indent=1))
        return 0
    by = {}
    for m in mods:
        by.setdefault((m.source, m.kind), []).append(m)
    for (src, kind), items in sorted(by.items()):
        print(f"\n[{src} / {kind}] {len(items)} modules")
        for m in sorted(items, key=lambda x: x.id):
            flags = "".join(x for x, ok in (("L", m.loud), ("N", m.nsfw), ("D", m.disabled_reason)) if ok)
            reason = f" - {m.disabled_reason}" if m.disabled_reason else ""
            print(f"  {m.id:<45} {m.category:<14} {flags}{reason}")
    print(f"\n{len(mods)} modules total (L = loud, N = NSFW, D = disabled after review)")
    return 0




def _saved_findings(rows: list) -> list:
    """Load saved results, naming the entry at fault: a hand-edited file can hold thousands."""
    findings = []
    for number, row in enumerate(rows, 1):
        try:
            findings.append(Finding.from_dict(row))
        except ValueError as exc:
            raise ValueError(f"saved result {number} of {len(rows)}: {exc}") from exc
    return findings


def _jsonl_scan(text: str) -> dict | None:
    """Accept Consensus's own JSON Lines results (one result per line) as report input."""
    findings = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, RecursionError):
            return None
        if not isinstance(row, dict) or not {"query", "status"} <= row.keys():
            return None
        findings.append(row)
    if not findings:
        return None
    queries = {(row["query"], row.get("query_type")): {"query": row["query"], "type": row.get("query_type") or "username",
                                                      "depth": row.get("depth") or 0, "parent": row.get("parent")}
               for row in reversed(findings) if isinstance(row["query"], str)}
    data = {"queries": list(reversed(queries.values())), "findings": findings}
    times = [row["ts"] for row in findings if type(row.get("ts")) in (int, float) and math.isfinite(row["ts"]) and row["ts"] > 0]
    if times:
        data.update(started=min(times), finished=max(times))
    return data


def cmd_report(args: argparse.Namespace, *, in_session=False) -> int:
    from .core.reports import save_report

    output = Path(args.output).expanduser()
    if output.is_dir():
        raise ValueError("output is a directory: give a report filename, such as reports/results.html")
    for parent in output.parents:
        if parent.exists() and not parent.is_dir():
            raise ValueError(f"output parent is not a directory: {parent}")
    source = Path(args.json_file).expanduser()
    if str(args.json_file) != "-":
        if source.is_dir():
            raise ValueError(f"{args.json_file} is a folder: give the saved scan file inside it, such as scan.json")
        if not source.exists():
            raise ValueError(f"{args.json_file} does not exist. Saved scans are written by: consensus scan ... -a -o scan.json")
        if output.exists() and output.samefile(source):
            # Rendering over the source replaced a complete saved scan with a filtered copy of itself.
            raise ValueError(f"{args.output} is the saved scan this report is made from; choose another output name "
                             "so the saved results are kept")
    try:
        text = _read_input_text(args.json_file)
        data = json.loads(text)
    except RecursionError as exc:
        raise ValueError("saved report JSON is nested too deeply") from exc
    except json.JSONDecodeError as exc:
        data = _jsonl_scan(text)
        if data is None:
            raise ValueError(f"{args.json_file} is not a saved scan: it is not valid JSON ({exc}). "
                             "Save results with: consensus scan ... -a -o scan.json") from exc
    if not isinstance(data, dict):
        raise ValueError("saved report must be a JSON object")
    if data and not data.keys() & {"generator", "generated", "queries", "started", "finished", "options",
                                   "counts", "findings", "comparisons"}:
        raise ValueError(f"{args.json_file} is not a saved scan: it has no findings or queries. "
                         "Save results with: consensus scan ... -a -o scan.json")
    for key, expected in (("queries", list), ("findings", list), ("options", dict)):
        if key in data and not isinstance(data[key], expected):
            raise ValueError(f"saved report has an invalid {key} field")
    for key in ("started", "finished"):
        value = data.get(key)
        if value is None:
            continue
        try:
            valid = type(value) in (int, float) and math.isfinite(value)
        except OverflowError:
            valid = False
        if not valid:
            raise ValueError(f"saved report {key} must be a finite number or null")
    summary = ScanSummary(queries=data.get("queries", []), started=data.get("started", 0), finished=data.get("finished"),
                          options=data.get("options", {}), findings=_saved_findings(data.get("findings", [])))
    if getattr(args, "compare_queries", None) is not None:
        summary.options["compare_queries"] = args.compare_queries
    recorded_counts = data.get("counts", {})
    if isinstance(recorded_counts, dict):
        total = sum(n for k, n in recorded_counts.items()
                    if k in {status.value for status in Status} and type(n) is int and n >= 0)
        if total > len(summary.findings):
            prior = summary.options.get("_input_omitted_results", 0)
            prior = prior if type(prior) is int and prior >= 0 else 0
            summary.options["_input_omitted_results"] = prior + total - len(summary.findings)
    path = save_report(summary, args.output, args.format, include_all=args.all)
    if summary.options.get("_input_omitted_results"):
        Printer().warn("The saved input omitted some results; re-rendering cannot recover them. Totals describe available rows.")
    printer = Printer()
    printer.identity()
    printer.report_saved(path)
    if note := _format_note(args.output, args.format):
        printer.warn(note)
    if not in_session:
        printer.command_menu()
    return 0


def cmd_keys(args: argparse.Namespace) -> int:
    if args.action == "path":
        print(config_path())
    elif args.action == "list":
        from .core.config import key_origin

        keys = get_config(reload=True).get("keys", {})
        for k, value in keys.items():
            origin = key_origin(k)
            state = ("*** (from the environment variable " + origin + ")" if origin
                     else "***" if value not in (None, "") else "empty - not used; consensus keys remove " + k)
            print(f"{k}: {state}")
        if not keys:
            print("no keys configured")
    elif args.action == "set":
        if len(args.args) != 2 or not args.args[1].strip():
            print("usage: consensus keys set <name> <value>   (to delete a key: consensus keys remove <name>)",
                  file=sys.stderr)
            return 2
        p = set_key(args.args[0], args.args[1])
        print(f"saved {args.args[0]} to {p}")
    elif args.action == "remove":
        from .core.config import key_origin, stored_keys

        if len(args.args) != 1:
            print("usage: consensus keys remove <name>", file=sys.stderr)
            return 2
        name = args.args[0]
        if name not in stored_keys():
            origin = key_origin(name)
            print(f"{name} is not stored in {config_path()}"
                  + (f"; it comes from the environment variable {origin}" if origin else
                     "; stored names: " + (", ".join(stored_keys()) or "none")), file=sys.stderr)
            return 1
        p = set_key(name, None, remove=True)
        print(f"removed {name} from {p}")
        if origin := key_origin(name):
            print(f"{name} is still supplied by the environment variable {origin}")
    return 0






def cmd_mcp(args: argparse.Namespace) -> int:
    try:
        from .mcp_server import run

        return run(["--transport", args.transport])
    except ImportError as exc:
        print(f"MCP server needs: pip install consensus-osint[mcp] ({exc})", file=sys.stderr)
        return 1


def _utf8_console(*streams) -> None:
    """Make the console streams UTF-8 so a site name in any script prints instead of crashing.

    Windows consoles often default to a legacy code page; a Chinese or Cyrillic site
    name then raises UnicodeEncodeError from a plain print().  Anything the terminal
    still cannot show is replaced rather than fatal.
    """
    for s in streams:
        try:
            if (getattr(s, "encoding", "") or "").lower().replace("-", "") != "utf8":
                s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - captured, piped or otherwise not a real console
            pass


def version_string() -> str:
    """The tool version plus which weekly database build it is running with."""
    from .core.signing import check_database

    st = check_database()
    if not st["present"]:
        return f"consensus {__version__} - database: no build stamp (local or modified data)"
    state = "verified" if st["verified"] else f"NOT VERIFIED: {st['reason']}"
    return f"consensus {__version__} - database build #{st['build']} ({st['date']}, {st['sites']:,} sites) {state}"


class _VersionAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        print(version_string())
        parser.exit()


def _announce_database(printer: Printer) -> None:
    """One line on which weekly build a scan is using, whether it is genuine, and what it changed."""
    from .core.signing import check_database

    st = check_database()
    if not st["present"]:
        printer.message("database: no build stamp - local or modified data, not a signed weekly build", "yellow")
        return
    line = f"database: weekly build #{st['build']} ({st['date']}, {st['sites']:,} sites)"
    n = st["notes"] or {}
    if n.get("added") or n.get("rule_changed"):
        line += f" - this build: +{n.get('added', 0)} sites, {n.get('rule_changed', 0)} rules fixed"
    if st["verified"]:
        printer.message(line + " - verified", "dim")
    else:
        printer.message(line + f" - NOT VERIFIED: {st['reason']}", "yellow")
    if st["stale"]:
        printer.message(f"   this build is {st['age_days']} days old and a newer weekly build is probably out; "
                        f"`consensus update --catalogue` checks its published build", "dim")


def cmd_update(args: argparse.Namespace) -> int:
    """Install application updates; retain the explicit catalogue check."""
    if not getattr(args, "catalogue", False):
        from .core.app_update import command

        return command(args)
    return cmd_catalogue_update(args)


def cmd_catalogue_update(args: argparse.Namespace) -> int:
    """Check the published signed catalogue build without installing."""
    from .core.signing import LATEST_STAMP_URL, check_database, fetch_latest_stamp

    local = check_database()
    try:
        latest = fetch_latest_stamp()
        if not isinstance(latest, dict) or type(latest.get("build")) is not int or latest["build"] < 1:
            raise ValueError("invalid build metadata")
    except Exception as exc:  # noqa: BLE001
        from .core.app_update import network_problem

        print(f"could not reach {LATEST_STAMP_URL}: {network_problem(exc)}", file=sys.stderr)
        return 1
    have, new = int(local.get("build") or 0), int(latest.get("build") or 0)
    if getattr(args, "json", False):
        print(json.dumps({"installed": local, "latest": latest, "newer_available": new > have}, indent=1))
        return 0
    print(f"installed: build #{have} ({local.get('date') or 'unstamped'}, {local.get('sites') or '?'} sites)"
          + ("" if local.get("verified") else f" - {local.get('reason')}"))
    print(f"latest   : build #{new} ({latest.get('date')}, {latest.get('sites')} sites)")
    n = latest.get("notes") if isinstance(latest.get("notes"), dict) else {}
    if new > have:
        print(f"\na newer weekly build is available; the latest one added {n.get('added', 0)} sites, "
              f"removed {n.get('removed', 0)} and fixed {n.get('rule_changed', 0)} rules.")
        print("update the application and its bundled catalogue with: consensus update")
    else:
        print("\nyou have the current build.")
    print("\n(that was one request for a small static file, made only because you ran this command)")
    return 0


def main(argv: list | None = None, *, scan_defaults=None, on_summary=None, in_session=False, continuation=None) -> int:
    _utf8_console(sys.stdout, sys.stderr)
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    # A global startup switch works before or after the command. Preserve tokens
    # after --, where a literal search term must not be interpreted as an option.
    boundary = raw_argv.index("--") if "--" in raw_argv else len(raw_argv)
    no_update_check = "--no-update-check" in raw_argv[:boundary]
    raw_argv = [arg for arg in raw_argv[:boundary] if arg != "--no-update-check"] + raw_argv[boundary:]
    if not raw_argv or all(arg in ("-h", "--help", "--no-color", "--no-footer", "--no-animation") for arg in raw_argv):
        from .core.scan_control import terminal_available

        if not in_session and not any(a in ("-h", "--help") for a in raw_argv) and terminal_available():
            from .core.app_update import startup_notice
            from .core.interactive import prepare_screen, start_session

            prepare_screen()
            startup_notice(disabled=no_update_check, auto_install=True)
            options = {"footer": False} if "--no-footer" in raw_argv else {}
            if "--no-animation" in raw_argv:
                options["animate"] = False
            return start_session(color="--no-color" not in raw_argv, **options)
        Printer(color="--no-color" not in raw_argv).welcome(__version__)
        return 0
    argv = normalise_argv(raw_argv)
    parser = build_parser(full_help="--help-all" in argv, color="--no-color" not in argv,
                          scan_defaults=scan_defaults, compact_errors=in_session)
    args = parser.parse_args(argv)
    if continuation is not None:
        args._continuation = continuation
    if getattr(args, "debug", False):
        logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING, format="%(message)s")
        for noisy in ("httpx", "httpcore", "hpack", "charset_normalizer", "asyncio"):
            logging.getLogger(noisy).setLevel(logging.ERROR)
    # Repeated session commands must not inherit an earlier command's debug level.
    logging.getLogger().setLevel(logging.DEBUG if getattr(args, "debug", False) else logging.WARNING)
    if os.name == "nt":
        try:
            # Playwright launches a driver subprocess, unsupported by Selector.
            policy = (asyncio.WindowsProactorEventLoopPolicy if getattr(args, "browser", False)
                      else asyncio.WindowsSelectorEventLoopPolicy)
            asyncio.set_event_loop_policy(policy())
        except Exception:  # noqa: BLE001
            pass
    cmd = args.cmd or "scan"
    try:
        if not in_session and cmd == "shell":
            from .core.interactive import prepare_screen

            prepare_screen()
        if not in_session and cmd in ("scan", "user", "email", "phone", "shell"):
            from .core.app_update import startup_notice

            update_options = {"auto_install": True} if cmd == "shell" else {}
            startup_notice(disabled=no_update_check or bool(getattr(args, "json", False))
                           or bool(getattr(args, "jsonl", False)) or bool(getattr(args, "quiet", False))
                           or bool(getattr(args, "proxy", None)) or bool(getattr(args, "tor", False)), **update_options)
        if cmd in ("scan", "user", "email", "phone"):
            return cmd_scan(args, on_summary=on_summary, in_session=in_session)
        if cmd == "shell":
            from .core.interactive import start_session

            options = {"footer": False} if args.no_footer else {}
            if args.no_animation:
                options["animate"] = False
            return start_session(color=not args.no_color, **options)
        if cmd == "terminal":
            from .core.terminal_profile import command

            return command([args.action], Printer())
        return {'sites': cmd_sites, 'modules': cmd_modules, 'update': cmd_update, 'report': lambda a: cmd_report(a, in_session=in_session), 'keys': cmd_keys, 'mcp': cmd_mcp, 'version': lambda a: print(version_string()) or 0, 'examples': lambda a: Printer(color=not a.no_color).examples() or 0, 'info': lambda a: Printer(color=not a.no_color).session_information() or 0, 'about': lambda a: Printer(color=not a.no_color).identity(__version__) or 0}[cmd](args)
    except KeyboardInterrupt:
        print("Command cancelled.", file=sys.stderr)
        return 130
    except (OSError, ValueError, argparse.ArgumentTypeError) as exc:
        if getattr(args, "debug", False):
            raise
        from .core.models import redact_options

        message = redact_options({"error": str(exc)})["error"]
        print(f"error: {message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
