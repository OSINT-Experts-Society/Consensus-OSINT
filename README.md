<p align="center">
  <img src="consensus_osint/templates/consensus-logo.png" width="760" alt="Consensus">
</p>

<h3 align="center">One platform. The strength of many.</h3>

<p align="center">Search usernames, email addresses and phone numbers.<br>Bring the returned evidence into one terminal view and a report you can keep.</p>

<p align="center">
  <a href="https://osint.ngo"><img src="consensus_osint/templates/society-signature.svg" width="310" alt="By the OSINT Experts Society"></a>
</p>

<p align="center">
  <a href="#get-started">Get started</a> ·
  <a href="#search">Search</a> ·
  <a href="#read-the-evidence">Read the evidence</a> ·
  <a href="#save-and-share">Reports</a> ·
  <a href="#contribute">Contribute</a>
</p>

Consensus brings selected lookup modules and site catalogues from projects including Sherlock, Maigret, WhatsMyName, Holehe and User Scanner into one application. It reconciles overlapping service checks, retains available profile details and shows where each result came from.

Use the interactive menu for an investigation, or the command line for repeatable searches and structured output. You do not need to run the upstream tools separately.

| Start with | Explore |
| --- | --- |
| **A username** | Public profiles across thousands of catalogue entries, with available names, biographies, links and other returned fields. |
| **An email address** | Eligible provider account signals, public profile information, domain analysis and supported exposure checks. |
| **A phone number** | Number format, country and carrier information, eligible reputation/account checks and clearly labelled search links. |
| **Several identifiers** | Separate searches, with optional comparisons when you believe the identifiers belong to the same person. |

**Current status:** active development and an ongoing audit. Some checks are disabled, restricted or require optional dependencies. An enabled check is not a promise of current live availability. Review important findings at their source; a match does not establish who owns an account.

## Get started

### Install from source (available now)

You need **Python 3.10 or later**, Git and a terminal. Clone the repository:

```console
git clone https://github.com/OSINT-Experts-Society/Consensus-OSINT.git
cd Consensus-OSINT
```

Create an isolated environment using the command for your operating system:

| Operating system | Command |
| --- | --- |
| Windows | `py -3 -m venv .venv` |
| macOS / Linux | `python3 -m venv .venv` |

If your Windows Python installation does not include the `py` launcher, use `python -m venv .venv` instead.

Activate it using the command for your terminal:

| Terminal | Command |
| --- | --- |
| Windows PowerShell | `.\.venv\Scripts\Activate.ps1` |
| Windows Command Prompt | `.venv\Scripts\activate.bat` |
| macOS / Linux | `source .venv/bin/activate` |

Then install Consensus with its lookup-module dependencies and open it:

```console
python -m pip install --upgrade pip
python -m pip install ".[modules]"
consensus
```

Activate the same environment when you open a new terminal. Once active, `consensus` works from any folder. `consensus info` shows the application and report locations.

To make a source installation available without activating the environment each time, add its executable directory to your user PATH. Run the appropriate block **from the cloned Consensus folder**, after installation.

**macOS / Linux**

```sh
consensusBin="$(pwd)/.venv/bin"
export PATH="$consensusBin:$PATH"
printf 'Add this directory to your shell PATH configuration: %s\n' "$consensusBin"
consensus info
```

This updates the current terminal. For future terminals, add `export PATH="/absolute/path/to/Consensus/.venv/bin:$PATH"` to `~/.zshrc` (zsh) or `~/.bashrc` (bash), replacing the example path with the directory printed above. Keep the quotes if the path contains spaces.

**Windows PowerShell**

```powershell
$consensusBin = (Resolve-Path '.venv\Scripts').Path
$consensusUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($consensusBin -notin ($consensusUserPath -split ';')) {
    [Environment]::SetEnvironmentVariable('Path', "$consensusBin;$consensusUserPath", 'User')
}
if ($consensusBin -notin ($env:Path -split ';')) {
    $env:Path = "$consensusBin;$env:Path"
}
consensus info
```

This updates the current terminal and your saved user PATH. If PowerShell blocks the activation script, you can install and run directly with `.\.venv\Scripts\python.exe -m pip install -e ".[modules]"` and `.\.venv\Scripts\consensus.exe`, without changing your execution policy.

Keep the checkout and its virtual environment at the same location. If you move them, recreate the environment, reinstall and update the PATH entry.

Update source installations with `git pull --ff-only` and the same editable-install command. `consensus update` deliberately does not modify a development checkout or an environment owned by another package manager.

### Managed installation (requires a published release)

The managed installer sets up Consensus, its lookup-module and PDF dependencies, and a private Python runtime. You do not need to install Python, Git or a package manager yourself.

The commands below require the first installer-enabled GitHub release and its matching PyPI package. Until those are published, use the source installation above.

**Windows PowerShell**

```powershell
irm https://github.com/OSINT-Experts-Society/Consensus-OSINT/releases/latest/download/install.ps1 | iex
```

**macOS / Linux Terminal** (requires `curl`)

```sh
curl -fsSL https://github.com/OSINT-Experts-Society/Consensus-OSINT/releases/latest/download/install.sh | sh
```

Open a new terminal, then start Consensus from any folder:

```console
consensus
```

The installer adds the command to your user PATH. Running the installer again checks for the latest release. Application files and the private runtime live in `~/.local/share/consensus-app`; settings remain in `~/.consensus` and reports stay where you saved them. `CONSENSUS_INSTALL_DIR` selects a different application directory. Set `CONSENSUS_NO_MODIFY_PATH=1` before installation to manage PATH yourself; the launcher is in that directory's `bin` folder.

<details>
<summary><strong>Add Consensus to PATH manually</strong></summary>

If `consensus` is not found after a managed installation, use the commands for your shell below. These use the default installation directory; if you set `CONSENSUS_INSTALL_DIR`, substitute that directory's `bin` folder.

**macOS — zsh (the default shell)**

```sh
echo 'export PATH="$HOME/.local/share/consensus-app/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
consensus
```

**Linux — bash**

```sh
echo 'export PATH="$HOME/.local/share/consensus-app/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
consensus
```

Choose the block for your shell even if you use a different operating system. For another shell, add the same `bin` directory using that shell's PATH configuration.

**Windows — PowerShell** (no administrator terminal needed)

```powershell
$consensusBin = Join-Path $env:USERPROFILE '.local\share\consensus-app\bin'
$consensusUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($consensusBin -notin ($consensusUserPath -split ';')) {
    [Environment]::SetEnvironmentVariable('Path', "$consensusBin;$consensusUserPath", 'User')
}
if ($consensusBin -notin ($env:Path -split ';')) {
    $env:Path = "$consensusBin;$env:Path"
}
consensus
```

The Windows commands update both this terminal and your saved user PATH. Open a new terminal for other sessions to pick up the change.

PATH setup does not install the application. The managed launcher is `~/.local/share/consensus-app/bin/consensus` on macOS/Linux and `%USERPROFILE%\.local\share\consensus-app\bin\consensus.cmd` on Windows. Source installations use the virtual environment described above instead.

</details>

<details>
<summary><strong>Source-install extras and integrations</strong></summary>

Use `python -m pip install -e .` for the core installation, including HTML parsing. Optional integrations report when their dependencies are missing.

| Extra | Adds |
| --- | --- |
| `modules` | Bundled module dependencies, HTML profile extraction and browser TLS impersonation. |
| `pdf` | PDF reports. |
| `browser` | Playwright integration; also run `python -m playwright install chromium`. |
| `mcp` | A Model Context Protocol server for compatible clients. |
| `all` | All the optional integrations above. |
| `dev` | Development tools and all optional integrations. |

Combine extras as needed: `python -m pip install -e ".[modules,pdf]"`. Some providers require separately configured credentials or subscriptions.

</details>

## Search

### In the terminal menu

Run `consensus`, then choose **Username**, **Email**, **Phone** or **Bulk search**. You can also type an identifier directly and let Consensus detect its type.

| Key while scanning | Action |
| --- | --- |
| `V` | Show or hide the hit preview. |
| `P` | Pause new checks; requests already running may finish. |
| `R` | Resume. |
| `S` or `Ctrl+C` | Stop and keep results collected so far. |

Completed results open at the top. Use arrow keys, Page Up/Page Down or Home/End to browse; Enter returns to the menu. **View results** reopens the latest search, and **Save report** exports it without another lookup.

Type `/` for session commands, `/config` for settings, `examples` for guidance or `exit` to finish. The menu's own words also work: `results`, `view` or `latest` reopen the latest search and `export` saves it; to search for such a word as a username, type `user results`. Stray answers and command-like words such as `yes`, `history` or `test` are not searched either; the session says how to search for them deliberately. At a session prompt, Enter, `0`, `back` or `quit` goes back without searching. Save the latest search before starting another one or exiting.

### From the command line

Replace the placeholders with identifiers you are authorised to investigate:

```console
consensus user "YOUR_USERNAME"
consensus email "YOUR_EMAIL"
consensus phone "+COUNTRY_CODE_AND_NUMBER"
consensus user "YOUR_USERNAME" --fast -o reports/username.html
```

Use international phone format when possible; copied `tel:` links are also accepted. For a national number, supply its country explicitly:

```console
consensus phone "YOUR_NATIONAL_NUMBER" --phone-region GB
```

Number metadata and generated search links do not identify the owner. Generated links have not been searched.

Use `--site` / `--exclude` for service selection and `--tags` / `--exclude-tags` for categories. Separate several values with commas; repeating an option (`--site github --site gitlab`) adds to the earlier values. An unknown site or tag is named in a warning. If the filters leave nothing to check, Consensus says that nothing was checked, which is not a negative result, and exits with status 2; `--no-sites --no-modules` remains a deliberate dry run. `--permute` and `--names` announce when `--max-permutations` cuts their list short. Phone reputation and configured API lookups honour these filters too; offline number analysis and suggested links remain available.

On the command line, `consensus help` shows help, and a command-like first word such as `search`, `list`, `upgrade` or `quit` is explained rather than looked up on every site; `consensus user search` searches for the word itself. A pasted profile link, `@handle`, `mailto:` address or `Name <address>` is searched exactly as typed, and Consensus points out the identifier you probably meant with the command to search it. Use `--variants` to add common username aliases. For an all-digit username, use `user VALUE` or `scan VALUE --type username`; its aliases remain username searches. Empty inputs are ignored.

### Search a list

Put one identifier per line in a text file. Empty lines and lines beginning with `#` are ignored.

To specify each line's type, use `username:alice` (or `user:alice`), `email:alice@example.com` or `phone:+441234567890`. This also preserves all-digit usernames. The same prefixes work for identifiers given directly on the command line, pasted into Bulk search and typed at the interactive prompt. A typed identifier that conflicts with `user`, `email`, `phone` or an explicit `--type` is rejected before scanning, as are lines containing control characters (for example UTF-16 text saved without its byte-order mark) or more than 320 characters.

Use UTF-8 text, with or without a byte-order mark. BOM-marked UTF-16 and UTF-32 files are also accepted, including files created by Windows PowerShell's default `Out-File`. Saved JSON report input supports the same encodings. Quote paths containing spaces. Input and report paths also accept `~/` for your home directory.

```console
consensus scan -i queries.txt -a -o reports/bulk.html
```

Use `-i -` to read from a pipe. For example, `cat queries.txt | consensus scan -i -` on macOS/Linux, or `Get-Content queries.txt | consensus scan -i -` in PowerShell.

Queries are treated separately by default. If you believe they refer to the same person, opt into shared-detail comparisons:

```console
consensus scan -i queries.txt --compare-queries -a -o reports/related.html
```

Shared names, words, sites or profile fields are leads to review, not proof of a common owner. Distinct submitted queries retain their original text and type.

## Read the evidence

| What you see | What it means |
| --- | --- |
| **Found** | A positive signal within that check's scope: for example a public profile, registration signal or public-key record. Read its explanation. |
| **Needs review** | A limitation needs attention, such as a changed identifier, differing name or weak evidence. The result remains unconfirmed. |
| **Enriched** | Additional information was returned. Inspect the fields and how they relate to your query. |
| **No match** | This check reported no match within its supported scope. Other services or account types may differ. |
| **Inconclusive, blocked, rate limited or error** | The check could not establish a reliable answer. These are not negative results. |
| **Background details** | Domain/number analysis or suggested search links, shown separately from account matches. |

Source logos and **Tools with this lookup** identify incorporated definitions and implementations. They are attribution, not independent confirmations. Consensus does not reproduce every feature of every credited project.

Some providers format or remove characters before searching. Results show the value used and call out cases needing review. Missing fields stay missing; a module classification alone does not establish useful enrichment.

<details>
<summary><strong>Coverage boundaries worth understanding</strong></summary>

- Public profiles, registration signals, authentication routes and public-key records answer different questions. An SSO route does not establish an existing account; a public-key index entry does not verify an active mailbox.
- Eligible Hudson Rock email/username checks can return limited exposure metadata. LeakCheck, XposedOrNot and ProxyNova remain held pending evidence. A recognised `hibp` configuration key does not mean a Have I Been Pwned adapter is implemented. Use `--no-breach` to exclude eligible breach checks.
- Supported breach output excludes password values and fragments. An empty, failed or unavailable response does not establish absence from breaches.
- Phone reputation results are third-party reports, not verified ownership or caller behaviour. Several phone account flows remain disabled or require notification opt-in.
- Optional `--search-engines` results are profile leads. Failed, restricted or unreadable searches remain inconclusive. HTML parsing is included in the core installation.
- Disabled checks remain disabled under broad selection flags. Offline parser tests do not establish live reliability or permission to remove a hold. Rules containing temporary wiki detection placeholders are also skipped; those entries do not yet have usable account evidence.

Use `consensus modules` and `consensus sites stats` to inspect the installed inventory; `consensus sites list WORD` lists the sites whose id, name or address contains the word, and `consensus sites info ID` shows one definition. Counts include definitions with different eligibility and scope; they are not a count of verified working services.

</details>

## Save and share

```console
consensus email "YOUR_EMAIL" -o reports/email.html
consensus scan -i queries.txt -a -o reports/all-results.json
consensus report reports/all-results.json -a -o reports/all-results.html
```

**HTML reports are standalone files** with search, filters, sorting, query navigation, returned fields, source attribution, shared-detail comparisons, light/dark themes and print layouts. Source logos are embedded locally. Profile images remain links rather than automatically loaded remote content.

Reports default to the launch folder's `reports` directory. Saved exports show their absolute path; use `-o` to choose another destination. If a report cannot be written (for example the file is open in another program), Consensus keeps the complete results as `NAME-recovered-DATE.json` beside it, or in the default reports folder, and shows the `consensus report` command that rebuilds the document without searching again. Report times state their UTC offset. `consensus report` reads a saved `.json` scan or the `.jsonl` results Consensus writes, and refuses to write over the file it is reading. Give `-o` once per run; if `-f` contradicts the file ending, Consensus says which format the file really contains. Text and Markdown reports saved without `-a` state, for each query, how many no-match, inconclusive and skipped checks are not listed.

Available formats: **HTML, interactive graph HTML, JSON, JSONL, CSV, text, Markdown, Neo4j graph JSON, XMind and optional PDF**. Consensus infers the format from the extension, or accepts `-f`.

Create an offline interactive evidence graph from saved results:

```console
consensus report reports/all-results.json -o reports/evidence.graph.html
```

Alternatively use `-f graph-html`. The graph opens at reading size from the top: scroll or drag to move through it, hold Ctrl while scrolling (or use + and −) to zoom, and use **Fit graph** for an overview. Search, or choose a node from the list, to inspect each query, result and source site, including returned metadata; result labels start with the verdict. The graph loads no external assets and needs no server. Connections show returned evidence, not verified identity or ownership. Existing `graph`/`.graph.json` aliases still produce Neo4j JSON.

Direct PDF export depends on the installed font. If it cannot render a character, export stops with guidance instead of replacing the text with empty boxes. For broader script support, save HTML and use your browser's Print to save a PDF.

Save JSON with **`-a`** to retain all outcomes for later review. A filtered report cannot recover omitted findings. Reports may contain personal information; choose storage and recipients accordingly.

<details>
<summary><strong>Automation and graph exports</strong></summary>

Use `-f json` for one JSON document on stdout, or `--jsonl` for streaming records. Add `-a` for unsuccessful outcomes, `--no-color` for plain output and `--no-footer` to disable managed terminal controls. `--quiet` requests summary output; when combined with `--jsonl`, it preserves the requested JSONL records.

Streaming records retain recursion depth and parent information. Final reports also contain completed comparisons and assessments. Redirected output does not open the interactive results viewer.

An explicitly requested `--ai` summary remains visible in quiet mode. With JSONL streaming or a report on stdout, the AI summary goes to stderr so the report stays machine-readable. `Ctrl+C` stops a pending AI summary while retaining the completed search results; in the managed terminal, `S` does this too.

Neo4j graph JSON includes APOC import instructions. Running an import changes the target database: distinct result URLs are retained, and re-importing a relationship replaces its properties with the supplied evidence.

</details>

## Network and privacy

Investigate only for lawful, authorised purposes, respect provider terms and verify findings before acting on them. Start with accounts you control when evaluating the application.

Searches contact selected providers and supporting services. There is no telemetry. Managed interactive installations make a small PyPI version request at most once a day; no search terms or identifiers are sent. Startup checks are skipped for redirected input/output, quiet/JSONL scans, and configured Consensus proxy/Tor use. Explicit application updates download packages from PyPI; the installer also downloads its runtime helper and Python. Set `CONSENSUS_NO_UPDATE_CHECK=1` or pass `--no-update-check` to disable startup checks. Optional AI analysis is opt-in and sends identifiers, profile URLs and metadata to the configured service, with credential filtering; review generated conclusions against the evidence.

**The managed footer checks your direct public IP even when you use a proxy.** It makes bounded requests to ipify, with a separate routed proxy observation, without sending query identifiers. Use `--no-footer` to disable those observations. The display does not guarantee the route of every connection; supporting DNS has separate routing.

```console
consensus user "YOUR_USERNAME" --proxy "socks5://127.0.0.1:9050" --no-footer
consensus user "YOUR_USERNAME" --tor --no-footer
consensus keys path
```

Tor must already be running. An explicit proxy takes precedence over `--tor`. You can also configure `CONSENSUS_PROXY`, `defaults.proxy` or `defaults.tor: true`; the order is command option, environment variable, then settings. A scan warns about `defaults:` entries it does not recognise, because a misspelt route setting has no effect.

Configuration normally lives in `~/.consensus/config.yaml`; `CONSENSUS_HOME` selects another directory. Keep credentials out of Git and shared commands. `consensus keys set NAME VALUE` stores an API key there in plain text, `consensus keys list` shows which names are set (never the values) and whether an environment variable supplies them, and `consensus keys remove NAME` deletes one.

Notification-capable flows are restricted by default. **`--allow-loud` opts into eligible checks that may notify someone or change account/contact state.** It does not enable disabled checks. Optional SMTP discovery is skipped with a configured HTTP/HTTPS/ALL proxy; SMTP replies alone remain inconclusive and that optional path does not guarantee encryption.

A reset-request acknowledgement does not prove an account exists or that an email was delivered. The Sexvid and Hanzii rules report these acknowledgements as inconclusive. Hanzii retains its explicit legacy missing-email response; unrecognised responses, including Sexvid's unverified missing-email formats, remain inconclusive.

## Keep Consensus up to date

For a managed installation, run:

```console
consensus update
```

Consensus downloads and verifies the latest stable release, installs it in a separate environment, and checks that it starts before switching the launcher. Startup validation has a 30-second limit. Restart Consensus to use the new version. An installation or validation failure leaves the previous version selected. If your current installation cannot start, rerun the installer to rebuild it from the same published release. Older environments are retained so running sessions can finish; updates never delete your settings or reports.

When you open a managed interactive session, an available update is shown with the command to install it. A slow or unavailable connection does not stop you using Consensus; a slow check may appear on the next launch. Updates are installed only when requested.

```console
consensus update --check
consensus update --json
consensus update --catalogue
```

`--check` and `--json` check the application version without installing. They distinguish the selected installation from the version running in the current session and indicate when a restart is needed. `--catalogue` retains the earlier signed-catalogue build check; it does not install anything. Application releases include their bundled catalogue. Inside the menu, `update` or `/update` runs the same updater.

The maintenance process targets weekly catalogue reviews. The application shows the installed build and its age; the schedule does not guarantee that every provider has been tested or updated that week. A catalogue signature verifies its issuer and integrity, not the live accuracy of each check.

## More controls and integrations

<details>
<summary><strong>Terminal preferences</strong></summary>

Use `/config animation off` in a session or `--no-animation` on the command line. Session preferences last until exit; reset clears the latest results and history and restores starting preferences.

`consensus shell --no-footer` uses a conventional line-based interface. Plain or unsupported terminals fall back automatically.

`consensus terminal install` adds a dedicated Consensus profile/icon for supported Windows Terminal installations; `consensus terminal remove` removes it. Choose the new profile from the terminal menu. Reinstall it after moving the Python environment. Native activity indicators depend on terminal support.

</details>

<details>
<summary><strong>MCP integration</strong></summary>

Install `[mcp]` and run `consensus mcp` for stdio. Optional transports are `consensus mcp --transport streamable-http` (`/mcp`) and `--transport sse` (`/sse`), served on `127.0.0.1:8000`. These local interfaces have no Consensus account/login layer.

`scan_username`, `scan_email` and `scan_phone` return the first page. Continue with `get_scan_results`; use `read_scan_chunk` for complete oversized findings and `release_scan_results` when finished. Read each finding's status and interpretation, including inconclusive and failed checks.

Reports are cached in memory, not automatically saved. They expire after one hour and can be evicted earlier at eight scans or 128 MiB of serialized JSON. A single report over that size produces an explicit error. Shutdown clears the cache. Keep scan IDs private and retrieve needed evidence before release or expiry. Notification-capable checks require explicit `allow_loud: true`.


</details>

For the complete command reference:

```console
consensus examples
consensus --help
consensus scan --help-all
```

## Contribute

Join the [OSINT Experts Society](https://osint.ngo), [LinkedIn group](https://www.linkedin.com/groups/13047129/) or [Reddit community](https://www.reddit.com/r/OSINTExperts/).

For bugs and improvements, [open an issue](https://github.com/OSINT-Experts-Society/Consensus-OSINT/issues) with your version, platform, a redacted command and a synthetic reproduction. Keep real identifiers and credentials out of public reports. Use the repository's Security tab for private security reporting where available.

To suggest a site, open an issue with its address and the type of lookup it supports.

## Credits

Consensus depends on the work of these projects and their contributors. Imported definitions, adapted techniques and vendored implementations have different scopes; credit does not imply that their maintainers endorse Consensus.

**Site lists** — [Sherlock](https://github.com/sherlock-project/sherlock) ·
[Maigret](https://github.com/soxoj/maigret) ·
[WhatsMyName](https://github.com/WebBreacher/WhatsMyName) ·
[sherlockV2](https://github.com/hanyxd/sherlockV2) ·
[DetectDee](https://github.com/Yvesssn/DetectDee) ·
[Aliens_eye](https://github.com/arxhr007/Aliens_eye) ·
[nexfil](https://github.com/thewhiteh4t/nexfil) ·
[gosearch](https://github.com/ibnaleem/gosearch) ·
[vesper](https://github.com/krishpranav/vesper) ·
[findme](https://github.com/0xSaikat/findme) ·
[linkook](https://github.com/JackJuly/linkook) ·
[UserJoo](https://github.com/ar33s0/UserJoo) ·
[Sreg](https://github.com/n0tr00t/Sreg) ·
[Fediverse Observer](https://fediverse.observer)

**Modules & techniques** — [user-scanner](https://github.com/kaifcodec/user-scanner) ·
[holehe](https://github.com/megadose/holehe) ·
[ignorant](https://github.com/megadose/ignorant) ·
[socialscan](https://github.com/iojw/socialscan) ·
[numint](https://github.com/whoamitang/numint) ·
[socid-extractor](https://github.com/soxoj/socid-extractor) ·
[marple](https://github.com/soxoj/marple) ·
[mailcat](https://github.com/sharsil/mailcat) ·
[Zehef](https://github.com/N0rz3/Zehef) ·
[Eyes](https://github.com/N0rz3/Eyes) ·
[hashtray](https://github.com/balestek/hashtray) ·
[mosint](https://github.com/alpkeskin/mosint) ·
[phoneinfoga](https://github.com/sundowndev/phoneinfoga) ·
[Telespotter](https://github.com/thumpersecure/Telespotter) ·
[libphonenumber](https://github.com/google/libphonenumber)


**Runtime providers** include Gravatar, Hudson Rock and eligible phone reputation services. Some optional providers require their own accounts or subscriptions. Held providers remain listed in the inventory, not promised as working coverage.

## Name and marks

The Consensus logo expresses independent contributions meeting around a shared centre. The OSINT Experts Society logo is the Society's own asset from [osint.ngo](https://osint.ngo/src/assets/images/osint-experts-society-logo.png), included unchanged. Third-party logos identify credited source tools; they remain their owners' marks and do not imply endorsement. Bundled source-logo origins and notices are recorded with the assets.

*Consensus* names this project and the signed weekly builds its maintainers publish. The code is available under the GPL; the name is reserved. A fork or derived distribution must use a different name and must not present itself as an official Consensus build. A catalogue signature identifies a maintainer-issued catalogue, not blanket approval of surrounding code.

## License

[GPL-3.0-or-later](LICENSE) for the combined work. [Third-party notices](THIRD_PARTY_NOTICES.txt) identify incorporated code, imported data, retained licences and reviewed source revisions. Complete notices ship in source archives and installed wheels, including the vendor notices and [original licence texts](licenses). Run `python -m pip show -f consensus-osint` to locate an installation's `.dist-info/licenses` files.

Vendored components retain their own MIT, MPL-2.0 and GPL-3.0 notices. WhatsMyName-derived data (`consensus_osint/data/sites_wmn.json`) is CC BY-SA 4.0, © 2015–2026 Micah Hoffman. The Mailcat adaptation retains Apache-2.0; the Marple adaptation and incorporated Sherlock/Maigret material retain their original MIT notices.

The notice index records unresolved provenance limits too: historical row import commits are incomplete, sherlockV2's original licence has unfilled attribution placeholders, phone-template origins need further tracing, and Fediverse Observer's data redistribution terms have not been established. These are not claims of complete licensing clearance.

Numint's Amazon, Instagram and Snapchat entries now call the maintained GPL-3.0 Ignorant implementations through a Consensus bridge. Both original licence notices are retained.

Terminal dependencies include [prompt-toolkit](https://github.com/prompt-toolkit/python-prompt-toolkit) (BSD-3-Clause) and [wcwidth](https://github.com/jquast/wcwidth) (MIT), installed separately with their own notices. Other dependencies also retain their respective licences. Provider access, data redistribution, marks and service terms are separate from the source-code licence; public source availability alone does not grant every commercial or paid-API use.
