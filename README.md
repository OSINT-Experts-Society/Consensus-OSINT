<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="consensus_osint/templates/consensus-wordmark-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="consensus_osint/templates/consensus-wordmark-light.svg">
    <img src="consensus_osint/templates/consensus-wordmark-light.svg" width="460" alt="Consensus">
  </picture>
</p>

<p align="center">By the <a href="https://osint.ngo">OSINT Experts Society</a></p>

<p align="center"><strong>Search usernames, email addresses and phone numbers with the combined capabilities of leading open-source OSINT tools.</strong></p>

<div align="center">
<table align="center">
  <thead>
    <tr><th align="left">Tool</th><th align="center">Username</th><th align="center">Email</th><th align="center">Phone</th></tr>
  </thead>
  <tbody>
    <tr><td align="left"><strong>Consensus</strong></td><td align="center"><strong>7,782</strong></td><td align="center"><strong>205</strong></td><td align="center"><strong>2</strong></td></tr>
    <tr><td align="left"><a href="https://github.com/soxoj/maigret/blob/b6642744988e7e6c2d21f75db60ec3093019ba25/maigret/resources/data.json">Maigret</a></td><td align="center">5,483</td><td align="center">—</td><td align="center">—</td></tr>
    <tr><td align="left"><a href="https://github.com/kaifcodec/user-scanner/tree/780d077a468035c6afd6b4a0f987317db651528b/user_scanner">User Scanner</a></td><td align="center">2,511</td><td align="center">211</td><td align="center">—</td></tr>
    <tr><td align="left"><a href="https://github.com/WebBreacher/WhatsMyName/blob/062bcfe48df79fa618e96edc79dc9673f3fe5643/wmn-data.json">WhatsMyName</a></td><td align="center">716</td><td align="center">—</td><td align="center">—</td></tr>
    <tr><td align="left"><a href="https://github.com/sherlock-project/sherlock/blob/e40a45ec2a074b90703b3b4b842c8a3adbd6ada3/sherlock_project/resources/data.json">Sherlock</a></td><td align="center">481</td><td align="center">—</td><td align="center">—</td></tr>
    <tr><td align="left"><a href="https://github.com/megadose/holehe/tree/14da70f588538936b20d238783c5e28a0772a2b3/holehe/modules">Holehe</a></td><td align="center">—</td><td align="center">123</td><td align="center">—</td></tr>
    <tr><td align="left"><a href="https://github.com/megadose/ignorant/tree/40b3eb734ef3d55e6d16eb314e49dbf520fa1f64/ignorant/modules">Ignorant</a></td><td align="center">—</td><td align="center">—</td><td align="center">3</td></tr>
  </tbody>
</table>
</div>

<details>
<summary align="center">About these counts (3 October 2026)</summary>

Catalogue snapshot: 3 October 2026. Counts site rules/module files, excluding explicitly disabled/invalid entries and package helpers. Overlapping implementations can cover the same service; these are not unique-site counts or a live reliability benchmark. Phone counts cover account lookups, excluding number analysis and search links. Actual checks depend on scan options and service requirements. — = no definitions in these catalogues.

</details>

<p align="center">One platform. The strength of many.</p>

**One search. Clear results. See which source tools cover each match.**

Consensus brings together selected lookup modules and site lists from **15+ open-source projects**, including:

**[Sherlock](https://github.com/sherlock-project/sherlock) | [Maigret](https://github.com/soxoj/maigret) | [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) | [Holehe](https://github.com/megadose/holehe) | [User Scanner](https://github.com/kaifcodec/user-scanner)**

**Bulk search &middot; Proxy support &middot; Reports &middot; Interactive graphs &middot; Advanced search options**

Built by the **OSINT Experts Society**. Our maintenance target is weekly expert reviews of new community lookup modules, evaluating suitable additions for Consensus.

## Install

You need [Python 3.10+](https://www.python.org/downloads/) and [Git](https://git-scm.com/downloads).

```console
git clone https://github.com/OSINT-Experts-Society/Consensus-OSINT.git
cd Consensus-OSINT
python -m pip install ".[modules]"
consensus
```

On macOS/Linux, use `python3` if `python` is unavailable. While this repository is private, you need GitHub access to clone it.

<details>
<summary>Installation help</summary>

If pip reports an **externally managed environment**, create a virtual environment in the cloned folder:

**macOS / Linux**

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install ".[modules]"
consensus
```

**Windows PowerShell** (also works when activation scripts are blocked)

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install ".[modules]"
.\.venv\Scripts\consensus.exe
```

For later sessions, activate the environment on macOS/Linux, or run `.\.venv\Scripts\consensus.exe` from the cloned folder on Windows.

If `consensus` is not found after a standard installation, run `python -m consensus_osint.cli` with the same Python used to install it.

</details>

## Start searching

Run **`consensus`** to open the menu:

1. Choose **Username**, **Email**, **Phone** or **Bulk search**.
2. Enter what you want to look up and follow the prompts.
3. Choose **View results** or **Save report** when finished.

Use international phone numbers, including the country code. Press **Ctrl+C** to stop a scan; type **`exit`** to quit.

Need command-line options? Run `consensus --help` or `consensus examples`.

### Command-line examples

Replace the quoted placeholders with your search:

```console
consensus user "YOUR_USERNAME"
consensus email "YOUR_EMAIL"
consensus phone "+COUNTRY_CODE_AND_NUMBER"
consensus user "YOUR_USERNAME" -o reports/username.html
```

For PDF reports or MCP support, install the extras you need: `python -m pip install ".[modules,pdf]"` or `python -m pip install ".[modules,mcp]"`.

## Join the community

Help shape Consensus: share feedback, suggest a site or [report an issue](https://github.com/OSINT-Experts-Society/Consensus-OSINT/issues).

Connect with the **OSINT Experts Society** on [our website](https://osint.ngo), [LinkedIn](https://www.linkedin.com/groups/13047129/) and [Reddit](https://www.reddit.com/r/OSINTExperts/).

Use responsibly and verify important matches at their source.

[GPL-3.0-or-later](LICENSE) | [Third-party credits and licences](THIRD_PARTY_NOTICES.txt)
