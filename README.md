<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="consensus_osint/templates/consensus-wordmark-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="consensus_osint/templates/consensus-wordmark-light.svg">
    <img src="consensus_osint/templates/consensus-wordmark-light.svg" width="460" alt="Consensus">
  </picture>
</p>

<p align="center">By the <a href="https://osint.ngo">OSINT Experts Society</a></p>

<p align="center"><strong>Search usernames, email addresses and phone numbers with the combined capabilities of leading open-source OSINT tools.</strong></p>

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
