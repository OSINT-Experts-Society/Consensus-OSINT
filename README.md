<p align="center">
  <img src="consensus_osint/templates/consensus-logo.png" width="760" alt="Consensus">
</p>

<h3 align="center">One platform. The strength of many.</h3>

<p align="center">Search usernames, email addresses and phone numbers.</p>

<p align="center">
  <a href="https://osint.ngo"><img src="consensus_osint/templates/society-signature.svg" width="310" alt="By the OSINT Experts Society"></a>
</p>

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

Use responsibly and verify important matches at their source.

[GPL-3.0-or-later](LICENSE) ? [Third-party credits and licences](THIRD_PARTY_NOTICES.txt) ? [OSINT Experts Society](https://osint.ngo)
