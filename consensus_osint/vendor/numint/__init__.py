"""Vendored subset of numint (https://github.com/whoamitang/numint), MIT.

Only the account-presence layer (``presence/``) and the minimal core it needs
(``core/models.py`` - trimmed, ``core/parser.py``) are vendored; numint's
engine, providers, AI, web and CLI layers are not.  Imports were adapted for
vendoring; the upstream MIT licence is kept in the LICENSE file in this directory.
The Amazon, Instagram and Snapchat entries now call the maintained GPL-3.0
Ignorant implementations through a Consensus bridge. This subset is not an
independently MIT-licensed implementation of those checks. Their HTML guards
need BeautifulSoup (the modules extra) when actually executed.
"""

__version__ = "0.1.0"
