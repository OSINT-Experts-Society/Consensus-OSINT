#!/bin/sh
# Install or update Consensus with its own Python runtime.
set -eu
CONSENSUS_INSTALL_DIR="${CONSENSUS_INSTALL_DIR:-$HOME/.local/share/consensus-app}"
export CONSENSUS_INSTALL_DIR
export UV_UNMANAGED_INSTALL="$CONSENSUS_INSTALL_DIR/uv"
export UV_PYTHON_INSTALL_DIR="$CONSENSUS_INSTALL_DIR/python"
export UV_PYTHON_INSTALL_BIN=0
release='https://github.com/OSINT-Experts-Society/Consensus-OSINT/releases/latest/download'
temporary=$(mktemp -d)
trap 'rm -f "$temporary/uv-install.sh" "$temporary/install-manager.py"; rmdir "$temporary"' EXIT
fetch() {
    curl --proto '=https' --tlsv1.2 -fsSL "$1" -o "$2"
}
mkdir -p "$CONSENSUS_INSTALL_DIR"
bundle=${1:-}
if [ -z "$bundle" ] && [ -f "$(dirname "$0")/release.json" ]; then
    bundle=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
fi
if [ -n "$bundle" ]; then
    bundle=$(CDPATH= cd -- "$bundle" && pwd)
    cp "$bundle/install-manager.py" "$temporary/install-manager.py"
elif ! fetch "$release/install-manager.py" "$temporary/install-manager.py"; then
    printf '%s\n' 'Could not download the Consensus installer release. Check that a release is published at https://github.com/OSINT-Experts-Society/Consensus-OSINT/releases and that GitHub is reachable. No application update was installed.' >&2
    exit 1
fi
if [ ! -x "$UV_UNMANAGED_INSTALL/uv" ]; then
    printf '%s\n' 'Preparing the private Consensus runtime...'
    fetch 'https://astral.sh/uv/0.11.15/install.sh' "$temporary/uv-install.sh"
    sh "$temporary/uv-install.sh"
fi
if [ -n "$bundle" ]; then
    "$UV_UNMANAGED_INSTALL/uv" run --no-config --no-project --managed-python --python 3.13 python -I "$temporary/install-manager.py" --feed "$bundle" --extras "${CONSENSUS_INSTALL_EXTRAS:-modules,pdf}"
else
    "$UV_UNMANAGED_INSTALL/uv" run --no-config --no-project --managed-python --python 3.13 python -I "$temporary/install-manager.py"
fi
if [ "${CONSENSUS_NO_MODIFY_PATH:-0}" != 1 ]; then
    UV_TOOL_BIN_DIR="$CONSENSUS_INSTALL_DIR/bin" "$UV_UNMANAGED_INSTALL/uv" tool update-shell
    printf '%s\n' 'Ready. Open a new terminal and run consensus. To update later, run consensus update.'
else
    printf 'Ready. Add %s/bin to PATH or run "%s/bin/consensus" directly.\n' "$CONSENSUS_INSTALL_DIR" "$CONSENSUS_INSTALL_DIR"
fi
