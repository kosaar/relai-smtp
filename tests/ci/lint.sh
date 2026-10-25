#!/usr/bin/env bash
# =============================================================================
#  Contrôles statiques (local et CI) : shellcheck, compilation Python,
#  tests unitaires Python (tests/unit, modules purs des images).
#  Usage : tests/ci/lint.sh
# =============================================================================
set -Eeuo pipefail
cd "$(dirname "$0")/../.."
export PYTHONDONTWRITEBYTECODE=1

rc=0
echo "==> shellcheck"
mapfile -t shells < <(git ls-files -z | xargs -0 grep -lIE '^#!.*(ba)?sh|^# shellcheck shell=' 2>/dev/null | sort -u)
shellcheck -x "${shells[@]}" || rc=1

echo "==> compilation Python"
mapfile -t pys < <(git ls-files -z | xargs -0 grep -lIE '^#!.*python3' 2>/dev/null; git ls-files '*.py')
if (( ${#pys[@]} )); then
    for f in "${pys[@]}"; do
        python3 -c 'import ast,sys; ast.parse(open(sys.argv[1],"rb").read(), sys.argv[1])' "$f" || rc=1
    done
fi

echo "==> tests unitaires Python"
if compgen -G 'tests/unit/test_*.py' >/dev/null; then
    python3 -m unittest discover -s tests/unit -t . -v || rc=1
else
    echo "(aucun test unitaire)"
fi

exit "$rc"
