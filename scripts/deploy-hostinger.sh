#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
remote='u224024544@88.223.84.124'
identity="$HOME/.ssh/inoon_hostinger_codex"
release="$(date -u +%Y%m%dT%H%M%SZ)"
archive="$(mktemp /tmp/cosmicnoon-site.XXXXXX)"
trap 'rm -f "$archive"' EXIT
for file in index.html about/index.html contact/index.html spacekeeper/index.html assets/css/site.css assets/js/site.js; do
  test -s "$file"
done
COPYFILE_DISABLE=1 tar --exclude='.DS_Store' -czf "$archive" index.html about contact spacekeeper assets images admin
scp -i "$identity" -P 65002 -o BatchMode=yes -o StrictHostKeyChecking=yes backend/MatomoReports.php "$remote:domains/cosmicnoon.com.au/private/MatomoReports.php"
scp -i "$identity" -P 65002 -o BatchMode=yes -o StrictHostKeyChecking=yes "$archive" "$remote:domains/cosmicnoon.com.au/release-$release.tar.gz"
ssh -i "$identity" -p 65002 -o BatchMode=yes -o StrictHostKeyChecking=yes "$remote" bash -s -- "$release" <<'REMOTE'
set -euo pipefail
release="$1"
cd "$HOME/domains/cosmicnoon.com.au"
mkdir -p .deployment-backups ".deploy-$release"
tar -xzf "release-$release.tar.gz" -C ".deploy-$release"
for file in index.html about/index.html contact/index.html spacekeeper/index.html assets/css/site.css assets/js/site.js; do
  test -s ".deploy-$release/$file"
done
test -s ".deploy-$release/admin/index.php"
test -s "$HOME/domains/cosmicnoon.com.au/private/admin-config.php"
mv public_html ".deployment-backups/$release"
mv ".deploy-$release" public_html
printf 'Deployed %s; prior site saved in .deployment-backups/%s\n' "$release" "$release"
REMOTE
