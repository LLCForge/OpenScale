#!/bin/sh
# "OpenScale ile gönder" / "Send with OpenScale" as a Finder Quick Action,
# the macOS counterpart of the Windows Send to entry (#803). It asks for the
# receiving device and runs "openscale send <file> <device>" for each
# selected file; the receiver accepts the file and it lands in quarantine.
#
# Set up once in Automator (or Shortcuts):
#   1. New > Quick Action. "Workflow receives current": files or folders,
#      in: Finder.
#   2. Add "Run Shell Script", Shell: /bin/sh, Pass input: as arguments.
#   3. Paste this file's contents and save as "OpenScale ile gönder".
# Then right-click files in Finder > Quick Actions > "OpenScale ile gönder".
# The openscale command must be on PATH (or change OPENSCALE below).
set -eu

OPENSCALE=${OPENSCALE:-/usr/local/bin/openscale}

case "${LANG:-}" in
tr*) ASK='Alıcı cihazın adı:'; BAD='Geçersiz cihaz adı.'; SKIP='Normal dosya değil, atlandı:'; DONE='Gönderildi:'; FAIL='Gönderilemedi:' ;;
*) ASK='Name of the receiving device:'; BAD='Invalid device name.'; SKIP='Not a normal file, skipped:'; DONE='Sent:'; FAIL='Could not send:' ;;
esac

# The text goes to AppleScript as an argument, never inside the script.
say() {
	osascript -e 'on run argv' -e 'display notification (item 1 of argv) with title "OpenScale"' -e 'end run' "$1" >/dev/null 2>&1 || true
}

DEVICE=$(osascript -e 'on run argv' -e 'text returned of (display dialog (item 1 of argv) default answer "" with title "OpenScale")' -e 'end run' "$ASK") || exit 0
case "$DEVICE" in
'' | -* | *[!A-Za-z0-9-]*) say "$BAD"; exit 1 ;;
esac
if [ "${#DEVICE}" -gt 63 ]; then
	say "$BAD"
	exit 1
fi

for FILE in "$@"; do
	if [ ! -f "$FILE" ] || [ -L "$FILE" ]; then
		say "$SKIP $FILE"
		continue
	fi
	case "$FILE" in
	/*) ;;
	*) say "$SKIP $FILE"; continue ;;
	esac
	if "$OPENSCALE" send "$FILE" "$DEVICE"; then
		say "$DONE $(basename -- "$FILE")"
	else
		say "$FAIL $(basename -- "$FILE")"
	fi
done
