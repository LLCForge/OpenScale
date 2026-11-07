#!/bin/sh
# "OpenScale ile gönder" / "Send with OpenScale" for GNOME Files (Nautilus),
# the Linux counterpart of the Windows Send to entry (#803). It asks for the
# receiving device and runs "openscale send <file> <device>" for each
# selected file; the receiver accepts the file and it lands in quarantine.
#
# Install for one user (no root needed):
#   mkdir -p ~/.local/share/nautilus/scripts
#   cp nautilus-openscale-gonder.sh "$HOME/.local/share/nautilus/scripts/OpenScale ile gönder"
#   chmod 700 "$HOME/.local/share/nautilus/scripts/OpenScale ile gönder"
# Then right-click files > Scripts > "OpenScale ile gönder". zenity shows the
# questions; without it the script writes to standard error only.
set -eu

case "${LANG:-}" in
tr*) ASK='Alıcı cihazın adı:'; BAD='Geçersiz cihaz adı.'; SKIP='Normal dosya değil, atlandı:'; DONE='Gönderildi:'; FAIL='Gönderilemedi:' ;;
*) ASK='Name of the receiving device:'; BAD='Invalid device name.'; SKIP='Not a normal file, skipped:'; DONE='Sent:'; FAIL='Could not send:' ;;
esac

say() {
	if command -v zenity >/dev/null 2>&1; then
		zenity --info --no-markup --title=OpenScale --text="$1" >/dev/null 2>&1 || true
	else
		printf '%s\n' "$1" >&2
	fi
}

if command -v zenity >/dev/null 2>&1; then
	DEVICE=$(zenity --entry --title=OpenScale --text="$ASK") || exit 0
else
	printf '%s ' "$ASK" >&2
	read -r DEVICE
fi
# Device names are DNS labels; nothing else reaches the command line.
case "$DEVICE" in
'' | -* | *[!A-Za-z0-9-]*) say "$BAD"; exit 1 ;;
esac
if [ "${#DEVICE}" -gt 63 ]; then
	say "$BAD"
	exit 1
fi

# Nautilus passes absolute paths, one per line, in this variable.
printf '%s\n' "${NAUTILUS_SCRIPT_SELECTED_FILE_PATHS:-}" | while IFS= read -r FILE; do
	[ -n "$FILE" ] || continue
	# Only regular files that are not symbolic links.
	if [ ! -f "$FILE" ] || [ -L "$FILE" ]; then
		say "$SKIP $FILE"
		continue
	fi
	case "$FILE" in
	/*) ;;
	*) say "$SKIP $FILE"; continue ;;
	esac
	if openscale send "$FILE" "$DEVICE"; then
		say "$DONE $(basename -- "$FILE")"
	else
		say "$FAIL $(basename -- "$FILE")"
	fi
done
