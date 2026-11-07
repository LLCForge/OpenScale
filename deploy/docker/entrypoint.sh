#!/bin/sh
# Entry point of the OpenScale container (#168, #292, ADR-0091, ADR-0092).
#
# State store (OPENSCALE_STATE):
#   file    (default) keys and the signed document live in the state
#           directory, normally a named volume; the device keeps its
#           identity across restarts.
#   memory  the state directory must be a tmpfs (docker run --tmpfs, a
#           Kubernetes emptyDir with medium: Memory). Nothing touches a
#           disk; every start is a new device that joins with an invite
#           and is approved again in the panel. The entry point refuses to
#           start if the directory is not memory-backed, so a key is never
#           written to a disk by mistake.
#
# Joining: if the state directory holds no device yet, the entry point
# runs `openscale invite-join` with the invite code from
# OPENSCALE_INVITE_FILE (default /run/secrets/openscale-invite, mounted
# read-only). The 4-digit approval code appears in the container log; the
# owner approves it in the panel. Without an invite it stops with
# instructions; it never starts an unjoined device.
#
# Every argument is passed to `openscale up`; OPENSCALE_<FLAG> variables of
# `up` (OPENSCALE_LISTEN_PORT, OPENSCALE_MTU, ...) work as usual.
set -eu

STATE_DIR=${OPENSCALE_STATE_DIR:-/var/lib/openscale}
MODE=${OPENSCALE_STATE:-file}
INVITE_FILE=${OPENSCALE_INVITE_FILE:-/run/secrets/openscale-invite}

log() { printf 'openscale-entrypoint: %s\n' "$*" >&2; }

case "$STATE_DIR" in
/*) ;;
*) log "OPENSCALE_STATE_DIR mutlak yol olmalı: $STATE_DIR"; exit 2 ;;
esac

# fstype prints the file system type of the mount that holds $1.
fstype() {
	awk -v dir="$1" '
		{ mp = $2; gsub(/\\040/, " ", mp) }
		index(dir "/", (mp == "/" ? "/" : mp "/")) == 1 && length(mp) >= best { best = length(mp); t = $3 }
		END { print t }' /proc/mounts
}

# Everything is checked before the directory is touched.
fs=$(fstype "$STATE_DIR")
case "$MODE" in
file)
	case "$fs" in
	tmpfs | ramfs)
		log "UYARI: OPENSCALE_STATE=file ama $STATE_DIR bellekte ($fs); konteyner silinince cihaz kimliği kaybolur."
		log "       Kalıcı kimlik için bir volume bağlayın, geçici cihaz için OPENSCALE_STATE=memory kullanın."
		;;
	esac
	;;
memory)
	case "$fs" in
	tmpfs | ramfs) ;;
	*)
		log "OPENSCALE_STATE=memory ama $STATE_DIR bellekte değil (dosya sistemi: ${fs:-bilinmiyor})."
		log "Anahtarın diske yazılmaması için başlatılmadı. --tmpfs $STATE_DIR:mode=0700 ile çalıştırın."
		exit 1
		;;
	esac
	;;
*)
	log "OPENSCALE_STATE 'file' veya 'memory' olmalı: $MODE"
	exit 2
	;;
esac

[ -d "$STATE_DIR" ] || install -d -m 0700 "$STATE_DIR"
chmod 0700 "$STATE_DIR"

if [ ! -f "$STATE_DIR/device.key" ] || [ ! -f "$STATE_DIR/anchor.json" ]; then
	if [ -f "$INVITE_FILE" ]; then
		name=${OPENSCALE_HOSTNAME:-$(hostname)}
		log "cihaz ağa katılmamış; davet koduyla katılınıyor (ad: $name)"
		/usr/bin/openscale invite-join --state-dir "$STATE_DIR" --code "@$INVITE_FILE" --name "$name"
	else
		log "cihaz ağa katılmamış ve davet kodu yok ($INVITE_FILE)."
		log "Panelden bir davet oluşturup dosyayı salt okunur bağlayın, ya da elle katılın:"
		log "  docker run --rm -it --entrypoint /usr/bin/openscale -v <volume>:$STATE_DIR <imaj> keygen --state-dir $STATE_DIR"
		log "  (ayrıntı: docs/konteyner.md)"
		exit 1
	fi
fi

exec /usr/bin/openscale up --state-dir "$STATE_DIR" "$@"
