#!/usr/bin/with-contenv bashio
# shellcheck shell=bash
# Start of the OpenScale add-on (#890, docs/homeassistant.md).
#  1. joins the network once with the invite code from the add-on options
#     (the code is written to a 0600 file, never to the command line or
#     the log), then asks the owner to remove it from the options;
#  2. optionally configures the MQTT publisher (#561) with the Mosquitto
#     add-on's credentials from the Supervisor and runs it next to the
#     tunnel;
#  3. runs "openscale up" in the foreground.
set -euo pipefail

STATE=/data/openscale
install -d -m 0700 "$STATE"
umask 077

NAME=$(bashio::config 'hostname')
PORT=$(bashio::config 'listen_port')
MEM=$(bashio::config 'memory_profile')
# The Supervisor validates the schema; checked again before any use.
[[ "$NAME" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || bashio::exit.nok "hostname geçersiz"
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && ((PORT >= 1 && PORT <= 65535)) || bashio::exit.nok "listen_port geçersiz"
[[ "$MEM" == low || "$MEM" == default ]] || bashio::exit.nok "memory_profile geçersiz"

if [[ ! -c /dev/net/tun ]]; then
	bashio::exit.nok "/dev/net/tun yok; eklentinin aygıt izni verilmemiş"
fi

if [[ ! -f "$STATE/device.key" || ! -f "$STATE/anchor.json" ]]; then
	if bashio::config.has_value 'invite_code'; then
		invite=$(mktemp -p /data .invite.XXXXXX)
		trap 'rm -f "$invite"' EXIT
		bashio::config 'invite_code' >"$invite"
		bashio::log.info "Cihaz ağa katılıyor (ad: ${NAME}); 4 haneli onay kodu aşağıda, panelden onaylayın."
		if ! /usr/bin/openscale invite-join --state-dir "$STATE" --code "@$invite" --name "$NAME"; then
			rm -f "$invite"
			bashio::exit.nok "Katılım başarısız; davet kodunu ve süresini denetleyin."
		fi
		rm -f "$invite"
		trap - EXIT
		bashio::log.warning "Katılım tamam. Davet kodunu eklenti ayarlarından silin; artık gerekmez."
	else
		bashio::exit.nok "Cihaz ağa katılmamış: panelden bir davet oluşturup eklenti ayarlarındaki invite_code alanına yapıştırın."
	fi
fi

if bashio::config.true 'mqtt_publish'; then
	PREFIX=$(bashio::config 'mqtt_prefix')
	if bashio::services.available 'mqtt'; then
		host=$(bashio::services mqtt 'host')
		mport=$(bashio::services mqtt 'port')
		user=$(bashio::services mqtt 'username')
		pass_file=$(mktemp -p "$STATE" .mqtt-password.XXXXXX)
		bashio::services mqtt 'password' >"$pass_file"
		args=(mqtt init --config "$STATE/mqtt.json" --broker "${host}:${mport}" --prefix "$PREFIX")
		if [[ -n "$user" ]]; then
			args+=(--user "$user" --password-file "$pass_file")
		fi
		if /usr/bin/openscale "${args[@]}" >/dev/null; then
			bashio::log.info "MQTT yayıncısı ${host}:${mport} aracısına ${PREFIX}/... konularıyla yayımlayacak."
			# Waits for the tunnel's local API, restarts after a broker outage.
			(
				sleep 20
				while true; do
					/usr/bin/openscale mqtt run --config "$STATE/mqtt.json" --state-dir "$STATE" || true
					sleep 30
				done
			) &
		else
			bashio::log.warning "MQTT yapılandırılamadı; tünel MQTT olmadan çalışıyor."
		fi
		rm -f "$pass_file"
	else
		bashio::log.warning "mqtt_publish açık ama MQTT servisi (Mosquitto eklentisi) yok; yayın kapalı."
	fi
else
	rm -f "$STATE/mqtt.json"
fi

export OPENSCALE_MEMORY_PROFILE="$MEM"
bashio::log.info "OpenScale tüneli açılıyor (UDP ${PORT})."
exec /usr/bin/openscale up --state-dir "$STATE" --listen-port "$PORT" --interface OpenScale
