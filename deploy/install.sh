#!/bin/bash
# OLUNE REMOTE — instalador no servidor (EC2 Ubuntu 24.04). Executar como root:
#   curl -fsSL https://raw.githubusercontent.com/jamesht509/olune-hbbs/main/deploy/install.sh -o /tmp/olune-install.sh
#   bash /tmp/olune-install.sh v1.1.16-olune.2
# Faz: baixa hbbs/hbbr do release no GitHub (confere SHA256), troca o docker compose por serviços systemd
# nativos, instala o Olune Access (convites/cotas, python3) + Caddy (TLS Let's Encrypt no nome sslip.io do
# IP fixo) e liga o gate de convites no hbbs (OLUNE_ACCESS_DB). Idempotente: pode rodar de novo para atualizar.
set -euo pipefail
TAG="${1:-v1.1.16-olune.2}"
REF="${DEPLOY_REF:-main}"
REPO="jamesht509/olune-hbbs"
RAW="https://raw.githubusercontent.com/$REPO/$REF/deploy"
BASE=/opt/olune-server; DATA=$BASE/data; BIN=$BASE/bin
export DEBIAN_FRONTEND=noninteractive
[ "$(id -u)" = 0 ] || { echo "execute como root"; exit 1; }
[ -s "$DATA/id_ed25519" ] || { echo "chave do servidor nao encontrada em $DATA/id_ed25519"; exit 1; }

echo "== pacotes"
apt-get update -qq
apt-get install -y -qq python3 curl ca-certificates debian-keyring debian-archive-keyring apt-transport-https gnupg >/dev/null
# Caddy não está nos repositórios padrão do Ubuntu: adiciona o repositório oficial (cloudsmith).
if ! command -v caddy >/dev/null 2>&1; then
  curl -1fsSL 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq
  apt-get install -y -qq caddy >/dev/null
fi

echo "== binarios $TAG"
TMP=$(mktemp -d); cd "$TMP"
curl -fsSL -o olune-hbbs.tar.gz "https://github.com/$REPO/releases/download/$TAG/olune-hbbs-linux-amd64.tar.gz"
curl -fsSL -o SHA256SUMS.release "https://github.com/$REPO/releases/download/$TAG/SHA256SUMS"
tar -xzf olune-hbbs.tar.gz
sha256sum -c SHA256SUMS.release
mkdir -p "$BIN"; install -m 0755 hbbs hbbr "$BIN/"

echo "== arquivos de implantacao ($REF)"
for f in olune_access.py olune-access.service olune-hbbs.service olune-hbbr.service Caddyfile refresh-host.sh; do
  curl -fsSL -o "$TMP/$f" "$RAW/$f"
done
mkdir -p /opt/olune-access
install -m 0644 "$TMP/olune_access.py" /opt/olune-access/olune_access.py
install -m 0644 "$TMP/olune-access.service" "$TMP/olune-hbbs.service" "$TMP/olune-hbbr.service" /etc/systemd/system/
[ -x "$BASE/refresh-host.sh" ] || install -m 0755 "$TMP/refresh-host.sh" "$BASE/refresh-host.sh"
"$BASE/refresh-host.sh" || true
IP=$(sed -n 's/^OLUNE_PUBLIC_HOST=//p' "$BASE/.env" | head -1)
[ -n "$IP" ] || { echo "IP publico nao encontrado em $BASE/.env"; exit 1; }
HOST="$(echo "$IP" | tr . -).sslip.io"
sed "s/__HOST__/$HOST/" "$TMP/Caddyfile" > /etc/caddy/Caddyfile

echo "== desligando docker compose antigo (hbbs/hbbr em container)"
systemctl disable --now olune-server.service 2>/dev/null || true
(cd "$BASE" && docker compose down 2>/dev/null) || true
systemctl disable --now docker.socket docker.service containerd.service 2>/dev/null || true

echo "== servicos"
systemctl daemon-reload
systemctl enable --now olune-access.service
systemctl restart olune-access.service
for i in $(seq 1 20); do [ -s "$DATA/olune-access.sqlite3" ] && break; sleep 1; done
systemctl enable --now olune-hbbr.service olune-hbbs.service
systemctl restart olune-hbbr.service olune-hbbs.service
systemctl enable caddy >/dev/null 2>&1 || true
systemctl restart caddy
sleep 3
echo "ativos: $(systemctl is-active olune-access olune-hbbr olune-hbbs caddy | tr '\n' ' ')"
ss -lntup 2>/dev/null | grep -E ':(21115|21116|21117|21121|443) ' | awk '{print $1, $5}' | sort -u
echo "health: $(curl -s http://127.0.0.1:21121/v1/health)"
echo "hbbs: $(journalctl -u olune-hbbs -n 3 --no-pager -o cat | tail -n 3 | tr '\n' ' ')"
echo "OLUNE_ACCESS_HOST=https://$HOST"
echo "OLUNE_ADMIN_TOKEN=$(cat "$DATA/olune-admin.token")"
echo "OLUNE_INSTALL_OK $TAG"
rm -rf "$TMP"
