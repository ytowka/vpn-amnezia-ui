#!/usr/bin/env bash
set -euo pipefail

TRANSIT_IP="0.0.0.0"
EXIT_IP="0.0.0.0"
PORT="0"

# Проверка прав
if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash setup-transit.sh"
    exit 1x
fi

# Определяем внешний интерфейс
IFACE="net0"

if [[ -z "$IFACE" ]]; then
    echo "Cannot detect network interface"
    exit 1
fi

echo "Interface: $IFACE"
echo "Transit: $TRANSIT_IP:$PORT"
echo "Exit: $EXIT_IP:$PORT"

# Включаем маршрутизацию IPv4
cat > /etc/sysctl.d/99-amnezia-transit.conf <<EOF
net.ipv4.ip_forward=1
EOF

sysctl -p /etc/sysctl.d/99-amnezia-transit.conf

# Добавляем правило, если оно отсутствует
add_rule() {
    local table="$1"
    shift

    if ! iptables -t "$table" -C "$@" 2>/dev/null; then
        iptables -t "$table" -A "$@"
    fi
}

# DNAT: клиент -> транзит -> выход
add_rule nat PREROUTING \
    -d "$TRANSIT_IP" \
    -p udp --dport "$PORT" \
    -j DNAT --to-destination "$EXIT_IP:$PORT"

# SNAT: подменяем адрес клиента адресом транзита
add_rule nat POSTROUTING \
    -o "$IFACE" \
    -d "$EXIT_IP" \
    -p udp --dport "$PORT" \
    -j SNAT --to-source "$TRANSIT_IP"

# Разрешаем входящий транзит
add_rule filter FORWARD \
    -o "$IFACE" \
    -d "$EXIT_IP" \
    -p udp --dport "$PORT" \
    -j ACCEPT

# Разрешаем обратный трафик
add_rule filter FORWARD \
    -i "$IFACE" \
    -s "$EXIT_IP" \
    -p udp --sport "$PORT" \
    -m conntrack --ctstate ESTABLISHED,RELATED \
    -j ACCEPT

# Сохраняем правила
if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save
else
    echo "WARNING: iptables rules are not persisted."
    echo "Install iptables-persistent or configure"
    echo "your firewall's native persistence mechanism."
fi

echo
echo "AmneziaWG UDP transit configured successfully!"
echo "$TRANSIT_IP:$PORT -> $EXIT_IP:$PORT"


