sudo tc qdisc del dev lo root
sudo tc qdisc add dev lo root handle 1: htb
sudo tc class add dev lo parent 1: classid 1:1 htb rate 100mbit
sudo tc qdisc add dev lo parent 1:1 handle 10: netem delay 25ms
sudo tc filter add dev lo parent 1: protocol ip prio 1 u32 flowid 1:1 match ip tos 0x02 0xff

sudo tc class add dev lo parent 1: classid 1:2 htb rate 100mbit
sudo tc qdisc add dev lo parent 1:2 handle 20: netem delay 50ms
sudo tc filter add dev lo parent 1: protocol ip prio 1 u32 flowid 1:2 match ip tos 0x04 0xff
