sudo tc qdisc del dev lo root
sudo tc qdisc add dev lo root handle 1: htb

#sudo tc class add dev lo parent 1: classid 1:1 htb rate 100mbit
#sudo tc qdisc add dev lo parent 1:1 handle 10: netem delay 50ms
#sudo tc filter add dev lo parent 1: protocol ip prio 1 u32 flowid 1:1 match ip tos 0x01 0xff match ip dport 31004 0xffff
#
#sudo tc class add dev lo parent 1: classid 1:2 htb rate 100mbit
#sudo tc qdisc add dev lo parent 1:2 handle 20: netem delay 0ms
#sudo tc filter add dev lo parent 1: protocol ip prio 1 u32 flowid 1:2 match ip tos 0x02 0xff match ip dport 31004 0xffff
#
#sudo tc class add dev lo parent 1: classid 1:3 htb rate 100mbit
#sudo tc qdisc add dev lo parent 1:3 handle 30: netem delay 100ms
#sudo tc filter add dev lo parent 1: protocol ip prio 1 u32 flowid 1:3 match ip tos 0x00 0xff match ip dport 31004 0xffff

sudo tc class add dev lo parent 1: classid 1:4 htb rate 100mbit
sudo tc qdisc add dev lo parent 1:4 handle 40: netem delay 50ms
sudo tc filter add dev lo parent 1: protocol ip prio 1 u32 flowid 1:4 match ip tos 0x01 0xff match ip dport 31002 0xffff

sudo tc class add dev lo parent 1: classid 1:5 htb rate 100mbit
sudo tc qdisc add dev lo parent 1:5 handle 50: netem delay 0ms
sudo tc filter add dev lo parent 1: protocol ip prio 1 u32 flowid 1:5 match ip tos 0x02 0xff match ip dport 31002 0xffff

sudo tc class add dev lo parent 1: classid 1:6 htb rate 100mbit
sudo tc qdisc add dev lo parent 1:6 handle 60: netem delay 100ms
sudo tc filter add dev lo parent 1: protocol ip prio 1 u32 flowid 1:6 match ip tos 0x00 0xff match ip dport 31002 0xffff

sudo tc class add dev lo parent 1: classid 1:7 htb rate 100mbit
sudo tc qdisc add dev lo parent 1:7 handle 70: netem loss 10%
sudo tc filter add dev lo parent 1: protocol ip prio 1 u32 flowid 1:7 match ip tos 0x04 0xff match ip src 127.0.0.17
