./scion.sh run
sleep 5
sudo tcpreplay -q -i scn_001 --duration 40 --loop 1000000 -tK pkts/all.pcapng &
sleep 1
./bin/metrics_querier --addr="172.20.0.18:30442"
sleep 1
./scion.sh stop