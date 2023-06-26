rm -rf pkts
mkdir pkts
for n in {1..1024};
do
    ./bin/pktgen -p 100 -c ./tools/pktgen/cmd/pktgen/testdata/sample.json 1-ff00:0:111,172.20.0.29:31100 --daemon 172.20.0.21:30255 -o pkts/$n.pcap --flowid $n
done

mergecap pkts/*.pcap -w pkts/all.pcapng