git pull
rm -rf "export"
mkdir "export"
./scion.sh stop
make
echo "Start benchmarks"
go test -bench=. ./go/coligate/processing -run="^#" -benchtime 5s > benchmarks.txt
echo "Start performance measurements with payload size of 200 bytes"
mkdir "export/200"
rm gen-cache/* ; ./scion.sh start ; sleep 5 ; ./bin/coligate_performance -pktSize 200 ; ./scion.sh stop
cp -r ./pprof/ ./export/200/pprof
mkdir "export/500"
echo "Start performance measurements with payload size of 500 bytes"
rm gen-cache/* ; ./scion.sh start ; sleep 5 ; ./bin/coligate_performance -pktSize 500 ; ./scion.sh stop
cp -r ./pprof/ ./export/500/pprof
mkdir "export/1000"
echo "Start performance measurements with payload size of 1000 bytes"
rm gen-cache/* ; ./scion.sh start ; sleep 5 ; ./bin/coligate_performance -pktSize 1000 ; ./scion.sh stop
cp -r ./pprof/ ./export/1000/pprof
mkdir "export/5000"
echo "Start performance measurements with payload size of 5000 bytes"
rm gen-cache/* ; ./scion.sh start ; sleep 5 ; ./bin/coligate_performance -pktSize 5000 ; ./scion.sh stop
cp -r ./pprof/ ./export/5000/pprof
cp -r ./metrics/ ./export
cp ./benchmarks.txt ./export/benchmark.txt
echo "done"