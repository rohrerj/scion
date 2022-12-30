git pull
rm -rf "export"
mkdir "export"
make
echo "Start benchmarks"
go test -bench=. ./go/coligate/processing -run="^#" -count 10 > benchmarks.txt
echo "Start performance measurements with payload size of 200 bytes"
mkdir "export/200"
while ! (./scion.sh stop ; rm gen-cache/* ; ./scion.sh start ; sleep 5 ; ./bin/end2end_integration -cmd ./bin/coligate_performance -pktSize 200)
do
    echo "retry"
done
./scion.sh stop
cp -r ./pprof/ ./export/200/pprof
mkdir "export/500"
echo "Start performance measurements with payload size of 500 bytes"
while ! (./scion.sh stop ; rm gen-cache/* ; ./scion.sh start ; sleep 5 ; ./bin/end2end_integration -cmd ./bin/coligate_performance -pktSize 500)
do
    echo "retry"
done
./scion.sh stop
cp -r ./pprof/ ./export/500/pprof
mkdir "export/1000"
echo "Start performance measurements with payload size of 1000 bytes"
while ! (./scion.sh stop ; rm gen-cache/* ; ./scion.sh start ; sleep 5 ; ./bin/end2end_integration -cmd ./bin/coligate_performance -pktSize 1000)
do
    echo "retry"
done
./scion.sh stop
cp -r ./pprof/ ./export/1000/pprof
mkdir "export/5000"
echo "Start performance measurements with payload size of 5000 bytes"
while ! (./scion.sh stop ; rm gen-cache/* ; ./scion.sh start ; sleep 5 ; ./bin/end2end_integration -cmd ./bin/coligate_performance -pktSize 5000)
do
    echo "retry"
done
./scion.sh stop
cp -r ./pprof/ ./export/5000/pprof
cp -r ./metrics/ ./export
cp ./benchmarks.txt ./export/benchmark.txt
echo "done"