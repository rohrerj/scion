rm -f bin/*
go build -o ./bin/ ./control/cmd/control
go build -o ./bin/ ./daemon/cmd/daemon
go build -o ./bin/ ./dispatcher/cmd/dispatcher
go build -o ./bin/ ./gateway/cmd/gateway
go build -o ./bin/ ./router/cmd/router
go build -o ./bin/ ./scion-pki/cmd/scion-pki
go build -o ./bin/ ./scion/cmd/scion
go build -o ./bin/ ./tools/metrics_querier
go build -o ./bin/ ./tools/pktgen/cmd/pktgen