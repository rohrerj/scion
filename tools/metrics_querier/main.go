// Copyright 2023 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"flag"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
)

var (
	promAddr       string
	queryFrequency int
	queryCount     int
	resultFile     string
	bufferSize     int
)

func main() {
	err := log.Setup(log.Config{Console: log.ConsoleConfig{Level: "info"}})
	if err != nil {
		return
	}
	addFlags()
	flag.Parse()

	flag.VisitAll(func(f *flag.Flag) {
		log.Info("Flag", f.Name, f.Value)
	})

	_, err = net.ResolveUDPAddr("udp", promAddr)
	if err != nil {
		log.Error("Address could not be resolved correctly.", "addr", promAddr, "err", err)
		return
	}
	log.Info("Quering started")

	err = startPromFetcher()
	if err != nil {
		log.Info("Quering failed")
	} else {
		log.Info("Quering finished")
	}
}

func addFlags() {
	flag.StringVar(&promAddr, "addr", "",
		"The prometheus address of the service to query(e.g. 127.0.0.20:30458)")
	flag.IntVar(&queryFrequency, "freq", 1000, "Query frequency in milliseconds (e.g. 1000)")
	flag.IntVar(&queryCount, "count", 30, "Number of total queries (e.g. 30)")
	flag.StringVar(&resultFile, "file", "metrics.json", "The result file (e.g. metrics.json)")
	flag.IntVar(&bufferSize, "buffer", 50000, "The buffer size for a single poll (e.g. 50000)")
}

func startPromFetcher() error {
	httpClient := &http.Client{}
	metricsBuffer := make([]byte, bufferSize)
	ticker := time.NewTicker(time.Duration(queryFrequency) * time.Millisecond)

	fullMap := make(map[string]map[string]float64)

	for i := 0; i < queryCount; i++ {
		t := <-ticker.C
		m, err := fetchMetrics(httpClient, metricsBuffer)
		if err != nil {
			log.Error("An error occurred while querying", "err", err)
			return err
		}
		for k, v := range m {
			dp, found := fullMap[k]
			if !found {
				dp = make(map[string]float64)
				fullMap[k] = dp
			}
			dp[strconv.Itoa(int(t.UnixMilli()))] = v
		}
	}
	data, err := json.MarshalIndent(fullMap, "", "\t")
	if err != nil {
		log.Error("metrics", "err", err)
		return err
	}
	file, err := os.Create(resultFile)
	if err != nil {
		log.Error("Accessing the result file failed", "err", err)
		return err
	}
	_, err = file.Write(data)
	if err != nil {
		log.Error("Writing the result file failed", "err", err)
		return err
	}
	file.Close()
	return nil
}

func fetchMetrics(httpClient *http.Client, buffer []byte) (map[string]float64,
	error) {
	req, err := http.NewRequest("GET", "http://"+promAddr+"/metrics", nil)
	if err != nil {
		return nil, serrors.New("Accessing the metrics endpoint failed", "err", err)
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, serrors.New("Accessing the metrics endpoint failed", "err", err)
	}
	n, _ := res.Body.Read(buffer)
	res.Body.Close()
	if n == len(buffer) {
		return nil, serrors.New("Buffer limit reached. Increase the buffer size!",
			"currentSize", bufferSize)
	}
	str := strings.Split(string(buffer[:n]), "\n")
	m := make(map[string]float64)
	for _, s := range str {
		if !strings.HasPrefix(s, "#") && len(s) > 3 {
			kv := strings.Split(s, " ")
			val, err := strconv.ParseFloat(kv[1], 64)
			if err != nil {
				return nil, serrors.New("Parsing the response failed.", "err", err)
			}
			m[kv[0]] = val
		}
	}
	return m, nil
}
