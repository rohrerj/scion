# Metrics Querier

Can be used to query the prometheus metrics of a service.
One can specify:

* **addr** The prometheus address of the service to query (e.g. 127.0.0.20:30458)

* **freq** Query frequency in milliseconds (e.g. 1000)

* **count** Number of total queries (e.g. 30)

* **file** The result file (e.g. metrics.json)

* **buffer** The buffer size for a single poll (e.g. 50000)

Only the address fields is required.
For all other fields the default values mentioned above will be used.

The metrics querier will query the provided endpoint in total **count** times,
once every **freq** milliseconds and store the results in **file**.

Example command:

```bash
./bin/metrics_querier -addr 127.0.0.9:30442
```