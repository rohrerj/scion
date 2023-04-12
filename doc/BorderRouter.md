# Border Router Design
* Author: Justin Rohrer
* Last Updated: 2023-04-12
* Status: In Review
* Discussion at: [#4334](https://github.com/scionproto/scion/issues/4334)
* Implemented in: (will be added once implemented)

# Motivation
Right now, the performance of the border router is strongly limited because a single goroutine per
border router interface is responsible for reading, parsing, processing and forwarding the packets.
Hence, the performance has to be improved.

# Overview
The border router is responsible for forwarding packets from the local AS to border routers of
other directly connected ASes and also in the other direction.
To do so the border router has to receive, parse, process and forward the packets.

# Design
The border router will consist of three layers. The communication between those layers and its components
are implemented as go channels.

* **Receivers** One receiver per border router interface is deployed and is responsible for batch-reading the
packets from the network socket, identify the source and flowID and use them to identify which processing
routine has to process the packet.
Each receiver has a preallocated buffer that they can use to store the packets they receive.
* **Processing Routines** Several processing routines are deployed in the border router and are responsible
for processing the packet. The processing implementation remains unchanged.
If a processing routine identifies a packet that belongs to the slow-path, the processing routines forward
the packet to a slow-path processing routine. If the queue of the slow-path processing routine is full, the
packet will not be processed at all. In this case the buffer is immediately returned to the receiver.
Once a packet is processed, it gets forwarded to the forwarder which is responsible for the egress interface.
* **Forwarders** One forwarder per border router interface is deployed and is responsible for forwarding the
packets over the network that it receives from the processing routines. It forwards the packets as a batch.
Afterwards it returns the buffers to the receiver from which that particular buffer originates.

![Border Router Design](fig/border_router/br_design.png)

## Mapping of processing routines
To prevent any packet reordering on the fast-path, we map the tuple of source and flowID to a fixed processing
routine using a hash function.

## Slow path
During processing, packets that have to follow the slow path are identified and forwarded to the
slow-path processing routines.
To rate limit them we can specify a different number of slow-path processing routines in the configuration.
In case a packet is identified to belong to the slow path but the queue of the slow path is full, the
packet is dropped.
Packets currently identified for slow-path are:
* Malformed packets
* SCMP traceroute packets

# Configuration
The configuration of the border router will remain in the border router toml file.
The following configuration entries are added:

## Buffer size in packets
Since a buffer of packets is bound to a receiver, the buffer can be configured for each
receiver seperately.
The number has to be positive.

## Number of processing routines (N)
By configuring the number of processing routines one can specify the number of goroutines that are able
to process packets in parallel.
The number has to be positive.

## Number of slow-path processing routines (M)
By configuring the number of slow-path processing routines one can specify the number of goroutines that
process the packets on the slow-path.
The number has to be positive.

## Processing packets queue size
Since each processing routine has a queue of packets to process and all packets not fitting in the queue
are dropped, one has to specify a reasonable queue size.
The number has to be positive.

# Considerations for future work
## Multiple Receivers per Border Router interface
We could deploy multiple packet receivers per border router interface and use eBPF to make sure that all
packets that belong to the same flow are received by the same receiver.
Because the rest remains unchanged we would still have the "no-reordering" guarantee and significantly
increase the read speed.