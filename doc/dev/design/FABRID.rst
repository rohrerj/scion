********
FABRID
********
.. _fabrid-design:

- Author: Justin Rohrer, Jelte van Bommel, Marc Odermatt, Marc Wyss, Cyrill Krähenbühl, Juan A. García-Pardo
- Last Updated: 2024-03-28
- Discussion at:

Abstract
===========

In SCION the endhosts have the option to choose *inter-AS* paths to forward packets to a destination.
However, some applications require more fine grained path selection like "Do not route traffic over devices
produced by hardware manufacturer X or that run software Y with version < Z" which requires transparency and
control also with respect to *intra-AS* paths.
This is useful for example if there exists a known bug in certain router versions that affect secure communication,
or if an entity simply does not trust a certain hardware manufacturer.
This can also be seen as an enhancement for keeping traffic within a certain jurisdiction, e.g., by routing traffic
only along devices located in a specific country.

Background
===========

`FABRID <https://netsec.ethz.ch/publications/papers/2023_usenix_fabrid.pdf>`_, is suggested as a solution to the
aforementioned problem.
A deployment of FABRID in SCIONLab makes its next-generation features available to interested parties around the globe.
FABRID also implicitly implements the `EPIC <https://netsec.ethz.ch/publications/papers/Legner_Usenix2020_EPIC.pdf>`_,
features source authentication for routers and destination host and path validation for source and destination hosts.

Proposal
========

FABRID indroduces policies, which can be thought of as additional path constraints that should be applied to intra-AS paths.
The border routers use those policies to decide on the intra-AS path to forward, e.g. by using MPLS labels.
Some FABRID policies are globally defined and others locally per AS.
The AS network operator configures which global FABRID policies are supported for the local AS and can add additional local FABRID
policies that are valid for this AS.
A source endhost can then select a path together with FABRID policies and forward the FABRID packet over this path to a destination endhost.
The destination endhost will then be able to recompute the path validator to verify that the packet had been forwarded over that inter-AS path.

Our proposed design and implementation of FABRID allows for incremental deployment at router- and AS-level, i.e., some AS operators may want to
deploy FABRID while others do not, and those who do may only want to deploy it on a subset of border routers.
This allows for a smooth migration where an AS can test-wise update some border routers and test that nothing breaks.
However, this could lead to the situation that we cannot find an end-to-end FABRID-enabled path.
The end host can still send its traffic along that inter-domain path by disabling FABRID for the on-path ASes that do not support it,
but without any of the guarantees provided by FABRID for those ASes.

Since each AS can create their own local FABRID policies, the end hosts have to learn them.
In our design, end hosts fetch policies from their local AS, and the local AS fetches them from the desired remote AS.
Those policies are only fetched on demand by the local control service and will be cached till end of their validity.
This allows for better scalability for the FABRID policies because an AS does not have to learn all FABRID policies from all other ASes.
Even though the beacon had to be adapted, the size increase is negligible.
The source endhost does not have to do anything about that, he will learn the policies from its local control service
which will either return the cached policies of query the remote control service.

This design document specifies the details of the of a header design, namely two new Hop-by-Hop extension options, forwarding support in the routers,
path validation for the destination endhost and additional beaconing information from the control service.

The design document will be extended in the future to also specify features that will be implemented in a later
iteration e,g. path validation for source end host.


Header design
--------------

The FABRID header design is built using the SCION Hop-by-Hop extensions (HBH), which allows for incremental deployability.
We created two different HBH options.
First, the Identifier option that contains the packet ID and a timestamp which is used to uniquely identify a packet of a flow.
And second, the FABRID option that contains the FABRID hopfield metadata fields and a path validator field.
The Identifier option can be used without the FABRID option and can therefore also be used by other extensions.
The FABRID option on the other hand requires that the Identifier option is specified in the HBH extension before the FABRID option.

.. _identifier-option:

Identifier Option
^^^^^^^^^^^^^^^^^^

The Identifier Option always has a length of 8 bytes and look like::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                    |  OptType = 3  |  OptLen = 8   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |R R R R R|                Timestamp                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Packet ID                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Timestamp
    The 27 bit timestamp of when the packet has been sent with 1 millisecond precision
    relative to the timestamp of the first InfoField of the SCION header.
Packet ID
    The 32 bit packet ID that is used together with the timestamp to uniquely identify
    the packet originating from a particular flow.

.. _fabrid-option:

FABRID Option
^^^^^^^^^^^^^^

The FABRID Option has a length of (#NumberOfOnPathASes + 1)*4 bytes.
This hop-by-hop option has an allignment of 4 bytes::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                    |  OptType = 4  |  OptLen = ?   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Enc PolicyID  |F|A|   Hop Validation Field                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Enc PolicyID  |F|A|   Hop Validation Field                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    ....       | | |               ....                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Enc PolicyID  |F|A|   Hop Validation Field                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Path Validator                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Encrypted PolicyID
    The 8 bit encrypted FABRID policy index.
F
    Stands for “FABRID enabled” and if this is set to false, the router responsible for
    that hop will not apply any FABRID logic to this packet.
    This can be used e.g. if an on-path AS does not support FABRID, or if the endhost does not care
    about FABRID for that AS.
A
    Stands for “AS-level key”. If this is set to true, instead of a AS-Host Key, an AS-AS DRKey will be used.
    This can be used to achieve scalability in future in-network DDoS defense solutions, see `RAINBOW`_.
    Using the AS-Host Key is the default option in FABRID.
Hop Validation Field
    22 bit Message Authentication Code to authenticate the FABRID extension metadata field.
    With this the receiving endhost can be sure that the packet has actually been processed by that AS.
Path Validator
    4 byte Path Validator. The sending endhost will compute the path validator and the
    receiving endhost can then recompute the path validator to verify that the packet
    has been sent over the correct path.

Identifier and FABRID Option combined
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If no other HBH extension options are present, the HBH options of a FABRID-enabled packet look like this::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                    |  OptType = 3  |  OptLen = 8   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |R R R R R|                Timestamp                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Packet ID                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Padding     |    Padding    |  OptType = 4  |  OptLen = ?   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Enc PolicyID  |F|A|   Hop Validation Field                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Enc PolicyID  |F|A|   Hop Validation Field                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    ....       | | |               ....                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Enc PolicyID  |F|A|   Hop Validation Field                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Path Validator                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Header fields computation
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. math::
    \begin{align*}
        &\text{encryptedPolicyID = policyID} \oplus \text{AES.Encrypt(}K_i\text{, Identifier)[0]}\\\\
        &\text{policyID = encryptedPolicyID} \oplus \text{AES.Encrypt(}K_i\text{, Identifier)[0]}\\\\
        &K_i \text{ = DRKey (AS A}_i \rightarrow \text{AS}_0\text{:Endhost) or (AS A}_i \rightarrow \text{AS}_0)\\\\
        &\text{HVF}_i = \text{MAC}_{K_i}\text{(Identifier, ingress}_i\text{, egress}_i\text{, encryptedPolicyID}_i, \\& \text{srcAddrLen, srcHostAddr)[0:3] } \& \text{ 0x3FFFFF}\\\\
        &\text{HVFVerified}_i = \text{MAC}_{K_i}\text{(Identifier, ingress}_i\text{, egress}_i\text{, encryptedPolicyID}_i, \\& \text{srcAddrLen, srcHostAddr)[3:6] } \& \text{ 0x3FFFFF}\\\\
    \end{align*}


For accessing a sub slice we use the [a:b] notation, where we take the bytes from index a to index b, where b is exclusive.
For the used DRKeys we use the notation AS A :math:`_i \rightarrow` AS :math:`_j`:Endhost TODO

Data plane
----------

Processing at the router
^^^^^^^^^^^^^^^^^^^^^^^^^^

Whenever a FABRID enabled router receives a SCION packet, it has to figure out whether it should be processed as FABRID or not.
In both cases, all the logic of a normal SCION packet will be applied too.
The router determines whether the SCION packet is a FABRID packet as follows:

.. image:: fig/FABRID/FABRIDActivation.png
    :scale: 70%

If the SCION packet uses FABRID, the router is going to verify the correctness of the current FABRID Hop-validation-field using
either the AS-to-AS or AS-to-Host DRKey and verifies whether the encrypted policy index matches a valid FABRID policy.
If this is the case, the router will update the FABRID Hop-validation-field accordingly and route the packet over
an intra-AS path matching the provided FABRID policy.
The corresponding intra-AS paths are provided to the border routers by the local control service.

Processing at the endhost
^^^^^^^^^^^^^^^^^^^^^^^^^^

To be able to send a FABRID packet, the endhost has to choose a path that supports its path constraints.
Then it can request the necessary DRKeys from its local control service.
With this the endhost is able to create FABRID packets and then send them to the border router for further forwarding.
The receiving endhost can then recompute the path validator to verify that the packet was forwarded over this path.
The FABRID snet implementation will automatically request the necessary DRKeys and compute the hop validation fields.
The endhost only has to provide the path and the FABRID policies.

Control plane
---------------

Control service
^^^^^^^^^^^^^^^^^

The control plane for FABRID is responsible for parsing FABRID policies into corresponding data structures.
Through gRPC, border routers can query the control service for the list of supported policies per interface,
as well as the mapping from policies to MPLS labels.
Policies are disseminated to remote ASes through PCBs, which clients in the AS can query from their Path Servers.
This policy information can also be requested directly from remote ASes over gRPC.

The control service introduces a FABRID service with the following endpoints where intra-AS means it can be reached
from the local AS and inter-AS means it can be reached from a remote AS:

- GetMPLSMapIfNecessary (intra-AS)
- GetRemotePolicyDescription (intra-AS)
- GetSupportedIndicesMap (inter-AS, intra-AS)
- GetIndexIdentifierMap (inter-AS, intra-AS)
- GetLocalPolicyDescription (inter-AS, intra-AS)

Important data structures
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The FABRID service uses the following important data structures:

- SupportedIndicesMap
    Maps a connection pair consisting of two ConnectionPoints (Type: string, IP: string, Prefix: uint32, InterfaceId: uint16)
    to a list of policy indices.
    This map shows for each connection pair which policy indices are supported, which can be one or multiple policies.
    A ConnectionPoint is either an interface, an IP range or wildcard.
    For all intermediary hops interface to interface connection points will be used whereas interface to IP range is used for the last hop.
- IndexIdentifierMap
    A policy index is to be embedded in the HBH extension and therefore has to be minimal in size.
    The size of a policy index is 8 bits, whereas identifiers can be a multiple of this (especially global identifiers).
    The policy index is thus different to the policy identifier. In order to decode which policies are supported on which interfaces,
    a mapping is required from policy index to local and global identifiers.
    This mapping is provided by this map.
- IdentifierDescriptionMap
    Global identifiers can be found in a global datastore, but local identifiers are specific to an AS.
    This map maps a local policy identifier to its corresponding description.
- MPLSMaps
    Routers need to be aware of the supported policy indices and the corresponding MPLS config they need to apply to packets to
    enforce the policy in the internal network.
    Routers periodically fetch this map from the control service.
    A hash of the MPLS map is maintained, such that routers only have to update if their hash differs from the one at the control service.
- RemotePolicyCache
    When a local policy is queried at a remote AS, the resulting policy description is cached at the requesting AS' FABRID Manager,
    such that subsequent requests can be served from cache.


PCB dissemination
^^^^^^^^^^^^^^^^^^^^^^^

The IndexIdentifierMap and SupportedIndicesMap are included in a (unsigned) detachable extension in the PCBs for an AS.
Hashes of these maps are maintained in a Signed AS Entry, such that the authenticity of these maps can be verified.
If the maps are detached, they can be fetched from the control service of that AS and the received maps can be verified with the hashes.
To ensure a consistent hash calculation, the key entries of these maps have to be sorted, such that they are accessed in a consistent order.

Exposing policies to the end hosts
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The path combinator finds the most recent FABRID map per AS among the received segments and subsequently uses this map to find the FABRID
policies that are available for each interface pair of hops.
This results in a set of PolicyIdentifiers per hop, which can then be used by the application, such as with the usage of a
specific ‘sequence’ parameter which incorporates the policies.
Once the application has decided which policies to use, it can craft a FABRID HBH extension and include this as an option when sending
the packet.

DRKey
^^^^^^

FABRID uses DRKey for computing the Encrypted Policy Indices, the FABRID Hop Validation Fields and the Path Validator.
The routers use the fast key derivation side, whereas the endhosts will use the slow side.

Configuration
--------------

Control service
^^^^^^^^^^^^^^^^^^

To be able to use DRKey, one has to configure the control service setting "drkey.level1_db" and "drkey.secret_value_db".
Additionally, since the border routers will fetch the secret value from the control service, the control service also has to
add the internal IP address of all border routers of the local AS to the DRKey delegation list for FABRID.

This could look like this::

    [drkey.level1_db]
    connection = "gen-cache/cs1-ff00_0_110-1.drkey-level1.db"

    [drkey.secret_value_db]
    connection = "gen-cache/cs1-ff00_0_110-1.drkey-secret.db"

    [drkey.delegation]
    FABRID = [ "fd00:f00d:cafe::7f00:11", "fd00:f00d:cafe::7f00:12", "fd00:f00d:cafe::7f00:13"]

The FABRID policies are configured in the control service. TODO(jelte): add more details

Border router
^^^^^^^^^^^^^^^

For a router to query the DRKey secret value from the control service, once has to enable this.

This could look like this::

    [router]
    use_drkey = true

Considerations for future work
--------------------------------

SCMP response
^^^^^^^^^^^^^^^

With the current implementation, the sending endhost is not being informed when his packet gets dropped due to a FABRID error.
In the future the border routers we might think about whether to enable routers to send an SCMP response if they encounter
an error when processing FABRID which might help the sending endhost in figuring out why his packet does not arrive at its destination.
However, we have to be careful to not introduce additional attack vectors, e.g. for volumetric denial-of-service or reflection attacks.

EPIC-HP as extension with Identifier option
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We could create a new HBH extension for EPIC hidden-path, which uses the Identifier option, instead of the
current design which uses a SCION path-type.
This allows the use of EPIC HP also in a incremental deployment like we have with FABRID.
And additionally, we could also use FABRID together with EPIC HP.

.. _RAINBOW:

The RAINBOW system
^^^^^^^^^^^^^^^^^^^^^

The RAINBOW system is a future extension of FABRID, which allows marking traffic as higher quality of service, to be
prioritized at on-path BRs.
Specifically, each BR reserves a certain amount of bandwidth for RAINBOW traffic, which is divided evenly between different source ASes.
As this division happens on the level of ASes and not individual endhosts, the BR also needs to be able to authenticate traffic at an AS level.
The FABRID HBH extension makes this possible, by including an "AS level key" flag, which specifies that the original HVF has been authenticated
again by an AS-AS DRKey, that is only known to trusted infrastructure in the source AS.

Rationale
==========

Path type vs HBH extension
--------------------------------

FABRID can be implemented either as a HBH extension or a path type.
The reason why we decided against a path type is that FABRID as a HBH extension is incrementally deployable, whereas
a new path type is not.
The drawback of this solution is that for the FABRID HBH extension, the Identifier HBH extension, and the HBH extension
header itself, we need in total 8 additional bytes compared to a design that uses a path-type.

Separate Identifier option
---------------------------

Instead of just having a single FABRID HBH option, we decided to move the packet ID and packet timestamp to another HBH option,
the so called Identifier option, because this might also be useful for other HBH extensions and not just for FABRID
(e.g., it would allow to port EPIC-HP from a path type to a HBH extension).
Since FABRID still requires the packetID and packet timestamp, providing the Identifier option became mandatory for FABRID packets.
The cost of moving the Identifier to a separate HBH extension is 4 bytes, where 2 bytes are used for the HBH option type and length
fields and 2 bytes for padding to have the FABRID HBH extension 4 bytes alligned.

Length of PacketID and PacketTimestamp for the Identifier HBH option
---------------------------------------------------------------------

The Identifier has a timestamp with a length of 27 bits, which encodes the relative time in milliseconds after
the timestamp value of the first InfoField of the SCION header.
The 27 bit allow to save relative timestamps with a difference of up to 37 hours which fulfills the requirement
that a path can be valid for up to 24 hours.

Length of FABRID policyID and how to determinte whether policy is local or global
----------------------------------------------------------------------------------

The decision on whether a certain FABRID policy is a local or global policy is done by the control service,
hence we do not have to reserve any bits of the FABRID policy index in the FABRID packets to encode whether
it is a local or global policy.
In the header design the FABRID policyIndex has a length of 1 byte, which allows 256 different options.
But since the control service can configure the policies per interface pair and / or per IP range, there
are many more options than the 256.


Compatibility
===============

FABRID is a new extension which uses the SCION Hop-by-Hop extension which allows
for incremental deployment of FABRID.
If a border router does not understand the FABRID Hop-by-Hop extension
it will simply ignore it and hence not provide any of the FABRID functionality and forward the packet as if it
is a normal SCION packet.
The "FABRID enabled" flag allows the sending endhost to choose for which ASes to enable path validation,
but is also specifically required, for edge-cases where an AS just starts to roll out FABRID functionality to its
border routers, but the sender does not yet know that this AS is FABRID aware.
Because if a packet does not contain a HVF for this AS, the packet has to be dropped unless the sender can explicitly
state that FABRID is disabled for this hop.

Implementation
================

We plan to provide the implementation in the following steps (PRs):

- Support in the border router to set MPLS labels to outgoing packets

- The basic FABRID implementation as described in this design document

- Full FABRID with path validation also at source

- FABRID Intra-AS emulation for SCIONLab