********
FABRID
********
.. _fabrid:

- Author: Justin Rohrer, Jelte van Bommel
- Last Updated: 2024-03-18
- Discussion at:

Abstract
===========

In SCION the endhosts have the option to choose inter-AS paths to forward packets to a destination.
However some applications require more fine grained path selection like“Do not route traffic over devices
produced by hardware manufacturer X or that run software Y with version < Z” for the intra-AS paths.
This is useful for example if there exists a known bug in certain router versions that affect secure communication,
or if an entity simply does not trust a certain manufacturer.

Background
===========

FABRID, `see here <https://netsec.ethz.ch/publications/papers/2023_usenix_fabrid.pdf>`_, is suggested as a solution to the
aforementioned problem.
An implementation of FABRID in SCIONLab allows for wider testing and evaluations of the protocol.

Proposal
========

The proposal consists of a header design, namely two new Hop-by-Hop extension options, forwarding support in the routers
and additional beaconing information from the control service.

Header design
--------------

The FABRID header design is built using the SCION Hop-by-Hop extensions (HBH) because the allow incremental deployability.
We created two different HBH options.
The Identifier option that contains the packet ID and a timestamp which us used to uniquely identify a packet of a flow.
And the FABRID option that contains the FABRID hopfield metadata fields and a path validator field.
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
    |R R R R R R|              Timestamp                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Packet ID                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Timestamp
    The 26 bit timestamp of when the packet has been sent with 1 second precision.
Packet ID
    The 32 bit packet ID that is used together with the timestamp to uniquely identify
    the packet originating from a particular flow.

.. _fabrid-option:

FABRID Option
^^^^^^^^^^^^^^

The FABRID Option has a length of (#NumberOfOnPathASes + 1)*4 bytes.
This hop-by-hop option should have an allignment of 4 bytes::

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
    that hop will not apply any FABRID logic to this packet
A
    Stands for “AS-level key”. If this is set to true, instead of a AS-Host Key, an AS-AS DRKey will be used.
Hop Validation Field
    22 bit Message Authentication Code to authenticate the FABRID extension metadata field.
Path Validator
    4 byte Path Validator.

Identifier and FABRID Option combined
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Both the Identifier and FABRID extension together could look like this::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                    |  OptType = 3  |  OptLen = 8   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |R R R R R R|              Timestamp                            |
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
        &encryptedPolicyID = policyID \oplus AES.Encrypt(K_i, Identifier)[0]\\\\
        &policyID = encryptedPolicyID \oplus AES.Encrypt(K_i, Identifier)[0]\\\\
        &K_i = DRKey\,(AS\,A_i \rightarrow AS_0:Endhost)\,or\,(AS\,A_i \rightarrow AS_0)\\\\
        &HVF_i = MAC_{K_i}(Identifier, ingress_i, egress_i, encryptedPolicyID_i,\\& srcAddrLen, srcHostAddr)[0:3] \oplus 0x3FFFFF\\\\
        &HVFVerified_i = MAC_{K_i}(Identifier, ingress_i, egress_i, encryptedPolicyID_i,\\& srcAddrLen, srcHostAddr)[3:6] \oplus 0x3FFFFF\\\\
    \end{align*}

Data plane
----------

Processing at the router
^^^^^^^^^^^^^^^^^^^^^^^^^^

Whenever a FABRID enabled router receives a SCION packet, it has to figure out whether it should be processed as FABRID or not.
In both cases, all the logic of a normal SCION packet will be applied too.
The router determines whether the SCION packet is a FABRID packet as follow:

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
With this the endhost is able to create FABRID packets and then send them to the border router for furhter forwarding.
The receiving endhost can then recompute the path validator to verify that the packet was forwarded over this path.

Control plane
---------------

Control service
^^^^^^^^^^^^^^^^^

The control plane for FABRID is responsible for parsing FABRID policies into corresponding data structures, and making
these datastructures available to routers in the same AS, clients in the AS, as well as clients from a remote AS.
Information for FABRID is also included in the PCBs emitted by each FABRID enabled AS.

The control service introduces a FABRID service with the following endpoints:

- GetMPLSMapIfNecessary (intra-AS)
- GetRemotePolicyDescription (intra-AS)
- GetSupportedIndicesMap (inter-AS, intra-AS)
- GetIndexIdentifierMap (inter-AS, intra-AS)
- GetLocalPolicyDescription (inter-AS, intra-AS)

Important data structures
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The FABRID service uses the following important data structures:

- SupportedIndicesMap
    Maps a connection pair consisting of two ConnectionPoints (Type: string, IP: string, Prefix: uint32, InterfaceId: uint16) to a list of policy indices. This map shows for each connection pair which policy indices are supported, which can be one or multiple policies.
- IndexIdentifierMap
    A policy index is to be embedded in the HBH extension and therefore has to be minimal in size. The size of a policy index is 8 bits, whereas identifiers can be a multiple of this (especially global identifiers). The policy index is thus different to the policy identifier. In order to decode which policies are supported on which interfaces, a mapping is required from policy index to local and global identifiers. This mapping is provided by this map.
- IdentifierDescriptionMap
    Global identifiers can be found in a global datastore, but local identifiers are specific to an AS. This map maps a local policy identifier to its corresponding description.
- MPLSMap
    Routers need to be aware of the supported policy indices and the corresponding MPLS config they need to apply to packets to enforce the policy in the internal network. The MPLSMap data structure stores a mapping between policy indices and the integer MPLS label that is applied to the packet at the border router. Routers periodically fetch this map from the control service. A hash of the MPLS map is maintained, such that routers only have to update if their hash differs from the one at the control service.
- RemotePolicyCache
    When a local policy is queried at a remote AS, the resulting policy description is cached at the requesting AS’ FABRID Manager, such that subsequent requests can be served from cache.


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
In the future the border routers might send an SCMP response if they encounter an error when processing FABRID which might
help the sending endhost in figuring out why his packet does not arrive at its destination.

Rationale
==========

Path type vs HBH extension
--------------------------------

FABRID can be implemented either as a HBH extension or a path type.
The reason why we decided against a path type is that FABRID as a HBH extension is incrementally deployable, whereas
a new path type is not.

Identifier option vs include everything in FABRID option
------------------------------------------------------------

We decided to move the packet ID and packet timestamp to another HBH option, the so called Identifier option,
because this might also be useful for other HBH extensions and not just for FABRID (e.g., it would allow to port EPIC-HP from a path type to a HBH extension).
Since FABRID still requires the packetID and packet timestamp, providing the Identifier option became mandatory for FABRID packets.

Compatibility
===============

FABRID is a new extension which uses the SCION Hop-by-Hop extension which allows
for incremential deployment of FABRID. If a border router does not understand the FABRID Hop-by-Hop extension
it will simply ignore it and hence not provide any of the FABRID functionality and forward the packet as if it
is a normal SCION packet. Since the sending endhost should be aware of whether a certain AS supports FABRID or not,
he can just set the "FABRID enabled" flag to false for the non-FABRID aware ASes which will be taken into account
when computing the FABRID path validator.

Implementation
================

The implementation will be implemented in a single pullrequest.