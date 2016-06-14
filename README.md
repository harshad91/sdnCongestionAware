## Congestion aware algorithm for routing elephant flows

This study is based on the concept used by recent data center designs which use a topology
facilitating multiple paths between two hosts. A typical topology (Fattree) is shown below.

![alt tag]()

Figure1: Fattree topology

Such kind of topologies usually consist of multi-rooted trees with many equal cost paths between a
given pair of hosts. In order to utilize this capability, traffic engineering is done to balance load
accross the network. One such approach is Equal Cost Multi-Path(ECMP) algorithm which uses
hashed forwarding to install a path. 

Because of the randomized behaviour of this algorithm, there are some cases in which colliding
paths are chosen. This can result in congestion further leading to lower data transfer times than
expected.
Here, we propose a greedy algorithm (henceforth called Least Congested Path- LCP) which strives
to max-utilize the available bandwidth in a network by exploiting the multi-path capability of
FatTree topology. Through the paper, we will put forth the algorithm and prove how it benefits over
ECMP.
Topology setup is done using mininet[1], SDN controller is POX[2] and measurements are
performed using IPERF[3] traffic generator.
