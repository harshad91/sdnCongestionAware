## Congestion aware algorithm for routing elephant flows

This study is based on the concept used by recent data center designs which use a topology
facilitating multiple paths between two hosts. A typical topology (Fattree) is shown below.

![](https://raw.githubusercontent.com/harshad91/sdnCongestionAware/master/fattree_num.png)

Figure1: Fattree topology

Such kind of topologies usually consist of multi-rooted trees with many equal cost paths between a
given pair of hosts. In order to utilize this capability, traffic engineering is done to balance load
accross the network. One such approach is Equal Cost Multi-Path(ECMP) algorithm which uses
hashed forwarding to install a path. 

Because of the randomized behaviour of this algorithm, there are some cases in which colliding
paths are chosen. This can result in congestion further leading to lower data transfer times than
expected.

Here, we propose a greedy algorithm (called Least Congested Path- LCP) which strives
to max-utilize the available bandwidth in a network by exploiting the multi-path capability of
FatTree topology. 

Topology setup is done using mininet, SDN controller is POX and measurements are
performed using IPERF traffic generator.
