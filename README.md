# SDN-Project-Multipath-Load-Balancing-with-RYU-controller-and-Mininet
The explosive growth of network traffic and complexities of modern applications necessitate efficient traffic management strategies. Software-Defined Networking (SDN) empowers network administrators with centralized control and programmability, opening doors for novel traffic management solutions like multipath load balancing. This project delves into the implementation of multipath load balancing within an SDN environment using Mininet and Ryu, aiming to optimize network performance by distributing traffic across multiple available paths.

# Network Topology
* Mininet is used to create a virtual network composed of switches, hosts, and links, replicating a real-world network topology. 
* Switches support OpenFlow protocol, enabling communication with the Ryu controller. 
* Multiple paths are configured between source and destination hosts, providing options for traffic distribution.

<p align="center">
<img src='https://github.com/ayodyawkh/SDN-Project-Multipath-Load-Balancing-with-RYU-controller-and-Mininet/assets/81368846/0b646831-dcd4-4e59-a4b4-9678dedb4c3d' width='600'>
</p>

# RYU Application Development
The project leverages Ryu, a Python framework for SDN development, to build a multipath load balancing controller. The key components of the RYU application are as follows,
*	ProjectController Class: The main controller class responsible for handling events, installing flows, and managing multipath routing logic.
*	install_paths Function: Calculates multipaths, installs OpenFlow rules for both IPv4 and ARP traffic, and creates group tables for load balancing.
*	get_optimal_paths Function: Identifies up to MAX_PATHS (currently 2) lowest-cost paths using a depth-first search algorithm.
*	add_ports_to_paths Function: Incorporates input and output ports into each path for implementation in network switches.
*	get_link_cost Function: Calculates path costs based on link bandwidth using the reference model.
*	Event Handlers: 
  	  * _switch_features_handler: Handles switch connection events and sets up initial flow rules.
  	  * port_desc_stats_reply_handler: Retrieves link bandwidth information from port descriptions.
  	  * _packet_in_handler: Processes incoming packets, learns host locations, and installs forwarding rules.
  	  * switch_enter_handler: Handles switch connection events and requests port information.


