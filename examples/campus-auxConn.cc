/* Network topology
 * a ring network consisting num_switch switch nodes (S)
 * every S node connected to a different ring subnet containing num_edge_switch switch nodes (ES)
 * every ES node connects with num_host hosts
 */

#include <string>
#include <fstream>
#include <vector>
#include <sys/time.h>

#include "ns3/core-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/network-module.h"
#include "ns3/log.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/netanim-module.h"
#include "ns3/ofswitch13-module.h"
#include "ns3/flow-monitor-module.h"

using namespace ns3;

typedef struct timeval TIMER_TYPE;
#define TIMER_NOW(_t) gettimeofday (&_t,NULL);
#define TIMER_SECONDS(_t) ((double)(_t).tv_sec + (_t).tv_usec * 1e-6)
#define TIMER_DIFF(_t1, _t2) (TIMER_SECONDS (_t1) - TIMER_SECONDS (_t2))

NS_LOG_COMPONENT_DEFINE("Campus_auxConn");

int main(int argc, char *argv[]) {
	typedef std::vector<NodeContainer> vector_of_NodeContainer;
	typedef std::vector<vector_of_NodeContainer> vector_of_vector_of_NodeContainer;

	typedef std::vector<Ipv4InterfaceContainer> vector_of_Ipv4InterfaceContainer;
	typedef std::vector<vector_of_Ipv4InterfaceContainer> vector_of_vector_of_Ipv4InterfaceContainer;
	typedef std::vector<vector_of_vector_of_Ipv4InterfaceContainer> vector_of_vector_of_vector_of_Ipv4InterfaceContainer;

	typedef std::vector<NetDeviceContainer> vector_of_NetDeviceContainer;
	typedef std::vector<vector_of_NetDeviceContainer> vector_of_vector_of_NetDeviceContainer;
	typedef std::vector<vector_of_vector_of_NetDeviceContainer> vector_of_vector_of_vector_of_NetDeviceContainer;

	typedef std::vector<Ptr<OFSwitch13Helper> > vector_of_OFSwitch13Helper_Pointer;
	typedef std::vector<Ptr<OFSwitch13Controller> > vector_of_OFSwitch13Controller_Ptr;

	uint32_t seed = 1;             //the seed for the random valuable generation
	uint32_t maxBytes = 5120;
	int num_switch = 4;       // number of switch nodes in the core ring network
	int num_edge_switch = 8; // number of edge switch nodes in one subnet
	int num_host = 4;        // number of hosts connected with one edge switch

	int num_TCP_conn = 2; // number of tcp auxiliary connections between a switch and the controller
	int num_UDP_conn = 0; // number of udp auxiliary connections between a switch and the controller
	int BW_ctrl = 1;      // bandwidth of the control channel (unit is Mbps)

	uint32_t min_start_time = 20; // minimal starting time for on-off application
	double start_time_interval = 0.001; // the interval between minimal starting time and maximal starting time

	double prob_remote_app = 0.1; // probability of the event that the destination of an on-off app is remote
	bool verbose = false; // log information level indication in ryu application

	std::ostringstream oss;

	CommandLine cmd;
	cmd.AddValue("maxBytes", "Total number of bytes for application to send",
			maxBytes);
	cmd.AddValue("num_switch", "Number of switches in the core ring network",
			num_switch);
	cmd.AddValue("num_edge_switch", "Number of edge switches in a subnet",
			num_edge_switch);
	cmd.AddValue("num_host", "number of hosts connected with one edge switch ",
			num_host);
	cmd.AddValue("min_start_time",
			"the minimal start time of on-off application", min_start_time);
	cmd.AddValue("start_time_interval",
			"the interval of starting time between serilized onoff applications",
			start_time_interval);
	cmd.AddValue("verbose", "verbose logging", verbose);
	cmd.AddValue("num_TCP_conn",
			"number of tcp auxiliary connections between a switch and the controller",
			num_TCP_conn);
	cmd.AddValue("num_UDP_conn",
			"number of udp auxiliary connections between a switch and the controller",
			num_UDP_conn);
	cmd.AddValue("BW_ctrl", "bandwidth of the control channel (unit is Mbps)",
			BW_ctrl);
	cmd.AddValue("seed", "the seed for the random valuable generation", seed);

	cmd.Parse(argc, argv);
	min_start_time = 3 * num_switch;
	uint32_t num_controller = num_switch + 1; // number of controllers

	if (verbose) {
		LogComponentEnable("Campus_auxConn", LOG_LEVEL_INFO);
		LogComponentEnable("OnOffApplication", LOG_LEVEL_INFO);
		//LogComponentEnable ("OFSwitch13Device", LOG_LEVEL_DEBUG);
		//LogComponentEnable ("OFSwitch13Controller", LOG_LEVEL_DEBUG);
		LogComponentEnable("PacketSink", LOG_LEVEL_INFO);
	}

	TIMER_TYPE t0, t1, t2;
	TIMER_NOW(t0);
	RngSeedManager::SetSeed(seed);
	// ---------------------define nodes-----------------------
	NodeContainer switch_nodes, controller_nodes;
	vector_of_NodeContainer edge_switch_nodes(num_switch);
	vector_of_vector_of_NodeContainer host_nodes(num_switch,
			vector_of_NodeContainer(num_edge_switch));

	//----------------------define net device------------------
	vector_of_NetDeviceContainer switch_2_switch_net_device(num_switch),
			switch_ports(num_switch);
	vector_of_NetDeviceContainer edgeSwitch_2_switch_net_device(num_switch);
	vector_of_vector_of_NetDeviceContainer edgeSwitch_2_edgeSwitch_net_device(
			num_switch, vector_of_NetDeviceContainer(num_edge_switch)),
			edge_switch_ports(num_switch,
					vector_of_NetDeviceContainer(num_edge_switch));
	vector_of_vector_of_vector_of_NetDeviceContainer host_2_edgeSwitch_net_device(
			num_switch,
			vector_of_vector_of_NetDeviceContainer(num_edge_switch,
					vector_of_NetDeviceContainer(num_host)));
	vector_of_vector_of_vector_of_NetDeviceContainer host_device(num_switch,
			vector_of_vector_of_NetDeviceContainer(num_edge_switch,
					vector_of_NetDeviceContainer(num_host)));
	vector_of_NetDeviceContainer controller_net_device(num_switch + 1);
	//vector_of_vector_of_NetDeviceContainer edgeSwitch_controller_net_device(num_switch, vector_of_NetDeviceContainer(num_edge_switch));

	// ---------------------define ipv4 interface
	vector_of_vector_of_vector_of_Ipv4InterfaceContainer host_ipv4_interfaces(
			num_switch,
			vector_of_vector_of_Ipv4InterfaceContainer(num_edge_switch,
					vector_of_Ipv4InterfaceContainer(num_host)));

	// ---------------------define links-----------------------
	CsmaHelper link_edgeSwitch_2_edgeSwitch, link_host_2_edgeSwitch,
			link_switch_2_switch, link_edgeSwitch_2_switch;

	link_switch_2_switch.SetChannelAttribute("DataRate",
			DataRateValue(DataRate("10Mbps")));
	link_switch_2_switch.SetChannelAttribute("Delay", StringValue("5ms"));

	link_edgeSwitch_2_switch.SetChannelAttribute("DataRate",
			DataRateValue(DataRate("10Mbps")));
	link_edgeSwitch_2_switch.SetChannelAttribute("Delay", StringValue("1ms"));

	link_edgeSwitch_2_edgeSwitch.SetChannelAttribute("DataRate",
			DataRateValue(DataRate("1Mbps")));
	link_edgeSwitch_2_edgeSwitch.SetChannelAttribute("Delay",
			StringValue("1ms"));

	link_host_2_edgeSwitch.SetChannelAttribute("DataRate",
			DataRateValue(DataRate("1Mbps")));
	link_host_2_edgeSwitch.SetChannelAttribute("Delay", StringValue("1ms"));

	// ---------------------define OF13Helper
	Ptr<OFSwitch13Helper> switch_helper = CreateObject<OFSwitch13Helper>();
	vector_of_OFSwitch13Helper_Pointer edgeSwitch_helper(num_switch);
	vector_of_OFSwitch13Controller_Ptr v_controller(num_switch + 1);

	// ---------------------create nodes--------------------------
	NS_LOG_INFO("create controller nodes");
	controller_nodes.Create(num_controller);

	NS_LOG_INFO("create switch node in the core network");
	switch_nodes.Create(num_switch);

	NS_LOG_INFO("create edge switch nodes in subnets");
	for (int i = 0; i < num_switch; i++) {
		edge_switch_nodes[i].Create(num_edge_switch);
	}

	NS_LOG_INFO("create host nodes");
	for (int i = 0; i < num_switch; i++) {
		for (int j = 0; j < num_edge_switch; j++) {
			host_nodes[i][j].Create(num_host);
		}
	}

	// ----------------------------------------------connect nodes----------------------------------------------
	//---connect switch nodes in core ring network------
	NS_LOG_INFO("connect switch nodes");
	for (int i = 1; i < num_switch; i++) {
		// due to the spanning tree issue, we delete one link in the ring
		NodeContainer nc(switch_nodes.Get(i - 1), switch_nodes.Get(i));
		switch_2_switch_net_device[i] = link_switch_2_switch.Install(nc);
		switch_ports[i - 1].Add(switch_2_switch_net_device[i].Get(0));
		switch_ports[i].Add(switch_2_switch_net_device[i].Get(1));
	}

	//----connect edge switch nodes in subnet-------
	NS_LOG_INFO("connect edge switch nodes");
	for (int i = 0; i < num_switch; i++) {
		for (int j = 1; j < num_edge_switch; j++) {
			// due to the spanning tree issue, we delete one link in the ring
			NodeContainer nc(edge_switch_nodes[i].Get(j - 1),
					edge_switch_nodes[i].Get(j));
			edgeSwitch_2_edgeSwitch_net_device[i][j] =
					link_edgeSwitch_2_edgeSwitch.Install(nc);
			edge_switch_ports[i][j - 1].Add(
					edgeSwitch_2_edgeSwitch_net_device[i][j].Get(0));
			edge_switch_ports[i][j].Add(
					edgeSwitch_2_edgeSwitch_net_device[i][j].Get(1));

		}
	}
	//------connect edge switch nodes to the switch nodes-------
	NS_LOG_INFO("connect edge switch nodes to switch nodes");
	for (int i = 0; i < num_switch; i++) {
		NodeContainer nc(edge_switch_nodes[i].Get(0), switch_nodes.Get(i));
		edgeSwitch_2_switch_net_device[i] = link_edgeSwitch_2_switch.Install(
				nc);
		edge_switch_ports[i][0].Add(edgeSwitch_2_switch_net_device[i].Get(0));
		switch_ports[i].Add(edgeSwitch_2_switch_net_device[i].Get(1));
	}

	//------connect host nodes to edge switch nodes-----------
	NS_LOG_INFO("connect host nodes to edge switch nodes");
	for (int i = 0; i < num_switch; i++) {
		for (int j = 0; j < num_edge_switch; j++) {
			for (int z = 0; z < num_host; z++) {
				NodeContainer nc(host_nodes[i][j].Get(z),
						edge_switch_nodes[i].Get(j));
				host_2_edgeSwitch_net_device[i][j][z] =
						link_host_2_edgeSwitch.Install(nc);
				edge_switch_ports[i][j].Add(
						host_2_edgeSwitch_net_device[i][j][z].Get(1));
				host_device[i][j][z].Add(
						host_2_edgeSwitch_net_device[i][j][z].Get(0));
			}
		}
	}

	//-----connect the switch nodes to controller------
	NS_LOG_INFO("connect the switch nodes to controller");
	switch_helper->SetAttribute("ChannelType",
			EnumValue(OFSwitch13Helper::DEDICATEDP2P));
	switch_helper->SetChannelDataRate(DataRate(BW_ctrl * 1000000));

	v_controller[0] = switch_helper->InstallDefaultController(
			controller_nodes.Get(0));
	DynamicCast<OFSwitch13LearningController>(v_controller[0]);

	std::vector<SocketType> v_conn;
	OFSwitch13DeviceContainer switchDevices;
	OFSwitch13DeviceContainer sw2CtrlDev;
	for (int i = 0; i < num_TCP_conn; i++) {
		v_conn.push_back(TCP);
	}
	for (int i = 0; i < num_UDP_conn; i++) {
		v_conn.push_back(UDP);
	}

	if (v_conn.empty()) {
		for (int i = 0; i < num_switch; i++) {
			sw2CtrlDev = switch_helper->InstallSwitch(switch_nodes.Get(i),
					switch_ports[i]);
			switchDevices.Add(sw2CtrlDev.Get(0));
		}
	} else {
		for (int i = 0; i < num_switch; i++) {
			sw2CtrlDev = switch_helper->InstallSwitchWithAux(
					switch_nodes.Get(i), switch_ports[i], v_conn);
			switchDevices.Add(sw2CtrlDev.Get(0));
		}
	}

	//------connect the edge switch nodes to controller------
	NS_LOG_INFO("connect the edge switch nodes to controller");
	for (int i = 0; i < num_switch; i++) {
		std::ostringstream oss1;
		oss1.str();
		oss1 << "10.100." << i << ".0";
		edgeSwitch_helper[i] = CreateObject<OFSwitch13Helper>();
		edgeSwitch_helper[i]->SetAttribute("ChannelType",
				EnumValue(OFSwitch13Helper::DEDICATEDP2P));
		edgeSwitch_helper[i]->SetChannelDataRate(DataRate(BW_ctrl * 1000000));

		edgeSwitch_helper[i]->SetAddressBase(oss1.str().c_str(),
				"255.255.255.0");

		v_controller[i + 1] = edgeSwitch_helper[i]->InstallDefaultController(
				controller_nodes.Get(i + 1));
		DynamicCast<OFSwitch13LearningController>(v_controller[i + 1]);

		if (v_conn.empty()) {
			for (int j = 0; j < num_edge_switch; j++) {
				sw2CtrlDev = edgeSwitch_helper[i]->InstallSwitch(
						edge_switch_nodes[i].Get(j), edge_switch_ports[i][j]);
				switchDevices.Add(sw2CtrlDev.Get(0));
			}
		} else {
			for (int j = 0; j < num_edge_switch; j++) {
				sw2CtrlDev = edgeSwitch_helper[i]->InstallSwitchWithAux(
						edge_switch_nodes[i].Get(j), edge_switch_ports[i][j],
						v_conn);
				switchDevices.Add(sw2CtrlDev.Get(0));
			}
		}
	}
	// ------------------------------Install the stack in all nodes------------------------
	InternetStackHelper stack;
	// install stack in the host nodes
	NS_LOG_INFO("install stack in the host nodes");
	for (int i = 0; i < num_switch; i++) {
		for (int j = 0; j < num_edge_switch; j++) {
			stack.Install(host_nodes[i][j]);
		}
	}

	//--------------------------------assign the ip address---------------------------------
	NS_LOG_INFO("Assign IP Address");
	Ipv4AddressHelper ipv4;
	oss.str("");
	oss << "11.0.0.0";
	ipv4.SetBase(oss.str().c_str(), "255.0.0.0");

	for (int i = 0; i < num_switch; i++) {
		for (int j = 0; j < num_edge_switch; j++) {
			for (int z = 0; z < num_host; z++) {
				host_ipv4_interfaces[i][j][z] = ipv4.Assign(
						host_device[i][j][z]);
				NS_LOG_INFO(
						"Host (" << i << "," << j << "," << z << ") ip address for host--edgeSwitch link: " << host_ipv4_interfaces[i][j][z].GetAddress(0));
			}
		}
	}

	//--------------------------------------install application -------------------------------------------
	/* install ON-OFF application and packet sink application in every hosts
	 * every host will be installed with an ON-OFF application and packet sink application
	 * the destination of the ON-OFF application is local with probability of 0.5 and is remote with 0.5
	 */

	Ptr<UniformRandomVariable> random_num_generator = CreateObject<
			UniformRandomVariable>();
	int app_index = 0;
	ApplicationContainer sink_apps;
	PacketSinkHelper sink_helper("ns3::TcpSocketFactory",
			InetSocketAddress(Ipv4Address::GetAny(), 9999));
	sink_helper.SetAttribute("IntervalSet", UintegerValue(500));
	for (int i = 0; i < num_switch; i++) {
		for (int j = 0; j < num_edge_switch; j++) {
			for (int z = 0; z < num_host; z++) {
				//NS_LOG_INFO("Install sink application on every host");
				//PacketSinkHelper sink_helper("ns3::TcpSocketFactory",InetSocketAddress(Ipv4Address::GetAny(),9999));
				sink_apps.Add(sink_helper.Install(host_nodes[i][j].Get(z)));

				// NS_LOG_INFO("Install the on-off application on every host");
				if (random_num_generator->GetValue() < prob_remote_app) {
					//the destination of the on-off app is remote
					int i_remote, j_remote, z_remote;
					//choose the subnet of destination randomly
					while (true) {
						i_remote = (int) num_switch
								* random_num_generator->GetValue();
						if (i_remote != i)
							break;
					}
					//choose the edge switch of destination randomly
					j_remote = (int) num_edge_switch
							* random_num_generator->GetValue();
					//choose the host (i.e., destination) randomly
					z_remote = (int) num_host
							* random_num_generator->GetValue();
					OnOffHelper on_off_helper("ns3::TcpSocketFactory",
							Address());
					AddressValue remote_address(
							InetSocketAddress(
									host_ipv4_interfaces[i_remote][j_remote][z_remote].GetAddress(
											0), 9999));
					on_off_helper.SetAttribute("Remote", remote_address);
					//on_off_helper.SetAttribute("DataRate",StringValue("1Kbps"));
					on_off_helper.SetAttribute("MaxBytes",
							UintegerValue(maxBytes));
					ApplicationContainer on_off_app;
					on_off_app = on_off_helper.Install(host_nodes[i][j].Get(z));
					on_off_app.Start(
							Seconds(
									start_time_interval * app_index
											+ min_start_time));
				} else {
					//the destination of the on-off app is local
					int j_local, z_local;
					if (num_host == 1) {
						while (true) {
							j_local = (int) num_edge_switch
									* random_num_generator->GetValue();
							if (j_local != j)
								break;
						}
					} else {
						j_local = (int) num_edge_switch
								* random_num_generator->GetValue();
					}

					//choose the host (i.e., destination) randomly
					if (j_local == j) {
						while (true) {
							z_local = (int) num_host
									* random_num_generator->GetValue();
							if (z_local != z)
								break;
						}
					} else {
						z_local = (int) num_host
								* random_num_generator->GetValue();
					}
					OnOffHelper on_off_helper("ns3::TcpSocketFactory",
							Address());
					AddressValue remote_address(
							InetSocketAddress(
									host_ipv4_interfaces[i][j_local][z_local].GetAddress(
											0), 9999));

					on_off_helper.SetAttribute("Remote", remote_address);
					//on_off_helper.SetAttribute("DataRate",StringValue("1Kbps"));
					on_off_helper.SetAttribute("MaxBytes",
							UintegerValue(maxBytes));
					ApplicationContainer on_off_app;
					on_off_app = on_off_helper.Install(host_nodes[i][j].Get(z));
					on_off_app.Start(
							Seconds(
									app_index * start_time_interval
											+ min_start_time));
					app_index++;
				}
			}
		}
	}
	sink_apps.Start(Seconds(0.0));

	uint32_t totalRx = 0;

	FlowMonitorHelper monitor;
	for (int i = 0; i < num_switch; i++) {
		for (int j = 0; j < num_edge_switch; j++) {
			monitor.Install(host_nodes[i][j]);
		}
	}

	//Simulator::Stop (Seconds (180));
	TIMER_NOW(t1);
	Simulator::Run();
	TIMER_NOW(t2);
	monitor.SerializeToXmlFile("FlowMonitor.xml", false, false);
	for (uint32_t i = 0; i < sink_apps.GetN(); ++i) {
		Ptr<PacketSink> sink1 = DynamicCast<PacketSink>(sink_apps.Get(i));
		if (sink1) {
			totalRx += sink1->GetTotalRx();
		}
	}
	double sumDelay = 0;
	int numFlow = 0;
	int numLostPktIn = 0;
	int numPktIn = 0;
	for (int i = 0; i < num_switch; i++) {
		numLostPktIn += switchDevices.Get(i)->m_pkt_in.size()
				- switchDevices.Get(i)->m_flow_setup.size();
		numPktIn += switchDevices.Get(i)->m_pkt_in.size();
		std::map<uint32_t, double>::iterator it;
		for (it = switchDevices.Get(i)->m_flow_setup.begin();
				it != switchDevices.Get(i)->m_flow_setup.end(); it++) {
			sumDelay += it->second;
			numFlow++;
		}
	}
	for (int k = 0; k < num_switch; k++) {
		for (int j = 0; j < num_edge_switch; j++) {
			int i = num_switch + k * num_edge_switch + j;
			numLostPktIn += switchDevices.Get(i)->m_pkt_in.size()
					- switchDevices.Get(i)->m_flow_setup.size();
			numPktIn += switchDevices.Get(i)->m_pkt_in.size();
			std::map<uint32_t, double>::iterator it;
			for (it = switchDevices.Get(i)->m_flow_setup.begin();
					it != switchDevices.Get(i)->m_flow_setup.end(); it++) {
				sumDelay += it->second;
				numFlow++;
			}
		}
	}

	std::cout << numLostPktIn / (numPktIn + 0.0) << " " << sumDelay / numFlow
			<< " ";

	std::map<uint8_t, int> TX_map;
	std::map<uint8_t, int> RX_map;
	for (int i = 0; i < (int) switchDevices.GetN(); i++) {
		std::cout << "switch id = " << i << std::endl;
		std::map<uint8_t, std::map<ofp_type, int> >::iterator it;
		for (it = switchDevices.Get(i)->m_conn_to_TXthr.begin();
				it != switchDevices.Get(i)->m_conn_to_TXthr.end(); ++it) {
			if (TX_map.find(it->first) == TX_map.end()) {
				TX_map[it->first] = 0;
			}
			std::cout << "    conntion id = " << unsigned(it->first)
					<< std::endl;
			std::map<ofp_type, int>::iterator it_m;
			for (it_m = it->second.begin(); it_m != it->second.end(); it_m++) {
				TX_map[it->first] += it_m->second;
				std::cout << "        send packet type = " << it_m->first
						<< ", throughput = " << it_m->second << std::endl;
			}
		}

		for (it = switchDevices.Get(i)->m_conn_to_RXthr.begin();
				it != switchDevices.Get(i)->m_conn_to_RXthr.end(); ++it) {
			if (RX_map.find(it->first) == RX_map.end()) {
				RX_map[it->first] = 0;
			}
			std::cout << "    conntion id = " << unsigned(it->first)
					<< std::endl;
			std::map<ofp_type, int>::iterator it_m;
			for (it_m = it->second.begin(); it_m != it->second.end(); it_m++) {
				RX_map[it->first] += it_m->second;
				std::cout << "        received packet type = " << it_m->first
						<< ", throughput = " << it_m->second << std::endl;
			}
		}

	}

	for (std::map<uint8_t, int>::iterator it = TX_map.begin();
			it != TX_map.end(); ++it) {
		std::cout << unsigned(it->first) << " " << it->second << std::endl;
	}

	for (std::map<uint8_t, int>::iterator it = RX_map.begin();
			it != RX_map.end(); ++it) {
		std::cout << unsigned(it->first) << " " << it->second << std::endl;
	}

	Ptr<PacketSink> sink1 = DynamicCast<PacketSink>(sink_apps.Get(0));
	std::cout << "last packet received at simulation time = "
			<< sink1->GetLastRevTime() << ", use "
			<< sink1->GetLastRevWallClockTime() - TIMER_SECONDS(t0)
			<< std::endl;
	std::cout << "total sent bytes = "
			<< maxBytes * num_switch * num_edge_switch * num_host << std::endl;
	std::cout << "get " << totalRx << " B" << std::endl;
	double simulate_time = TIMER_DIFF (t1, t0) + TIMER_DIFF(t2, t1);
	std::cout << "total simulation time = " << simulate_time << std::endl;
	std::cout << "simulation stopped at " << Simulator::Now().GetSeconds()
			<< std::endl;

	// double simulate_time = TIMER_DIFF (t1, t0) + TIMER_DIFF (t2, t1);
	//Ptr<PacketSink> sink1 = DynamicCast<PacketSink> (sink_apps.Get (0));
	std::cout << totalRx << " "
			<< maxBytes * num_switch * num_edge_switch * num_host << " ";
	Simulator::Destroy();
	return 0;
}

