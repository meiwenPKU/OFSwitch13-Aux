/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* Network topology
 *
 *  h00---     --- c0----      ---hn0
 *        \   /          \    /
 *   .     \ /            \  /     .
 *   .      s0----s1...----sn      .
 *   .     /     /  \        \     .
 *        /     /    \        \
 *  h0n---    h10    h1n       ---hnn
 */
#include <sys/time.h>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/ofswitch13-module.h"
#include "ns3/netanim-module.h"
#include <map>

using namespace ns3;

#define REALLY_BIG_TIME 1000000
#define CONNECTION 0

typedef struct timeval TIMER_TYPE;
#define TIMER_NOW(_t) gettimeofday (&_t,NULL);
#define TIMER_SECONDS(_t) ((double)(_t).tv_sec + (_t).tv_usec * 1e-6)
#define TIMER_DIFF(_t1, _t2) (TIMER_SECONDS (_t1) - TIMER_SECONDS (_t2))

NS_LOG_COMPONENT_DEFINE("linear-auxConn");

int main(int argc, char *argv[]) {

	typedef std::vector<NodeContainer> vector_of_NodeContainer;
	typedef std::vector<OFSwitch13DeviceContainer> vector_of_OFSwitch13DeviceContainer;
	typedef std::vector<NetDeviceContainer> vector_of_NetDeviceContainer;
	typedef std::vector<vector_of_NetDeviceContainer> vector_of_vector_of_NetDeviceContainer;

	uint32_t seed = 1;      // the seed for random variable generation
	uint32_t maxBytes = 5120;
	int num_switch = 3; 	// number of switch nodes in the core ring network
	int num_host = 20; 	// number of hosts connected with one edge switch
	int num_TCP_conn = 0; // number of tcp auxiliary connections between a switch and the controller
	int num_UDP_conn = 3; // number of udp auxiliary connections between a switch and the controller
	int BW_ctrl = 1;      // bandwidth of the control channel (unit is Mbps)

	uint32_t min_start_time = 20; // minimal starting time for on-off application
	uint32_t start_time_interval = 0.001; // the interval of starting time between on_off application

	bool verbose = true;  // log information level indication in ryu application

	std::ostringstream oss;

	CommandLine cmd;
	cmd.AddValue("maxBytes", "Total number of bytes for application to send",
			maxBytes);
	cmd.AddValue("num_switch", "Number of switches in the network", num_switch);
	cmd.AddValue("num_host", "number of hosts connected with one edge switch ",
			num_host);
	cmd.AddValue("min_start_time",
			"the minimal start time of on-off application", min_start_time);
	cmd.AddValue("start_time_interval",
			"the interval of starting time between serilized onoff applications",
			start_time_interval);
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
	// enable log component

	if (verbose) {
		LogComponentEnable("linear-auxConn", LOG_LEVEL_INFO);
		LogComponentEnable("OnOffApplication", LOG_LEVEL_INFO);
		LogComponentEnable("OFSwitch13Device", LOG_LEVEL_DEBUG);
		LogComponentEnable("OFSwitch13Controller", LOG_LEVEL_DEBUG);
		LogComponentEnable("PacketSink", LOG_LEVEL_INFO);
		LogComponentEnable("PointToPointChannel", LOG_LEVEL_INFO);
	}

	TIMER_TYPE t0, t1, t2;
	TIMER_NOW(t0);
	RngSeedManager::SetSeed(seed);
	//RngSeedManager::SetSeed(TIMER_SECONDS(t0));
	// ---------------------define nodes-----------------------
	NodeContainer switch_nodes, controller_nodes;
	vector_of_NodeContainer host_nodes(num_switch);

	//----------------------define net device------------------
	NetDeviceContainer hostDevices;
	vector_of_NetDeviceContainer switch_2_switch_net_device(num_switch - 1);
	vector_of_OFSwitch13DeviceContainer switch_2_controller_net_device(
			num_switch);
	vector_of_vector_of_NetDeviceContainer host_2_switch_net_device(num_switch,
			vector_of_NetDeviceContainer(num_host));
	vector_of_NetDeviceContainer controller_net_device(1), switch_ports(
			num_switch);

	// ---------------------define links-----------------------
	CsmaHelper link_host_2_switch, link_switch_2_switch;
	link_switch_2_switch.SetChannelAttribute("DataRate", StringValue("10Mbps"));
	link_switch_2_switch.SetChannelAttribute("Delay", StringValue("1ms"));

	link_host_2_switch.SetChannelAttribute("DataRate", StringValue("1Mbps"));
	link_host_2_switch.SetChannelAttribute("Delay", StringValue("1ms"));

	// ---------------------define OF13Helper
	Ptr<OFSwitch13Helper> of13Helper = CreateObject<OFSwitch13Helper>();

	// ---------------------create nodes--------------------------
	NS_LOG_INFO("create controller nodes");
	controller_nodes.Create(1);

	NS_LOG_INFO("create switch node in the core network");
	switch_nodes.Create(num_switch);

	NS_LOG_INFO("create host nodes");
	for (int i = 0; i < num_switch; i++) {
		host_nodes[i].Create(num_host);
	}

	// ----------------------------------------------connect nodes----------------------------------------------
	//---connect switch nodes ------
	NS_LOG_INFO("connect switch nodes");
	for (int i = 1; i < num_switch; i++) {
		NodeContainer nc(switch_nodes.Get(i - 1), switch_nodes.Get(i));
		switch_2_switch_net_device[i - 1] = link_switch_2_switch.Install(nc);
		switch_ports[i - 1].Add(switch_2_switch_net_device[i - 1].Get(0));
		switch_ports[i].Add(switch_2_switch_net_device[i - 1].Get(1));
	}

	//------connect host nodes to switch nodes-----------
	NS_LOG_INFO("connect host nodes to switch nodes");
	for (int i = 0; i < num_switch; i++) {
		for (int z = 0; z < num_host; z++) {
			NodeContainer nc(host_nodes[i].Get(z), switch_nodes.Get(i));
			host_2_switch_net_device[i][z] = link_host_2_switch.Install(nc);
			switch_ports[i].Add(host_2_switch_net_device[i][z].Get(1));
			hostDevices.Add(host_2_switch_net_device[i][z].Get(0));

		}
	}

	//------connect core switch to controller--------
	Ptr<Node> of13ControllerNode = CreateObject<Node>();
	NS_LOG_INFO("connect the core switch nodes to controller");
	of13Helper->SetAttribute("ChannelType",
			EnumValue(OFSwitch13Helper::DEDICATEDP2P));
	of13Helper->SetChannelDataRate(DataRate(BW_ctrl * 1000000));

	Ptr<OFSwitch13Controller> of13ControllerApp;
	of13ControllerApp = of13Helper->InstallDefaultController(
			of13ControllerNode);
	Ptr<OFSwitch13LearningController> learningCtrl = DynamicCast<
			OFSwitch13LearningController>(of13ControllerApp);

	std::vector<SocketType> v_conn;
	OFSwitch13DeviceContainer switchDevices;
	for (int i = 0; i < num_TCP_conn; i++) {
		v_conn.push_back(TCP);
	}
	for (int i = 0; i < num_UDP_conn; i++) {
		v_conn.push_back(UDP);
	}
	if (v_conn.empty()) {
		for (int i = 0; i < num_switch; i++) {
			switch_2_controller_net_device[i] = of13Helper->InstallSwitch(
					switch_nodes.Get(i), switch_ports[i]);
			switchDevices.Add(switch_2_controller_net_device[i].Get(0));
		}
	} else {
		for (int i = 0; i < num_switch; i++) {
			switch_2_controller_net_device[i] =
					of13Helper->InstallSwitchWithAux(switch_nodes.Get(i),
							switch_ports[i], v_conn);
			switchDevices.Add(switch_2_controller_net_device[i].Get(0));
		}
	}
	// -----------------------install the stack in all nodes and dce manager in controller nodes----------------------
	InternetStackHelper stack;
	// install stack in the host nodes
	NS_LOG_INFO("install stack in the host nodes");
	for (int i = 0; i < num_switch; i++) {
		stack.Install(host_nodes[i]);
	}

	//--------------------------------assign the ip address---------------------------------
	NS_LOG_INFO("Assign IP Address");
	Ipv4AddressHelper ipv4switches;
	Ipv4InterfaceContainer internetIpIfaces;
	ipv4switches.SetBase("11.0.0.0", "255.0.0.0");
	internetIpIfaces = ipv4switches.Assign(hostDevices);
	NS_LOG_INFO("Finished Assign IP Address");

	//--------------------------------------install application -------------------------------------------
	/* install ON-OFF application and packet sink application in every hosts
	 * every host will be installed with an ON-OFF application and packet sink application
	 * the destination of the ON-OFF application is local with probability of 0.5 and is remote with 0.5
	 */
	NS_LOG_INFO("Install ON-OFF APP");
	Ptr<UniformRandomVariable> random_num_generator = CreateObject<
			UniformRandomVariable>();
	ApplicationContainer sink_apps;
	int app_index = 0;
	PacketSinkHelper sink_helper("ns3::TcpSocketFactory",
			InetSocketAddress(Ipv4Address::GetAny(), 9999));
	sink_helper.SetAttribute("IntervalSet", UintegerValue(500));
	for (int i = 0; i < num_switch; i++) {
		for (int z = 0; z < num_host; z++) {
			//NS_LOG_INFO("Install sink application on every host");
			sink_apps.Add(sink_helper.Install(host_nodes[i].Get(z)));
			int i_remote;
			while (true) {
				i_remote = (int) (num_switch - 1)
						* random_num_generator->GetValue() + 1;
				if (i_remote != i)
					break;
			}
			OnOffHelper on_off_helper("ns3::TcpSocketFactory", Address());
			AddressValue remote_address(
					InetSocketAddress(
							internetIpIfaces.GetAddress(
									i_remote * num_host + z), 9999));

			//std::cout<< "(" << i << "," << z <<") -- " << "(" << i_remote << "," << z << "): " << internetIpIfaces.GetAddress(i_remote*num_host+z) << " -- " << internetIpIfaces.GetAddress(i_remote*num_host+z) <<std::endl;

			on_off_helper.SetAttribute("Remote", remote_address);
			on_off_helper.SetAttribute("MaxBytes", UintegerValue(maxBytes));
			ApplicationContainer on_off_app;
			on_off_app = on_off_helper.Install(host_nodes[i].Get(z));
			on_off_app.Start(
					Seconds(start_time_interval * app_index + min_start_time));
			app_index++;

		}
	}
	sink_apps.Start(Seconds(0.0));

	uint32_t totalRx = 0;

	FlowMonitorHelper monitor;
	for (int i = 0; i < num_switch; i++) {
		monitor.Install(host_nodes[i]);
	}

	//Simulator::Stop(Seconds(400.0));

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
	std::cout << numLostPktIn / (numPktIn + 0.0) << " " << sumDelay / numFlow
			<< " ";

	std::map<uint8_t, int> TX_map;
	std::map<uint8_t, int> RX_map;
	for (int i = 0; i < num_switch; i++) {
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
	std::cout << "total sent bytes = " << maxBytes * num_switch * num_host
			<< std::endl;
	std::cout << "get " << totalRx << " B" << std::endl;
	double simulate_time = TIMER_DIFF (t1, t0) + TIMER_DIFF(t2, t1);
	std::cout << "total simulation time = " << simulate_time << std::endl;
	std::cout << "simulation stopped at " << Simulator::Now().GetSeconds()
			<< std::endl;

	std::cout << maxBytes * num_switch * num_host << " " << totalRx << " ";
	Simulator::Destroy();

	// std::cout << "Simulation is finished" << std::endl;
	return 0;

}

