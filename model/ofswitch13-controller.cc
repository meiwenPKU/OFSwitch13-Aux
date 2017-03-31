/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015 University of Campinas (Unicamp)
 *
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
 *
 * Author: Luciano Chaves <luciano@lrc.ic.unicamp.br>
 */

#include <wordexp.h>
#include "ns3/uinteger.h"
#include "ofswitch13-controller.h"

namespace ns3 {

OFSwitch13Controller::EchoInfo::EchoInfo(Ipv4Address ip) {
	waiting = true;
	send = Simulator::Now();
	destIp = ip;
}

Time OFSwitch13Controller::EchoInfo::GetRtt() {
	if (waiting) {
		return Time(-1);
	} else {
		Time rtt = recv - send;
		return recv - send;
	}
}

InetSocketAddress SwitchInfo::GetInet() {
	return InetSocketAddress(ipv4, port);
}

/********** Public methods ***********/
NS_LOG_COMPONENT_DEFINE("OFSwitch13Controller");
NS_OBJECT_ENSURE_REGISTERED(OFSwitch13Controller);

OFSwitch13Controller::OFSwitch13Controller() :
		m_port(6653), m_swport(9999) {
	NS_LOG_FUNCTION(this);
	m_serverSocket = 0;
	m_xid = rand() & 0xffffffff;
}

OFSwitch13Controller::~OFSwitch13Controller() {
	NS_LOG_FUNCTION(this);
}

TypeId OFSwitch13Controller::GetTypeId(void) {
	static TypeId tid =
			TypeId("ns3::OFSwitch13Controller").SetParent<Object>().SetGroupName(
					"OFSwitch13").AddAttribute("Port",
					"Port on which we listen for incoming packets.",
					TypeId::ATTR_GET, UintegerValue(0),
					MakeUintegerAccessor(&OFSwitch13Controller::m_port),
					MakeUintegerChecker<uint16_t>()).AddAttribute(
					"NoFeatureReplyTimeout",
					"The maximal interval for receiving no feature reply after a feature request is sent.",
					TimeValue(Seconds(5)),
					MakeTimeAccessor(
							&OFSwitch13Controller::m_noFeatureReplyTimeOut),
					MakeTimeChecker()).AddAttribute("NoMsgAfterRecTimeout",
					"The maximal interval for receiving no msg after the last msg receive.",
					TimeValue(Seconds(30)),
					MakeTimeAccessor(&OFSwitch13Controller::m_noRecTimeOut),
					MakeTimeChecker());
	return tid;
}

void OFSwitch13Controller::DoDispose() {
	m_serverSocket = 0;
	m_switchesMap.clear();
	m_echoMap.clear();
	m_schedCommands.clear();

	Application::DoDispose();
}

void OFSwitch13Controller::RegisterSwitchMetadata(SwitchInfo swInfo) {
	NS_LOG_FUNCTION(swInfo.ipv4);

	std::pair<SwitchsMap_t::iterator, bool> ret;
	ret = m_switchesMap.insert(
			std::pair<Ipv4Address, SwitchInfo>(swInfo.ipv4, swInfo));
	if (ret.second == false) {
		NS_LOG_ERROR("This switch is already registered with this controller");
	}
}

void OFSwitch13Controller::RegisterConnection(uint8_t auxID,
		uint64_t datapathID, Ipv4Address source) {
	m_connectionMap.insert(
			std::pair<Ipv4Address, std::pair<uint64_t, uint8_t> >(source,
					std::pair<uint64_t, uint8_t>(datapathID, auxID)));
}

SwitchInfo OFSwitch13Controller::GetSwitchMetadata(
		Ptr<const OFSwitch13Device> dev) {
	NS_LOG_FUNCTION(dev);

	SwitchsMap_t::iterator it;
	for (it = m_switchesMap.begin(); it != m_switchesMap.end(); it++) {
		if (it->second.swDev == dev) {
			return it->second;
		}
	}
	return SwitchInfo();
}

int OFSwitch13Controller::DpctlCommand(SwitchInfo swtch,
		const std::string textCmd) {
	// If no TCP connection, schedule the command for further execution
	if (swtch.socket == NULL) {
		ScheduleCommand(swtch, textCmd);
		return -1;
	}

	int error = 0;
	char **argv;
	size_t argc;

	wordexp_t cmd;
	wordexp(textCmd.c_str(), &cmd, 0);
	argv = cmd.we_wordv;
	argc = cmd.we_wordc;

	if (!strcmp(argv[0], "set-table-match") || !strcmp(argv[0], "ping")) {
		NS_LOG_WARN("Dpctl command currently not supported.");
	} else {
		return dpctl_exec_ns3_command((void*) &swtch, argc, argv);
	}

	wordfree(&cmd);
	return error;
}

int OFSwitch13Controller::DpctlCommand(Ptr<const OFSwitch13Device> dev,
		const std::string textCmd) {
	return DpctlCommand(GetSwitchMetadata(dev), textCmd);
}

void OFSwitch13Controller::DpctlSendAndPrint(vconn *swtch,
		ofl_msg_header *msg) {
	NS_LOG_FUNCTION_NOARGS ();

	SwitchInfo *sw = (SwitchInfo*) swtch;
	sw->ctrl->SendToSwitch(sw, msg, 0);
}

/********* Protected methods *********/
void OFSwitch13Controller::StartApplication() {
	NS_LOG_FUNCTION(this << "Starting Controller app at port " << m_port);

	// Create the server listening tcp socket
	if (!m_serverSocket) {
		m_serverSocket = Socket::CreateSocket(GetNode(),
				TcpSocketFactory::GetTypeId());
		m_serverSocket->SetAttribute("SegmentSize", UintegerValue(8900));
		m_serverSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_port));
		m_serverSocket->Listen();
	}

	// Setting socket callbacks
	m_serverSocket->SetRecvCallback(
			MakeCallback(&OFSwitch13Controller::SocketRead, this));
	m_serverSocket->SetAcceptCallback(
			MakeCallback(&OFSwitch13Controller::SocketRequest, this),
			MakeCallback(&OFSwitch13Controller::SocketAccept, this));
	m_serverSocket->SetCloseCallbacks(
			MakeCallback(&OFSwitch13Controller::SocketPeerClose, this),
			MakeCallback(&OFSwitch13Controller::SocketPeerError, this));

}

void OFSwitch13Controller::StopApplication() {
	for (SwitchsMap_t::iterator it = m_switchesMap.begin();
			it != m_switchesMap.end(); it++) {
		it->second.socket->Close();
	}
	if (m_serverSocket) {
		m_serverSocket->Close();
		m_serverSocket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket> >());
	}
	m_switchesMap.clear();
}

uint32_t OFSwitch13Controller::GetNextXid() {
	return ++m_xid;
}

void OFSwitch13Controller::ConnectionStarted(SwitchInfo swtch) {
	NS_LOG_FUNCTION(this << swtch.ipv4);
}

int OFSwitch13Controller::SendToSwitch(SwitchInfo *swtch, ofl_msg_header *msg,
		uint32_t xid) {
	char *msg_str = ofl_msg_to_string(msg, NULL);
	NS_LOG_DEBUG(
			"At " << Simulator::Now().GetSeconds() << "s, TX to switch " << swtch->ipv4 << ": " << msg_str);
	free(msg_str);

	if (!xid) {
		xid = GetNextXid();
	}

	Ptr<Packet> pkt = ofs::PacketFromMsg(msg, xid);

	// Check for available space in TCP buffer before sending the packet
	Ptr<Socket> switchSocket = swtch->socket;
	if (switchSocket->GetTxAvailable() < pkt->GetSize()) {
		return 0;
		NS_FATAL_ERROR("Unavailable space to send OpenFlow message");
	}

	// NS_LOG_DEBUG(Simulator::Now().GetSeconds() << " send a " << msg->type << " to " << swtch->ipv4);

	return !switchSocket->Send(pkt);
}

int OFSwitch13Controller::SendEchoRequest(SwitchInfo swtch,
		size_t payloadSize) {
	NS_LOG_FUNCTION(swtch.ipv4);

	ofl_msg_echo msg;
	msg.header.type = OFPT_ECHO_REQUEST;
	msg.data_length = payloadSize;
	msg.data = 0;

	if (payloadSize) {
		msg.data = (uint8_t*) xmalloc(payloadSize);
		random_bytes(msg.data, payloadSize);
	}

	uint32_t xid = GetNextXid();
	EchoInfo echo(swtch.ipv4);
	m_echoMap.insert(std::pair<uint32_t, EchoInfo>(xid, echo));

	int error = SendToSwitch(&swtch, (ofl_msg_header*) &msg, xid);

	if (payloadSize) {
		free(msg.data);
	}

	return error;
}

int OFSwitch13Controller::SendBarrierRequest(SwitchInfo swtch) {
	NS_LOG_FUNCTION(swtch.ipv4);

	ofl_msg_header msg;
	msg.type = OFPT_BARRIER_REQUEST;

	return SendToSwitch(&swtch, &msg);
}

// --- BEGIN: Handlers functions -------
ofl_err OFSwitch13Controller::HandleEchoRequest(ofl_msg_echo *msg,
		SwitchInfo swtch, uint32_t xid) {
	NS_LOG_FUNCTION(swtch.ipv4 << xid);

	ofl_msg_echo reply;
	reply.header.type = OFPT_ECHO_REPLY;
	reply.data_length = msg->data_length;
	reply.data = msg->data;
	SendToSwitch(&swtch, (ofl_msg_header*) &reply, xid);

	ofl_msg_free((ofl_msg_header*) msg, NULL /*exp*/);
	return 0;
}

ofl_err OFSwitch13Controller::HandleEchoReply(ofl_msg_echo *msg,
		SwitchInfo swtch, uint32_t xid) {
	NS_LOG_FUNCTION(swtch.ipv4 << xid);

	EchoMsgMap_t::iterator it = m_echoMap.find(xid);
	if (it == m_echoMap.end()) {
		NS_LOG_WARN("Received echo response for unknonw echo request.");
	} else {
		it->second.waiting = false;
		it->second.recv = Simulator::Now();
		NS_LOG_DEBUG(
				"Received echo reply from " << it->second.destIp << " with RTT " << it->second.GetRtt ().As (Time::MS));
	}

	ofl_msg_free((ofl_msg_header*) msg, NULL /*exp*/);
	return 0;
}

ofl_err OFSwitch13Controller::HandleHello(ofl_msg_header *msg, SwitchInfo swtch,
		uint32_t xid) {
	if (m_mainConnSetup[m_connectionMap[swtch.ipv4].first]) {
		// the main connection has already been setup
		return 0;
	} else {
		if (swtch.swDev->GetMainSwAddress()
				== InetSocketAddress(swtch.ipv4, swtch.port)) {
			// the main connection is setup now
			m_mainConnSetup[m_connectionMap[swtch.ipv4].first] = true;
			NS_LOG_DEBUG("Main connection is setup");
			// create the server listening udp socket
			for (std::map<Ipv4Address, SwitchInfo>::iterator it1 =
					m_switchesMap.begin(); it1 != m_switchesMap.end(); ++it1) {
				if (!(it1->second.ctrl) && (it1->second.socket)
						&& (m_connectionMap[swtch.ipv4].first
								== m_connectionMap[it1->second.ipv4].first)) {
					it1->second.socket->Bind(
							InetSocketAddress(it1->second.ctrl_ipv4, m_port));
					it1->second.socket->SetRecvCallback(
							MakeCallback(&OFSwitch13Controller::SocketUdpRead,
									this));
					it1->second.socket->Listen();

					UdpConnInfo udpInfo;
					udpInfo.RecHello = false;
					m_udpConnStat.insert(
							std::pair<Address, UdpConnInfo>(
									InetSocketAddress(it1->second.ipv4,
											it1->second.port), udpInfo));

					while (true) {

						int a = it1->second.socket->Connect(
								InetSocketAddress(it1->first, m_swport));
						if (a == 0) {
							break;
						} else {
							std::cout << "trying to connect switches......"
									<< std::endl;
						}
					}

					it1->second.ctrl = this;
					it1->second.port = m_swport;

					SwitchInfo *swInfo = &it1->second;
					// Handshake messages
					ofl_msg_header hello;
					hello.type = OFPT_HELLO;
					SendToSwitch(swInfo, &hello);
					ofl_msg_header features;
					features.type = OFPT_FEATURES_REQUEST;
					SendToSwitch(swInfo, &features);
					SendBarrierRequest(*swInfo);
					// Executing any scheduled commands for this switch
					std::pair<DevCmdMap_t::iterator, DevCmdMap_t::iterator> ret;
					ret = m_schedCommands.equal_range(swInfo->swDev);
					for (DevCmdMap_t::iterator it1 = ret.first;
							it1 != ret.second; it1++) {
						DpctlCommand(*swInfo, it1->second);
					}
					m_schedCommands.erase(ret.first, ret.second);

					// Notify the connection started
					ConnectionStarted(*swInfo);
				}
			}
		} else {
			// receive hello msg on auxiliary connection before the main connection is setup
			NS_LOG_ERROR(
					"Receive hello msg on auxiliary connection before the main connection is setup");
			return 0;
		}
	}
	return 0;
}

ofl_err OFSwitch13Controller::HandlePacketIn(ofl_msg_packet_in *msg,
		SwitchInfo swtch, uint32_t xid) {
	NS_LOG_FUNCTION(swtch.ipv4 << xid);
	ofl_msg_free((ofl_msg_header*) msg, NULL /*exp*/);
	return 0;
}

ofl_err OFSwitch13Controller::HandleError(ofl_msg_error *msg, SwitchInfo swtch,
		uint32_t xid) {
	NS_LOG_FUNCTION(swtch.ipv4 << xid);
	char *str;
	str = ofl_msg_to_string((ofl_msg_header*) msg, NULL);
	NS_LOG_ERROR("OpenFlow error: " << str);
	free(str);

	if (msg->type == OFPET_BAD_REQUEST && msg->code == OFPBRC_BAD_VERSION
			&& swtch.socket->GetSocketType() == Socket::NS3_SOCK_DGRAM) {
		ofl_msg_header hello;
		hello.type = OFPT_HELLO;
		SendToSwitch(&swtch, &hello);
	}
	ofl_msg_free((ofl_msg_header*) msg, NULL /*exp*/);
	return 0;
}

ofl_err OFSwitch13Controller::HandleFeaturesReply(ofl_msg_features_reply *msg,
		SwitchInfo swtch, uint32_t xid) {
	NS_LOG_FUNCTION(swtch.ipv4 << xid);
	ofl_msg_free((ofl_msg_header*) msg, NULL /*exp*/);
	if (Simulator::Now()
			- m_udpConnStat[InetSocketAddress(swtch.ipv4, swtch.port)].LastFeatureReqTime
			<= m_noFeatureReplyTimeOut)
		m_udpConnStat[InetSocketAddress(swtch.ipv4, swtch.port)].RecFeaRes =
		true;
	return 0;
}

ofl_err OFSwitch13Controller::HandleGetConfigReply(
		ofl_msg_get_config_reply *msg, SwitchInfo swtch, uint32_t xid) {
	NS_LOG_FUNCTION(swtch.ipv4 << xid);
	ofl_msg_free((ofl_msg_header*) msg, NULL /*exp*/);
	return 0;
}

ofl_err OFSwitch13Controller::HandleFlowRemoved(ofl_msg_flow_removed *msg,
		SwitchInfo swtch, uint32_t xid) {
	NS_LOG_FUNCTION(swtch.ipv4 << xid);
	ofl_msg_free_flow_removed(msg, true, NULL);
	return 0;
}

ofl_err OFSwitch13Controller::HandlePortStatus(ofl_msg_port_status *msg,
		SwitchInfo swtch, uint32_t xid) {
	NS_LOG_FUNCTION(swtch.ipv4 << xid);
	ofl_msg_free((ofl_msg_header*) msg, NULL /*exp*/);
	return 0;
}

ofl_err OFSwitch13Controller::HandleAsyncReply(ofl_msg_async_config *msg,
		SwitchInfo swtch, uint32_t xid) {
	NS_LOG_FUNCTION(swtch.ipv4 << xid);
	ofl_msg_free((ofl_msg_header*) msg, NULL /*exp*/);
	return 0;
}

ofl_err OFSwitch13Controller::HandleMultipartReply(
		ofl_msg_multipart_reply_header *msg, SwitchInfo swtch, uint32_t xid) {
	NS_LOG_FUNCTION(swtch.ipv4 << xid);
	ofl_msg_free((ofl_msg_header*) msg, NULL /*exp*/);
	return 0;
}

ofl_err OFSwitch13Controller::HandleRoleReply(ofl_msg_role_request *msg,
		SwitchInfo swtch, uint32_t xid) {
	NS_LOG_FUNCTION(swtch.ipv4 << xid);
	ofl_msg_free((ofl_msg_header*) msg, NULL /*exp*/);
	return 0;
}

ofl_err OFSwitch13Controller::HandleQueueGetConfigReply(
		ofl_msg_queue_get_config_reply *msg, SwitchInfo swtch, uint32_t xid) {
	NS_LOG_FUNCTION(swtch.ipv4 << xid);
	ofl_msg_free((ofl_msg_header*) msg, NULL /*exp*/);
	return 0;
}
// --- END: Handlers functions -------

SwitchInfo OFSwitch13Controller::SelectRandomSW(SwitchInfo sw) {
	int count = 0;
	for (std::map<Ipv4Address, SwitchInfo>::iterator it = m_switchesMap.begin();
			it != m_switchesMap.end(); it++) {
		if (m_connectionMap[it->first].first
				== m_connectionMap[sw.ipv4].first) {
			count++;
		}
	}

	for (std::map<Ipv4Address, SwitchInfo>::iterator it = m_switchesMap.begin();
			it != m_switchesMap.end(); it++) {
		if (m_connectionMap[it->first].first
				== m_connectionMap[sw.ipv4].first) {
			if (rand() % 1000 <= 1000 / count) {
				return it->second;
			}
		}
	}
	return sw;
}

SwitchInfo OFSwitch13Controller::SelectRandomTCPSW(SwitchInfo sw) {
	int count = 0;
	for (std::map<Ipv4Address, SwitchInfo>::iterator it = m_switchesMap.begin();
			it != m_switchesMap.end(); it++) {
		if (m_connectionMap[it->first].first == m_connectionMap[sw.ipv4].first
				&& it->second.socket->GetSocketType()
						== Socket::NS3_SOCK_STREAM) {
			count++;
		}
	}

	for (std::map<Ipv4Address, SwitchInfo>::iterator it = m_switchesMap.begin();
			it != m_switchesMap.end(); it++) {
		if (m_connectionMap[it->first].first == m_connectionMap[sw.ipv4].first
				&& it->second.socket->GetSocketType()
						== Socket::NS3_SOCK_STREAM) {
			if (rand() % 1000 <= 1000 / count) {
				return it->second;
			}
		}
	}
	return sw;
}

/********** Private methods **********/
int OFSwitch13Controller::ReceiveFromSwitch(SwitchInfo swtch,
		ofl_msg_header *msg, uint32_t xid) {

	// Dispatches control messages to appropriate handler functions.
	switch (msg->type) {
	case OFPT_HELLO:
		return HandleHello(msg, swtch, xid);
	case OFPT_BARRIER_REPLY:
		ofl_msg_free(msg, NULL /*exp*/);
		return 0;

	case OFPT_PACKET_IN:
		return HandlePacketIn((ofl_msg_packet_in*) msg, swtch, xid);

	case OFPT_ECHO_REQUEST:
		return HandleEchoRequest((ofl_msg_echo*) msg, swtch, xid);

	case OFPT_ECHO_REPLY:
		return HandleEchoReply((ofl_msg_echo*) msg, swtch, xid);

	case OFPT_ERROR:
		return HandleError((ofl_msg_error*) msg, swtch, xid);

	case OFPT_FEATURES_REPLY:
		return HandleFeaturesReply((ofl_msg_features_reply*) msg, swtch, xid);

	case OFPT_GET_CONFIG_REPLY:
		return HandleGetConfigReply((ofl_msg_get_config_reply*) msg, swtch, xid);

	case OFPT_FLOW_REMOVED:
		return HandleFlowRemoved((ofl_msg_flow_removed*) msg, swtch, xid);

	case OFPT_PORT_STATUS:
		return HandlePortStatus((ofl_msg_port_status*) msg, swtch, xid);

	case OFPT_GET_ASYNC_REPLY:
		return HandleAsyncReply((ofl_msg_async_config*) msg, swtch, xid);

	case OFPT_MULTIPART_REPLY:
		return HandleMultipartReply((ofl_msg_multipart_reply_header*) msg,
				swtch, xid);

	case OFPT_ROLE_REPLY:
		return HandleRoleReply((ofl_msg_role_request*) msg, swtch, xid);

	case OFPT_QUEUE_GET_CONFIG_REPLY:
		return HandleQueueGetConfigReply((ofl_msg_queue_get_config_reply*) msg,
				swtch, xid);

	case OFPT_EXPERIMENTER:
	default:
		return ofl_error(OFPET_BAD_REQUEST, OFPGMFC_BAD_TYPE);
	}
}

void OFSwitch13Controller::UdpAuxConnNoRecTimeout(Address addr) {
	if (m_udpConnStat[addr].LastRecTime + m_noRecTimeOut > Simulator::Now()) {
		NS_LOG_INFO(
				"Receive msg after last receive before NoMsgAfterStartTimeout is timeout");
	} else {
		Ipv4Address ipv4 = InetSocketAddress::ConvertFrom(addr).GetIpv4();
		SwitchsMap_t::iterator it = m_switchesMap.find(ipv4);
		it->second.socket->Close();
	}
}

void OFSwitch13Controller::SocketUdpRead(Ptr<Socket> socket) {
	if (socket->GetSocketType() == Socket::NS3_SOCK_DGRAM) {
		//std::cout << "read a udp packet" << std::endl;
		NS_LOG_FUNCTION(this << socket);
		static Ptr<Packet> pendingPacket = 0;
		static uint32_t pendingBytes = 0;
		static Address from;
		do {
			if (!pendingBytes) {
				// Starting with a new OpenFlow message.
				// At least 8 bytes (OpenFlow header) must be available.
				uint32_t rxBytesAvailable = socket->GetRxAvailable();
				if (rxBytesAvailable < 8) {
					return; // Wait for more bytes.
				}

				// Receive the OpenFlow header
				pendingPacket = socket->RecvFrom(
						std::numeric_limits<uint32_t>::max(), 0, from);
				// Get the OpenFlow message size
				ofp_header header;
				pendingPacket->CopyData((uint8_t*) &header, sizeof(ofp_header));
				pendingBytes = ntohs(header.length) - pendingPacket->GetSize();
			}
			// Receive the remaining OpenFlow message
			if (pendingBytes) {
				if (socket->GetRxAvailable() < pendingBytes) {
					// We need to wait for more bytes
					return;
				}
				pendingPacket->AddAtEnd(socket->Recv(pendingBytes, 0));
			}

			if (InetSocketAddress::IsMatchingType(from)) {
				Ipv4Address ipv4 =
						InetSocketAddress::ConvertFrom(from).GetIpv4();
				NS_LOG_LOGIC(
						"At time " << Simulator::Now ().GetSeconds () << "s the OpenFlow Controller received " << pendingPacket->GetSize () << " bytes from switch " << ipv4 << " port " << InetSocketAddress::ConvertFrom (from).GetPort ());

				uint32_t xid;
				ofl_msg_header *msg;
				ofl_err error;

				SwitchsMap_t::iterator it = m_switchesMap.find(ipv4);
				NS_ASSERT_MSG(it != m_switchesMap.end(),
						"Unknown swtch " << from);

				// Get the openflow buffer, unpack the message and send to handler
				ofpbuf *buffer = ofs::BufferFromPacket(pendingPacket,
						pendingPacket->GetSize());
				error = ofl_msg_unpack((uint8_t*) buffer->data, buffer->size,
						&msg, &xid, NULL);
				if (!error) {
					char *msg_str = ofl_msg_to_string(msg, NULL);
					NS_LOG_DEBUG("RX from switch " << ipv4 << ": " << msg_str);
					free(msg_str);

					if (m_udpConnStat.find(from) == m_udpConnStat.end()) {
						std::cout << "receive unknown message" << std::endl;
						NS_LOG_ERROR("Receive unknown Msg ");
					} else {
						if (msg->type == OFPT_HELLO) {
							m_udpConnStat[from].RecHello = true;
						} else {
							if (!m_udpConnStat[from].RecHello) {
								NS_LOG_ERROR(
										"receive another msg before receiving a hello msg, send a error msg back to the switch.");
								ofl_msg_error err;
								err.header.type = OFPT_ERROR;
								err.type = OFPET_BAD_REQUEST;
								err.code = OFPBRC_BAD_VERSION;
								err.data_length = buffer->size;
								err.data = (uint8_t*) buffer->data;
								SendToSwitch(&(it->second),
										(ofl_msg_header*) &err);
								ofpbuf_delete(buffer);
								return;
							}
						}
						m_udpConnStat[from].LastRecTime = Simulator::Now();
						if (m_udpEventId[from].PeekEventImpl() == NULL) {
							m_udpEventId[from] =
									Simulator::Schedule(m_noRecTimeOut,
											&OFSwitch13Controller::UdpAuxConnNoRecTimeout,
											this, from);
							;
						} else {
							Simulator::Cancel(m_udpEventId[from]);
							m_udpEventId[from] =
									Simulator::Schedule(m_noRecTimeOut,
											&OFSwitch13Controller::UdpAuxConnNoRecTimeout,
											this, from);
							;
						}
					}

					error = ReceiveFromSwitch(it->second, msg, xid);
					if (error) {
						// NOTE: It is assumed that if a handler returns with error,
						// it did not use any part of the control message, thus it
						// can be freed up. If no error is returned however, the
						// message must be freed inside the handler (because the
						// handler might keep parts of the message)
						ofl_msg_free(msg, NULL);
					}
				}
				ofpbuf_delete(buffer);
			}
			pendingPacket = 0;
			pendingBytes = 0;

			// Repeat until socket buffer gets emtpy
		} while (socket->GetRxAvailable());
	}

}

void OFSwitch13Controller::SocketRead(Ptr<Socket> socket) {
	NS_LOG_FUNCTION(this << socket);
	static Ptr<Packet> pendingPacket = 0;
	static uint32_t pendingBytes = 0;
	static Address from;

	do {
		if (!pendingBytes) {
			// Starting with a new OpenFlow message.
			// At least 8 bytes (OpenFlow header) must be available.
			uint32_t rxBytesAvailable = socket->GetRxAvailable();
			if (rxBytesAvailable < 8) {
				return; // Wait for more bytes.
			}

			// Receive the OpenFlow header
			pendingPacket = socket->RecvFrom(sizeof(ofp_header), 0, from);

			// Get the OpenFlow message size
			ofp_header header;
			pendingPacket->CopyData((uint8_t*) &header, sizeof(ofp_header));
			pendingBytes = ntohs(header.length) - sizeof(ofp_header);
		}

		// Receive the remaining OpenFlow message
		if (pendingBytes) {
			if (socket->GetRxAvailable() < pendingBytes) {
				// We need to wait for more bytes
				return;
			}
			pendingPacket->AddAtEnd(socket->Recv(pendingBytes, 0));
		}

		if (InetSocketAddress::IsMatchingType(from)) {
			Ipv4Address ipv4 = InetSocketAddress::ConvertFrom(from).GetIpv4();
			NS_LOG_LOGIC(
					"At time " << Simulator::Now ().GetSeconds () << "s the OpenFlow Controller received " << pendingPacket->GetSize () << " bytes from switch " << ipv4 << " port " << InetSocketAddress::ConvertFrom (from).GetPort ());

			uint32_t xid;
			ofl_msg_header *msg;
			ofl_err error;

			SwitchsMap_t::iterator it = m_switchesMap.find(ipv4);
			if (it == m_switchesMap.end()) {
				return;
			}
			NS_ASSERT_MSG(it != m_switchesMap.end(), "Unknown swtch " << from);

			// Get the openflow buffer, unpack the message and send to handler
			ofpbuf *buffer = ofs::BufferFromPacket(pendingPacket,
					pendingPacket->GetSize());
			error = ofl_msg_unpack((uint8_t*) buffer->data, buffer->size, &msg,
					&xid, NULL);
			if (!error) {
				char *msg_str = ofl_msg_to_string(msg, NULL);
				NS_LOG_DEBUG("RX from switch " << ipv4 << ": " << msg_str);
				free(msg_str);

				error = ReceiveFromSwitch(it->second, msg, xid);
				if (error) {
					// NOTE: It is assumed that if a handler returns with error,
					// it did not use any part of the control message, thus it
					// can be freed up. If no error is returned however, the
					// message must be freed inside the handler (because the
					// handler might keep parts of the message)
					ofl_msg_free(msg, NULL);
				}
			}
			ofpbuf_delete(buffer);
		}
		pendingPacket = 0;
		pendingBytes = 0;

		// Repeat until socket buffer gets emtpy
	} while (socket->GetRxAvailable());
}

bool OFSwitch13Controller::SocketRequest(Ptr<Socket> socket,
		const Address& from) {
	NS_LOG_FUNCTION(this << socket << from);
	NS_LOG_LOGIC(
			"Switch request connection from " << InetSocketAddress::ConvertFrom (from).GetIpv4 ());
	// Find the switch in our database
	Ipv4Address ipv4 = InetSocketAddress::ConvertFrom(from).GetIpv4();
	if (m_connectionMap[ipv4].second == 0) {
		// this is the main connection
		NS_LOG_DEBUG("Controller: accepts main connection request!");
		return true;
	} else {
		// this is a tcp auxiliary connection
		SwitchsMap_t::iterator it = m_switchesMap.find(ipv4);
		NS_ASSERT_MSG(it != m_switchesMap.end(),
				"Unregistered switch " << ipv4);

		SwitchInfo *swInfo = &it->second;
		if (from != swInfo->swDev->GetMainSwAddress()
				&& !m_mainConnSetup[m_connectionMap[swInfo->ipv4].first]) {
			// reject a tcp auxiliary connection before the main connection is setup
			NS_LOG_ERROR(
					"reject a tcp auxiliary connection before the main connection is setup");
			return false;
		}
	}
	return true;
}

void OFSwitch13Controller::UdpAuxConnFeaReqTimeout(SwitchInfo* swtch,
		Address addr) {
	if (!m_udpConnStat[addr].RecFeaRes) {
		ofl_msg_header features;
		features.type = OFPT_FEATURES_REQUEST;
		SendToSwitch(swtch, &features);
		m_udpConnStat[addr].LastFeatureReqTime == Simulator::Now();
		m_udpConnStat[addr].RecFeaRes = false;
		Simulator::Schedule(m_noFeatureReplyTimeOut,
				&OFSwitch13Controller::UdpAuxConnFeaReqTimeout, this, swtch,
				addr);
	}
}

void OFSwitch13Controller::SocketAccept(Ptr<Socket> socket,
		const Address& from) {
	NS_LOG_FUNCTION(this << socket << from);

	// Find the switch in our database
	Ipv4Address ipv4 = InetSocketAddress::ConvertFrom(from).GetIpv4();
	SwitchsMap_t::iterator it = m_switchesMap.find(ipv4);
	NS_ASSERT_MSG(it != m_switchesMap.end(), "Unregistered switch " << ipv4);

	//debug
	NS_LOG_DEBUG(
			"Switch request connection accepted from " << ipv4 << ", port = " << InetSocketAddress::ConvertFrom (from).GetPort());

	SwitchInfo *swInfo = &it->second;
	socket->SetRecvCallback(
			MakeCallback(&OFSwitch13Controller::SocketRead, this));

	// Update other switch information
	swInfo->ctrl = this;
	swInfo->socket = socket;
	swInfo->port = InetSocketAddress::ConvertFrom(from).GetPort();

	NS_LOG_DEBUG(
			"Switch main connection address  " << InetSocketAddress::ConvertFrom (swInfo->swDev->GetMainSwAddress()).GetIpv4 () << ", port = " << InetSocketAddress::ConvertFrom (swInfo->swDev->GetMainSwAddress()).GetPort ());

	// Handshake messages
	ofl_msg_header hello;
	hello.type = OFPT_HELLO;
	SendToSwitch(swInfo, &hello);

	ofl_msg_header features;
	features.type = OFPT_FEATURES_REQUEST;
	SendToSwitch(swInfo, &features);
	m_udpConnStat[from].LastFeatureReqTime == Simulator::Now();
	m_udpConnStat[from].RecFeaRes = false;
	Simulator::Schedule(m_noFeatureReplyTimeOut,
			&OFSwitch13Controller::UdpAuxConnFeaReqTimeout, this, swInfo, from);

	SendBarrierRequest(*swInfo);

	// Executing any scheduled commands for this switch
	std::pair<DevCmdMap_t::iterator, DevCmdMap_t::iterator> ret;
	ret = m_schedCommands.equal_range(swInfo->swDev);
	for (DevCmdMap_t::iterator it = ret.first; it != ret.second; it++) {
		DpctlCommand(*swInfo, it->second);
	}
	m_schedCommands.erase(ret.first, ret.second);

	// Notify the connection started
	ConnectionStarted(*swInfo);
}

void OFSwitch13Controller::SocketPeerClose(Ptr<Socket> socket) {
	NS_LOG_FUNCTION(this << socket);
	for (std::map<Ipv4Address, SwitchInfo>::iterator it = m_switchesMap.begin();
			it != m_switchesMap.end(); ++it) {
		if (it->second.socket == socket) {
			if (it->second.swDev->GetMainSwAddress()
					== InetSocketAddress(it->second.ipv4, it->second.port)) {
				//this socket is on the main connection, close all the other sockets on the auxiliary connections
				for (std::map<Ipv4Address, SwitchInfo>::iterator it1 =
						m_switchesMap.begin(); it1 != m_switchesMap.end();
						++it1) {
					if (it1->second.swDev == it->second.swDev) {
						it1->second.socket->Close();
					}
				}
			}
			break;
		}
	}
}

void OFSwitch13Controller::SocketPeerError(Ptr<Socket> socket) {
	NS_LOG_WARN(this << socket);
	for (std::map<Ipv4Address, SwitchInfo>::iterator it = m_switchesMap.begin();
			it != m_switchesMap.end(); ++it) {
		if (it->second.socket == socket) {
			if (it->second.swDev->GetMainSwAddress()
					== InetSocketAddress(it->second.ipv4, it->second.port)) {
				//this socket is on the main connection, close all the other sockets on the auxiliary connections
				for (std::map<Ipv4Address, SwitchInfo>::iterator it1 =
						m_switchesMap.begin(); it1 != m_switchesMap.end();
						++it1) {
					if (it1->second.swDev == it->second.swDev) {
						it1->second.socket->Close();
					}
				}
			}
			break;
		}
	}
}

void OFSwitch13Controller::ScheduleCommand(SwitchInfo swtch,
		const std::string textCmd) {
	NS_ASSERT(swtch.swDev);
	std::pair<Ptr<OFSwitch13Device>, std::string> entry(swtch.swDev, textCmd);
	m_schedCommands.insert(entry);
}

} // namespace ns3
