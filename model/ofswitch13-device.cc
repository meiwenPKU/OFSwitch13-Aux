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

#define NS_LOG_APPEND_CONTEXT \
  if (m_dpId) { std::clog << "[dp " << m_dpId << "] "; }

#include "ns3/object-vector.h"
#include "ofswitch13-device.h"
#include "ofswitch13-interface.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Device");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Device);

// Initializing OFSwitch13Device static members
uint64_t OFSwitch13Device::m_globalDpId = 0;
uint64_t OFSwitch13Device::m_globalPktId = 0;
//uint64_t OFSwitch13Device::m_globalPacketIn = 0;

OFSwitch13Device::DpIdDevMap_t OFSwitch13Device::m_globalSwitchMap;

/********** Public methods **********/
TypeId
OFSwitch13Device::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13Device")
    .SetParent<Object> ()
    .SetGroupName ("OFSwitch13")
    .AddConstructor<OFSwitch13Device> ()
    .AddAttribute ("DatapathId",
                   "The unique identification of this OpenFlow switch.",
                   TypeId::ATTR_GET,
                   UintegerValue (0),
                   MakeUintegerAccessor (&OFSwitch13Device::m_dpId),
                   MakeUintegerChecker<uint64_t> ())
    .AddAttribute ("PortList",
                   "The list of ports associated to this switch.",
                   ObjectVectorValue (),
                   MakeObjectVectorAccessor (&OFSwitch13Device::m_ports),
                   MakeObjectVectorChecker<OFSwitch13Port> ())
    .AddAttribute ("TCAMDelay",
                   "Average time to perform a TCAM operation in pipeline "
                   "(Default: standard TCAM on a NetFPGA).",
                   TimeValue (NanoSeconds (30)),
                   MakeTimeAccessor (&OFSwitch13Device::m_tcamDelay),
                   MakeTimeChecker ())
    .AddAttribute ("DatapathTimeout",
                   "The interval between timeout operations on pipeline.",
                   TimeValue (MilliSeconds (100)),
                   MakeTimeAccessor (&OFSwitch13Device::m_timeout),
                   MakeTimeChecker ())
    .AddAttribute ("ControllerAddr",
                   "The controller main InetSocketAddress.",
                   AddressValue (
                     InetSocketAddress (Ipv4Address ("10.100.150.1"), 6653)),
                   MakeAddressAccessor (&OFSwitch13Device::m_ctrlAddr),
                   MakeAddressChecker ())
     .AddAttribute ("SwitchAddr",
		           "The switch main InetSocketAddress.",
		            AddressValue (
			          InetSocketAddress (Ipv4Address ("10.100.150.0"), 9999)),
		            MakeAddressAccessor (&OFSwitch13Device::m_swAddr),
		            MakeAddressChecker ())
    .AddAttribute ("LibLogLevel",
                   "Set the ofsoftswitch13 library logging level."
                   "Use 'none' to turn logging off. "
                   "Use 'all' to maximum verbosity. "
                   "You can also use a custom ofsoftswitch13 verbosity level.",
                   StringValue ("none"),
                   MakeStringAccessor (&OFSwitch13Device::SetLibLogLevel),
                   MakeStringChecker ())

    // Meter band packet drop trace source
    .AddTraceSource ("MeterDrop",
                     "Trace source indicating a packet dropped by meter band",
                     MakeTraceSourceAccessor (
                       &OFSwitch13Device::m_meterDropTrace),
                     "ns3::Packet::TracedCallback")
  ;
  return tid;
}

OFSwitch13Device::OFSwitch13Device ()
{
  NS_LOG_FUNCTION (this);
  NS_LOG_INFO ("OpenFlow version " << OFP_VERSION);

  m_dpId = ++m_globalDpId;
  m_ctrlSocket = 0;
  m_ctrlAddr = Address ();
  m_datapath = DatapathNew ();
  pendingPacketforContrRcv = 0;
  pendingBytesforContrRcv = 0;
  OFSwitch13Device::RegisterDatapath (m_dpId, Ptr<OFSwitch13Device> (this));
  Simulator::Schedule (m_timeout, &OFSwitch13Device::DatapathTimeout, this,
                       m_datapath);
}

OFSwitch13Device::~OFSwitch13Device ()
{
  NS_LOG_FUNCTION (this);
}

Ptr<OFSwitch13Port>
OFSwitch13Device::AddSwitchPort (Ptr<NetDevice> portDevice)
{
  NS_LOG_FUNCTION (this << portDevice);
  NS_LOG_INFO ("Adding port addr " << portDevice->GetAddress ());

  if (GetNSwitchPorts () >= DP_MAX_PORTS)
    {
      NS_LOG_ERROR ("No more ports allowed.");
      return 0;
    }

  Ptr<CsmaNetDevice> csmaPortDevice = portDevice->GetObject<CsmaNetDevice> ();
  if (!csmaPortDevice)
    {
      NS_FATAL_ERROR ("NetDevice must be of CsmaNetDevice type.");
    }

  // Create the OpenFlow port for this device
  Ptr<OFSwitch13Port> ofPort;
  ofPort = CreateObject<OFSwitch13Port> (m_datapath, csmaPortDevice, this);

  // Save port in port list (assert port no and vector index)
  m_ports.push_back (ofPort);
  NS_ASSERT (m_ports.size () == ofPort->GetPortNo ());

  return ofPort;
}

void
OFSwitch13Device::ReceiveFromSwitchPort (Ptr<Packet> packet, uint32_t portNo)
{
  NS_LOG_FUNCTION (this << packet);

  Simulator::Schedule (m_pipeDelay, &OFSwitch13Device::SendToPipeline, this,
                       packet, portNo);
}

uint32_t
OFSwitch13Device::GetNSwitchPorts (void) const
{
  return m_datapath->ports_num;
}

Address
OFSwitch13Device::GetMainSwAddress(void) const
{
	return m_swAddr;
}
uint64_t
OFSwitch13Device::GetDatapathId (void) const
{
  return m_dpId;
}

uint32_t
OFSwitch13Device::GetNumberFlowEntries (void) const
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT_MSG (m_datapath, "No datapath defined yet.");

  uint32_t entries = 0;
  for (size_t i = 0; i < PIPELINE_TABLES; i++)
    {
      entries += GetNumberFlowEntries (i);
    }
  return entries;
}

uint32_t
OFSwitch13Device::GetNumberFlowEntries (size_t tid) const
{
  NS_ASSERT_MSG (m_datapath, "No datapath defined yet.");

  uint32_t entries = 0;
  struct flow_table *table = m_datapath->pipeline->tables[tid];
  if (!(table->disabled))
    {
      entries = table->stats->active_count;
    }
  return entries;
}

void
OFSwitch13Device::SetLibLogLevel (std::string log)
{
  NS_LOG_FUNCTION (this << log);

  if (log != "none")
    {
      set_program_name ("ns3-ofswitch13");
      vlog_init ();
      if (log == "all")
        {
          vlog_set_verbosity (0);
        }
      else
        {
          vlog_set_verbosity (log.c_str ());
        }
    }
}

void
OFSwitch13Device::SetAuxConn(Address desti, uint8_t conn_id)
{
	NS_LOG_FUNCTION(this << desti);
	m_auxConn.insert(std::pair<Address,Ptr<Socket> >(desti,Ptr<Socket>()));
	m_aux_id_to_addr.insert(std::pair<uint8_t,Address>(conn_id,desti));
	//m_auxAdd.insert(std::pair<Address,Address>(desti,source));
}

void
OFSwitch13Device::StartControllerAuxConnection(std::vector<SocketType>& v_conn_type)
{
	//NS_LOG_FUNCTION (this << v_conn_type);
	if (v_conn_type.size() != m_auxConn.size())
	{
		NS_LOG_ERROR ("size of v_conn_type does not match m_v_aux");
	}
	int i = 0;
	for (std::map<Address,Ptr<Socket> >::iterator it = m_auxConn.begin(); it != m_auxConn.end(); ++it)
	{
		if (!it->second)
		{
			int error = 0;
			switch (v_conn_type[i]) {
			case TCP:
				it->second = Socket::CreateSocket (GetObject<Node> (),
												   TcpSocketFactory::GetTypeId ());
				break;
/*
			case UDP:
				it->second = Socket::CreateSocket(GetObject<Node>(),
						                           UdpSocketFactory::GetTypeId());
				break;
			case PACKET:
				it->second = Socket::CreateSocket(GetObject<Node>(),
										           PacketSocketFactory::GetTypeId());
				break;
			case IPV4RAW:
				it->second = Socket::CreateSocket(GetObject<Node>(),
										           Ipv4RawSocketFactory::GetTypeId());
				break;
*/
			default:
				NS_LOG_ERROR("unsupported socket type");
			}
			if (v_conn_type[i] == TCP){
			    it->second->SetAttribute ("SegmentSize", UintegerValue (8900)); //??
				error = it->second->Bind();
				if (error)
				{
				  NS_LOG_ERROR ("Error binding socket " << error);
				  return;
				}

				error = it->second->Connect (InetSocketAddress::ConvertFrom(it->first));
				if (error)
				{
				  NS_LOG_ERROR ("Error connecting socket " << error);
				  return;
				}

				it->second->SetConnectCallback (
				MakeCallback (&OFSwitch13Device::SocketAuxCtrlSucceeded, this),
				MakeCallback (&OFSwitch13Device::SocketCtrlFailed, this));
			}
		}
		else
		{
		    NS_LOG_ERROR ("Controller already set.");
		    return;
		}
		i++;
	}
}
void
OFSwitch13Device::StartControllerConnection ()
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT (!m_ctrlAddr.IsInvalid ());

  // Start a TCP connection to the controller
  if (!m_ctrlSocket)
    {
      int error = 0;
      m_ctrlSocket = Socket::CreateSocket (GetObject<Node> (),
                                           TcpSocketFactory::GetTypeId ());
      m_ctrlSocket->SetAttribute ("SegmentSize", UintegerValue (8900));

      error = m_ctrlSocket->Bind ();
      if (error)
        {
          NS_LOG_ERROR ("Error binding socket " << error);
          return;
        }

      error =
        m_ctrlSocket->Connect (InetSocketAddress::ConvertFrom (m_ctrlAddr));
      if (error)
        {
          NS_LOG_ERROR ("Error connecting socket " << error);
          return;
        }

      m_ctrlSocket->SetConnectCallback (
        MakeCallback (&OFSwitch13Device::SocketCtrlSucceeded, this),
        MakeCallback (&OFSwitch13Device::SocketCtrlFailed, this));

      return;
    }

  NS_LOG_ERROR ("Controller already set.");
}

Ptr<OFSwitch13Queue>
OFSwitch13Device::GetOutputQueue (uint32_t portNo)
{
  NS_LOG_FUNCTION (this << portNo);
  return GetOFSwitch13Port (portNo)->GetOutputQueue ();
}

// ofsoftswitch13 overriding and callback functions.
int
OFSwitch13Device::SendOpenflowBufferToRemote (ofpbuf *buffer, remote *ctrl)
{
  Ptr<OFSwitch13Device> dev = OFSwitch13Device::GetDevice (ctrl->dp->id);

  // FIXME No support for multiple controllers / auxiliary connections by now.
  // So, just ignoring remote information and sending to our single socket.
  Ptr<Packet> packet = ofs::PacketFromBuffer (buffer);
  return dev->SendToControllerWithAux (packet, buffer->conn_id);
}

void
OFSwitch13Device::DpActionsOutputPort (struct packet *pkt, uint32_t outPort,
                                       uint32_t outQueue, uint16_t maxLen,
                                       uint64_t cookie)
{
  Ptr<OFSwitch13Device> dev = OFSwitch13Device::GetDevice (pkt->dp->id);

  switch (outPort)
    {
    case (OFPP_TABLE):
      {
        if (pkt->packet_out)
          {
            // Makes sure packet cannot be resubmit to pipeline again setting
            // packet_out to false. Also, pipeline_process_packet takes
            // ownership of the packet, we need a copy.
            struct packet *pkt_copy = packet_clone (pkt);
            pkt_copy->packet_out = false;
            pipeline_process_packet (pkt_copy->dp->pipeline, pkt_copy);
          }
        break;
      }
    case (OFPP_IN_PORT):
      {
        dev->SendToSwitchPort (pkt, pkt->in_port, 0);
        break;
      }
    case (OFPP_CONTROLLER):
      {
        ofl_msg_packet_in msg;
        msg.header.type = OFPT_PACKET_IN;
        msg.total_len = pkt->buffer->size;
        msg.reason = pkt->handle_std->table_miss ? OFPR_NO_MATCH : OFPR_ACTION;
        msg.table_id = pkt->table_id;
        msg.data = (uint8_t*)pkt->buffer->data;
        msg.cookie = cookie;

        // Even with miss_send_len == OFPCML_NO_BUFFER, save the packet into
        // buffer to avoid loosing ns-3 packet id. This is not full compliant
        // with OpenFlow specification, but works very well here ;)
        dp_buffers_save (pkt->dp->buffers, pkt);
        msg.buffer_id = pkt->buffer_id;
        msg.data_length = MIN (maxLen, pkt->buffer->size);

        if (!pkt->handle_std->valid)
          {
            packet_handle_std_validate (pkt->handle_std);
          }
        msg.match = (ofl_match_header*) &pkt->handle_std->match;
        dp_send_message (pkt->dp, (ofl_msg_header *)&msg, 0);
        break;
      }
    case (OFPP_FLOOD):
    case (OFPP_ALL):
      {
        sw_port *p;
        LIST_FOR_EACH (p, struct sw_port, node, &pkt->dp->port_list)
        {
          if ((p->stats->port_no == pkt->in_port)
              || (outPort == OFPP_FLOOD && p->conf->config & OFPPC_NO_FWD))
            {
              continue;
            }
          dev->SendToSwitchPort (pkt, p->stats->port_no, 0);
        }
        break;
      }
    case (OFPP_NORMAL):
    case (OFPP_LOCAL):
    default:
      {
        if (pkt->in_port != outPort)
          {
            // Outputting packet on port outPort
            dev->SendToSwitchPort (pkt, outPort, outQueue);
          }
      }
    }
}

void
OFSwitch13Device::MeterCreatedCallback (struct meter_entry *entry)
{
  Ptr<OFSwitch13Device> dev = OFSwitch13Device::GetDevice (entry->dp->id);
  dev->NotifyMeterEntryCreated (entry);
}

void
OFSwitch13Device::MeterDropCallback (struct packet *pkt)
{
  Ptr<OFSwitch13Device> dev = OFSwitch13Device::GetDevice (pkt->dp->id);
  dev->NotifyPacketDropped (pkt);
}

void
OFSwitch13Device::PacketCloneCallback (struct packet *pkt,
                                       struct packet *clone)
{
  Ptr<OFSwitch13Device> dev = OFSwitch13Device::GetDevice (pkt->dp->id);
  dev->NotifyPacketCloned (pkt, clone);
}

void
OFSwitch13Device::PacketDestroyCallback (struct packet *pkt)
{
  Ptr<OFSwitch13Device> dev = OFSwitch13Device::GetDevice (pkt->dp->id);
  dev->NotifyPacketDestroyed (pkt);
}

void
OFSwitch13Device::BufferSaveCallback (struct packet *pkt, time_t timeout)
{
  Ptr<OFSwitch13Device> dev = OFSwitch13Device::GetDevice (pkt->dp->id);
  dev->BufferPacketSave (pkt->ns3_uid, timeout);
}

void
OFSwitch13Device::BufferRetrieveCallback (struct packet *pkt)
{
  Ptr<OFSwitch13Device> dev = OFSwitch13Device::GetDevice (pkt->dp->id);
  dev->BufferPacketRetrieve (pkt->ns3_uid);
}


/********** Private methods **********/
void
OFSwitch13Device::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  OFSwitch13Device::UnregisterDatapath (m_dpId);

  m_ctrlSocket = 0;
  PortList_t::iterator it;
  for (it = m_ports.begin (); it != m_ports.end (); it++)
    {
      Ptr<OFSwitch13Port> port = *it;
      port->Dispose ();
      *it = 0;
    }
  m_ports.clear ();

  pipeline_destroy (m_datapath->pipeline);
  group_table_destroy (m_datapath->groups);
  meter_table_destroy (m_datapath->meters);
  free (m_datapath);

  Object::DoDispose ();
}

datapath*
OFSwitch13Device::DatapathNew ()
{
  NS_LOG_FUNCTION (this);

  datapath* dp = (datapath*)xmalloc (sizeof (datapath));

  dp->mfr_desc = (char*)xmalloc (DESC_STR_LEN);
  dp->hw_desc = (char*)xmalloc (DESC_STR_LEN);
  dp->sw_desc = (char*)xmalloc (DESC_STR_LEN);
  dp->dp_desc = (char*)xmalloc (DESC_STR_LEN);
  dp->serial_num = (char*)xmalloc (DESC_STR_LEN);
  strncpy (dp->mfr_desc, "The ns-3 team", DESC_STR_LEN);
  strncpy (dp->hw_desc, "N/A", DESC_STR_LEN);
  strncpy (dp->sw_desc, "ns3 OpenFlow datapath version 1.3", DESC_STR_LEN);
  strncpy (dp->dp_desc, "ofsoftswitch13 (from CPqD)", DESC_STR_LEN);
  strncpy (dp->serial_num, "1.1", DESC_STR_LEN);

  dp->id = m_dpId;
  dp->last_timeout = time_now ();
  m_lastTimeout = Simulator::Now ();
  list_init (&dp->remotes);

  // unused
  dp->generation_id = -1;
  dp->listeners = 0;
  dp->n_listeners = 0;
  dp->listeners_aux = 0;
  dp->n_listeners_aux = 0;
  // unused

  memset (dp->ports, 0x00, sizeof (dp->ports));
  dp->local_port = 0;

  dp->buffers = dp_buffers_create (dp);
  dp->pipeline = pipeline_create (dp);
  dp->groups = group_table_create (dp);
  dp->meters = meter_table_create (dp);

  list_init (&dp->port_list);
  dp->ports_num = 0;
  dp->max_queues = OFSwitch13Queue::GetMaxQueues ();
  dp->exp = 0;

  dp->config.flags = OFPC_FRAG_NORMAL; // IP fragments with no special handling
  dp->config.miss_send_len = OFP_DEFAULT_MISS_SEND_LEN; // 128 bytes

  // ofsoftswitch13 callbacks
  dp->pkt_clone_cb = &OFSwitch13Device::PacketCloneCallback;
  dp->pkt_destroy_cb = &OFSwitch13Device::PacketDestroyCallback;
  dp->buff_save_cb = &OFSwitch13Device::BufferSaveCallback;
  dp->buff_retrieve_cb = &OFSwitch13Device::BufferRetrieveCallback;
  dp->meter_drop_cb = &OFSwitch13Device::MeterDropCallback;
  dp->meter_created_cb = &OFSwitch13Device::MeterCreatedCallback;

  return dp;
}

void
OFSwitch13Device::DatapathTimeout (datapath* dp)
{
  NS_LOG_FUNCTION (this);
  meter_table_add_tokens (dp->meters);
  pipeline_timeout (dp->pipeline);

  // Check for changes in links (port) status
  PortList_t::iterator it;
  for (it = m_ports.begin (); it != m_ports.end (); it++)
    {
      Ptr<OFSwitch13Port> port = *it;
      port->PortUpdateState ();
    }

  //
  // To provide a more realistic OpenFlow switch model, specially with respect
  // to flow table search time, we are considering that in real OpenFlow
  // implementations, packet classification can use sophisticated search
  // algorithms, as the HyperSplit (DOI 10.1109/FPT.2010.5681492). As most of
  // theses algorithms classifies the packet based on binary search trees, we
  // are estimating the pipeline average time to a K * log (n), where k is the
  // m_tcamDelay set to the time for a TCAM operation in a NetFPGA hardware,
  // and n is the current number of entries in flow tables.
  //
  m_pipeDelay = m_tcamDelay * (int64_t)ceil (log2 (GetNumberFlowEntries ()));

  dp->last_timeout = time_now ();
  m_lastTimeout = Simulator::Now ();
  Simulator::Schedule (m_timeout, &OFSwitch13Device::DatapathTimeout, this,
                       dp);
}

Ptr<OFSwitch13Port>
OFSwitch13Device::GetOFSwitch13Port (uint32_t no)
{
  NS_LOG_FUNCTION (this << no);

  // Assert port no (starts at 1)
  NS_ASSERT_MSG (no > 0 && no <= m_ports.size (), "Port is out of range.");
  return m_ports.at (no - 1);
}

bool
OFSwitch13Device::SendToSwitchPort (struct packet *pkt, uint32_t portNo,
                                    uint32_t queueNo)
{
  NS_LOG_FUNCTION (this << pkt->ns3_uid << portNo);

  Ptr<OFSwitch13Port> port = GetOFSwitch13Port (portNo);
  if (!port)
    {
      NS_LOG_ERROR ("can't forward to invalid port.");
      return false;
    }

  // When a packet is sent to OpenFlow pipeline, we keep track of its original
  // ns3::Packet using the PipelinePacket structure. When the packet is
  // processed by the pipeline with no internal changes, we forward the
  // original ns3::Packet to the specified output port.  When internal changes
  // are necessary, we need to create a new packet with the modified content
  // and copy all packet tags to this new one. This approach is more expensive
  // than the previous one, but is far more simple than identifying which
  // changes were performed in the packet to modify the original ns3::Packet.
  Ptr<Packet> packet;
  if (m_pktPipe.IsValid ())
    {
      NS_ASSERT_MSG (m_pktPipe.HasId (pkt->ns3_uid), "Invalid packet ID.");
      if (pkt->changes)
        {
          // The original ns-3 packet was modified by OpenFlow switch.
          // Create a new packet with modified data and copy tags from the
          // original packet.
          NS_LOG_DEBUG ("Packet modified by OpenFlow switch.");
          packet = ofs::PacketFromBuffer (pkt->buffer);
          OFSwitch13Device::CopyTags (m_pktPipe.GetPacket (), packet);
        }
      else
        {
          // Using the original ns-3 packet.
          packet = m_pktPipe.GetPacket ();
        }
    }
  else
    {
      // This is a new packet (probably created by the controller).
      NS_LOG_DEBUG ("Creating new ns-3 packet from openflow buffer.");
      packet = ofs::PacketFromBuffer (pkt->buffer);
    }

  // Send the packet to switch port.
  return port->Send (packet, queueNo);
}

void
OFSwitch13Device::SendToPipeline (Ptr<Packet> packet, uint32_t portNo)
{
  NS_LOG_FUNCTION (this << packet);
  NS_ASSERT_MSG (!m_pktPipe.IsValid (), "Another packet in pipeline.");

  // Creating the internal OpenFlow packet structure from ns-3 packet
  // Allocate buffer with some extra space for OpenFlow packet modifications.
  uint32_t headRoom = 128 + 2;
  uint32_t bodyRoom = packet->GetSize () + VLAN_ETH_HEADER_LEN;
  ofpbuf *buffer = ofs::BufferFromPacket (packet, bodyRoom, headRoom);
  struct packet *pkt = packet_create (m_datapath, portNo, buffer, 0, false);

  // Save the ns-3 packet
  pkt->ns3_uid = OFSwitch13Device::GetNewPacketId ();
  m_pktPipe.SetPacket (pkt->ns3_uid, packet);

  // Send packet to ofsoftswitch13 pipeline
  pipeline_process_packet (m_datapath->pipeline, pkt);
}

int
OFSwitch13Device::SendToControllerWithAux(Ptr<Packet> packet, uint8_t conn_id)
{
	if (m_auxConn.size() == 0)
	{
		return SendToController(packet);
	}
    //hemin yang, testing
    uint32_t xid;
    ofl_msg_header *msg;
    ofpbuf *buffer = ofs::BufferFromPacket (packet,packet->GetSize ());
    ofl_msg_unpack ((uint8_t*)buffer->data, buffer->size, &msg, &xid, NULL);

	if (conn_id == 0) // main connection
	{
		return SendToController(packet);
	}
	else // auxiliary connection
	{
	    if (msg->type == OFPT_PACKET_IN){
	    	conn_id = rand()%m_auxConn.size()+1;
	    	//if (conn_id == 0) return SendToController(packet);
	    }
/*
	    if (msg->type == OFPT_FLOW_REMOVED){
	    	conn_id = rand()%(m_auxConn.size()+1);
	    	//packet->PrintByteTags(std::cout);
	        //if (m_dpId == 1) m_globalPacketIn += packet->GetSize();
	    	if (conn_id == 0) return SendToController(packet);
	    }
*/

        if (!m_auxConn[m_aux_id_to_addr[conn_id]])
		{
		  NS_LOG_WARN ("No auxiliary connection. Discarding message... ");
		  return -1;
		}

	      // Check for available space in TCP buffer before sending the packet
	      if (m_auxConn[m_aux_id_to_addr[conn_id]]->GetTxAvailable () < packet->GetSize ())
		{
		  NS_LOG_ERROR ("Unavailable space to send OpenFlow message now.");
		  Simulator::Schedule (m_timeout, &OFSwitch13Device::SendToControllerWithAux,
				       this, packet,conn_id);
		  return -1;
		}


          char *msg_str = ofl_msg_to_string (msg, NULL);
	      NS_LOG_DEBUG(Simulator::Now().GetSeconds() << ", switch " << this->GetDatapathId()
			      << "send a " << msg_str << " packet to controller through connection " << int(conn_id));
              
	      uint32_t bytes = m_auxConn[m_aux_id_to_addr[conn_id]]->Send (packet);
	      if (bytes != packet->GetSize ())
		  {
		      NS_LOG_ERROR ("There was an error sending the message!");
		      std::cout << "error happened" << std::endl;
		  }
	      //if (m_dpId == 1) m_globalPacketIn += packet->GetSize();
		  if ((m_conn_to_TXthr[conn_id]).find(msg->type) != (m_conn_to_TXthr[conn_id]).end()) {
			  (m_conn_to_TXthr[conn_id])[msg->type] += bytes;
		  } else {
			   (m_conn_to_TXthr[conn_id])[msg->type] = bytes;
		  }
	      return (int)!bytes;
	}
	NS_LOG_ERROR ("Connection id is not supported.");
	return 0;
}

int
OFSwitch13Device::SendToController (Ptr<Packet> packet)
{
  if (!m_ctrlSocket)
    {
      NS_LOG_WARN ("No controller connection. Discarding message... ");
      return -1;
    }

  // Check for available space in TCP buffer before sending the packet
  if (m_ctrlSocket->GetTxAvailable () < packet->GetSize ())
    {
      NS_LOG_ERROR ("Unavailable space to send OpenFlow message now.");
      Simulator::Schedule (m_timeout, &OFSwitch13Device::SendToController,
                           this, packet);
      return -1;
    }

  //testing
  uint32_t test_xid;
  ofl_msg_header *test_msg;
  ofpbuf *test_buffer = ofs::BufferFromPacket (packet,packet->GetSize ());
  ofl_msg_unpack ((uint8_t*)test_buffer->data, test_buffer->size, &test_msg, &test_xid, NULL);
  char *msg_str = ofl_msg_to_string (test_msg, NULL);
  NS_LOG_DEBUG(Simulator::Now().GetSeconds() << ", switch " << this->GetDatapathId()
		  << " send a " << msg_str << " packet to controller through main connection");

  uint32_t bytes = m_ctrlSocket->Send (packet);
  if (bytes != packet->GetSize ())
    {
      NS_LOG_ERROR ("There was an error sending the message!"); // changed for debug
    }

  if ((m_conn_to_TXthr[0]).find(test_msg->type) != (m_conn_to_TXthr[0]).end()) {
      (m_conn_to_TXthr[0])[test_msg->type] += bytes;
  } else { 
       (m_conn_to_TXthr[0])[test_msg->type] = bytes;
  }

  return (int)!bytes;
}

void
OFSwitch13Device::ReceiveFromController (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);

  do
    {
      if (!pendingBytesforContrRcv)
        {
          // Starting with a new OpenFlow message.
          // At least 8 bytes (OpenFlow header) must be available.
          uint32_t rxBytesAvailable = socket->GetRxAvailable ();
          if (rxBytesAvailable < 8)
            {
              return; // Wait for more bytes.
            }

          // Receive the OpenFlow header and get the OpenFlow message size
          ofp_header header;
          pendingPacketforContrRcv = socket->RecvFrom (sizeof (ofp_header), 0, fromforContrRcv);
          pendingPacketforContrRcv->CopyData ((uint8_t*)&header, sizeof (ofp_header));
          pendingBytesforContrRcv = ntohs (header.length) - sizeof (ofp_header);
        }

      // Receive the remaining OpenFlow message
      if (pendingBytesforContrRcv)
        {
          if (socket->GetRxAvailable () < pendingBytesforContrRcv)
            {
              // We need to wait for more bytes
              return;
            }
          pendingPacketforContrRcv->AddAtEnd (socket->Recv (pendingBytesforContrRcv, 0));
        }

      if (InetSocketAddress::IsMatchingType (fromforContrRcv))
        {
          Ipv4Address ipv4 = InetSocketAddress::ConvertFrom (fromforContrRcv).GetIpv4 ();
          uint16_t port = InetSocketAddress::ConvertFrom (fromforContrRcv).GetPort ();

          NS_LOG_DEBUG ("At time " << Simulator::Now ().GetSeconds () <<
                        "s the OpenFlow switch " << GetDatapathId () <<
                        " received " << pendingPacketforContrRcv->GetSize () <<
                        " bytes from controller " << ipv4 <<
                        " socket " << socket <<
                        " port " << port);

          ofl_msg_header *msg;
          ofl_err error;

          struct sender ctrl;
          ctrl.remote = CONTAINER_OF (list_front (&m_datapath->remotes),
                                      remote, node);
          if (InetSocketAddress::ConvertFrom (fromforContrRcv) == m_ctrlAddr){
        	  ctrl.conn_id = 0;
          } else {
              for (std::map<uint8_t,Address>::iterator it = m_aux_id_to_addr.begin(); it != m_aux_id_to_addr.end(); ++it){
            	  if (it->second == InetSocketAddress(ipv4,port)){
            		  ctrl.conn_id = it->first;
            		  break;
            	  }
              }
          }

          // Get the OpenFlow buffer, unpack the message and send to handler
          ofpbuf *buffer = ofs::BufferFromPacket (pendingPacketforContrRcv,
                  		  pendingPacketforContrRcv->GetSize ());
          error = ofl_msg_unpack ((uint8_t*)buffer->data, buffer->size, &msg,
                                  &ctrl.xid, m_datapath->exp);


          if (!error)
            {
              char *msg_str = ofl_msg_to_string (msg, m_datapath->exp);
              NS_LOG_DEBUG ("Rx from ctrl: " << msg_str);
              free (msg_str);

              if ((m_conn_to_RXthr[ctrl.conn_id]).find(msg->type) != (m_conn_to_RXthr[ctrl.conn_id]).end()) {
                  (m_conn_to_RXthr[ctrl.conn_id])[msg->type] += buffer->size;
              } else { 
                   (m_conn_to_RXthr[ctrl.conn_id])[msg->type] = buffer->size;
              }
              error = handle_control_msg (m_datapath, msg, &ctrl);
              if (error)
                {
                  // NOTE: It is assumed that if a handler returns with error,
                  // it did not use any part of the control message, thus it
                  // can be freed up. If no error is returned however, the
                  // message must be freed inside the handler (because the
                  // handler might keep parts of the message)
                  ofl_msg_free (msg, m_datapath->exp);
                }
            }
          if (error)
            {
              NS_LOG_ERROR ("Error processing OpenFlow msg from controller.");
              // Notify the controller
              ofl_msg_error err;
              err.header.type = OFPT_ERROR;
              err.type = (ofp_error_type)ofl_error_type (error);
              err.code = ofl_error_code (error);
              err.data_length = buffer->size;
              err.data = (uint8_t*)buffer->data;
              dp_send_message (m_datapath, (ofl_msg_header*)&err, &ctrl);
            }
          ofpbuf_delete (buffer);
        }
      pendingPacketforContrRcv = 0;
      pendingBytesforContrRcv = 0;

      // Repeat until socket buffer gets empty
    }
  while (socket->GetRxAvailable ());
}

void
OFSwitch13Device::SocketCtrlSucceeded (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);

  NS_LOG_DEBUG ("Controller accepted main connection request!");
  socket->SetRecvCallback (
    MakeCallback (&OFSwitch13Device::ReceiveFromController, this));

  // Save connection information to remotes list in datapath
  remote_create (m_datapath, 0, 0);

  // Send Hello message
  ofl_msg_header msg;
  msg.type = OFPT_HELLO;
  dp_send_message (m_datapath, &msg, 0);
}

void OFSwitch13Device::SocketAuxCtrlSucceeded(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);

  NS_LOG_DEBUG ("Controller accepted auxiliary connection request!");
  socket->SetRecvCallback (
	MakeCallback (&OFSwitch13Device::ReceiveFromController, this));

}

void
OFSwitch13Device::SocketCtrlFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_ERROR ("Controller did not accepted connection request!");
}

void
OFSwitch13Device::NotifyMeterEntryCreated (struct meter_entry *entry)
{
  NS_LOG_FUNCTION (this << entry->config->meter_id);

  // Update meter entry last_fill field with the time of last datapath timeout,
  // and force a new bucket refill based on this elapsed time.
  for (size_t i = 0; i < entry->config->meter_bands_num; i++)
    {
      entry->stats->band_stats [i]->last_fill =
        static_cast<uint64_t> (m_lastTimeout.GetMilliSeconds ());
    }
  meter_table_add_tokens (m_datapath->meters);
}

void
OFSwitch13Device::NotifyPacketCloned (struct packet *pkt, struct packet *clone)
{
  NS_LOG_FUNCTION (this << pkt->ns3_uid);

  // Assigning a new unique ID for this cloned packet.
  clone->ns3_uid = OFSwitch13Device::GetNewPacketId ();
  m_pktPipe.NewCopy (clone->ns3_uid);
}

void
OFSwitch13Device::NotifyPacketDestroyed (struct packet *pkt)
{
  NS_LOG_FUNCTION (this << pkt->ns3_uid);

  if (m_pktPipe.IsValid () && m_pktPipe.HasId (pkt->ns3_uid))
    {
      // This is the packet current under pipeline
      bool valid = m_pktPipe.DelCopy (pkt->ns3_uid);
      if (!valid)
        {
          NS_LOG_DEBUG ("Packet " << pkt->ns3_uid <<
                        " done at switch " << GetDatapathId ());
        }
    }
  else
    {
      // This dropped packet is not the one current under pipeline. It must be
      // an old packet that was previously saved into buffer and will be
      // deleted now, freeing up space for a new packet at same buffer index
      // (that's how the ofsoftswitch13 handles the buffer). So, we are going
      // to remove this packet from our buffer list, if it still exists there.
      BufferPacketDelete (pkt->ns3_uid);
    }
}

void
OFSwitch13Device::NotifyPacketDropped (struct packet *pkt)
{
  NS_LOG_FUNCTION (this << pkt->ns3_uid);

  NS_ASSERT_MSG (m_pktPipe.HasId (pkt->ns3_uid), "Invalid packet ID.");
  NS_LOG_DEBUG ("OpenFlow meter band dropped packet " << pkt->ns3_uid);

  // Fire drop trace source
  m_meterDropTrace (m_pktPipe.GetPacket ());
}

void
OFSwitch13Device::BufferPacketSave (uint64_t packetId, time_t timeout)
{
  NS_LOG_FUNCTION (this << packetId);

  NS_ASSERT_MSG (m_pktPipe.HasId (packetId), "Invalid packet ID.");

  // Remove from pipeline and save into buffer map
  std::pair <uint64_t, Ptr<Packet> > entry (packetId, m_pktPipe.GetPacket ());
  std::pair <IdPacketMap_t::iterator, bool> ret;
  ret = m_pktsBuffer.insert (entry);
  if (ret.second == false)
    {
      NS_LOG_WARN ("Packet " << packetId << " already in switch "
                             << GetDatapathId () << " buffer.");
    }
  m_pktPipe.DelCopy (packetId);

  // Scheduling the buffer remove for expired packet. Since packet timeout
  // resolution is expressed in seconds, let's double it to avoid rounding
  // conflicts.
  //Simulator::Schedule (Time::FromInteger (2 * timeout, Time::S), &OFSwitch13Device::BufferPacketDelete, this, packetId);
}

void
OFSwitch13Device::BufferPacketRetrieve (uint64_t packetId)
{
  NS_LOG_FUNCTION (this << packetId);

  NS_ASSERT_MSG (!m_pktPipe.IsValid (), "Another packet in pipeline.");

  // Remove from buffer map and save back into pipeline
  IdPacketMap_t::iterator it = m_pktsBuffer.find (packetId);
  NS_ASSERT_MSG (it != m_pktsBuffer.end (), "Packet not found in buffer.");
  m_pktPipe.SetPacket (it->first, it->second);
  m_pktsBuffer.erase (it);
}

void
OFSwitch13Device::BufferPacketDelete (uint64_t packetId)
{
  NS_LOG_FUNCTION (this << packetId);

  // Delete from buffer map
  IdPacketMap_t::iterator it = m_pktsBuffer.find (packetId);
  if (it != m_pktsBuffer.end ())
    {
      m_pktsBuffer.erase (it);
    }
}

uint64_t
OFSwitch13Device::GetNewPacketId ()
{
  return ++m_globalPktId;
}

bool
OFSwitch13Device::CopyTags (Ptr<const Packet> srcPkt, Ptr<const Packet> dstPkt)
{
  // Copy packet tags
  PacketTagIterator pktIt = srcPkt->GetPacketTagIterator ();
  while (pktIt.HasNext ())
    {
      PacketTagIterator::Item item = pktIt.Next ();
      Callback<ObjectBase *> constructor = item.GetTypeId ().GetConstructor ();
      Tag *tag = dynamic_cast <Tag *> (constructor ());
      item.GetTag (*tag);
      dstPkt->AddPacketTag (*tag);
      delete tag;
    }

  // Copy byte tags
  ByteTagIterator bytIt = srcPkt->GetByteTagIterator ();
  while (bytIt.HasNext ())
    {
      ByteTagIterator::Item item = bytIt.Next ();
      Callback<ObjectBase *> constructor = item.GetTypeId ().GetConstructor ();
      Tag *tag = dynamic_cast<Tag *> (constructor ());
      item.GetTag (*tag);
      dstPkt->AddByteTag (*tag);
      delete tag;
    }

  return true;
}

void
OFSwitch13Device::RegisterDatapath (uint64_t id, Ptr<OFSwitch13Device> dev)
{
  std::pair<uint64_t, Ptr<OFSwitch13Device> > entry (id, dev);
  std::pair<DpIdDevMap_t::iterator, bool> ret;
  ret = OFSwitch13Device::m_globalSwitchMap.insert (entry);
  if (ret.second == false)
    {
      NS_FATAL_ERROR ("Error inserting datapath device into global map.");
    }
}

void
OFSwitch13Device::UnregisterDatapath (uint64_t id)
{
  DpIdDevMap_t::iterator it;
  it = OFSwitch13Device::m_globalSwitchMap.find (id);
  if (it != OFSwitch13Device::m_globalSwitchMap.end ())
    {
      OFSwitch13Device::m_globalSwitchMap.erase (it);
    }
  else
    {
      NS_FATAL_ERROR ("Error removing datapath device from global map.");
    }
}

Ptr<OFSwitch13Device>
OFSwitch13Device::GetDevice (uint64_t id)
{
  DpIdDevMap_t::iterator it;
  it = OFSwitch13Device::m_globalSwitchMap.find (id);
  if (it != OFSwitch13Device::m_globalSwitchMap.end ())
    {
      return it->second;
    }
  else
    {
      NS_FATAL_ERROR ("Error retrieving datapath device from global map.");
      return 0;
    }
}

OFSwitch13Device::PipelinePacket::PipelinePacket ()
  : m_valid (false),
    m_packet (0)
{
}

void
OFSwitch13Device::PipelinePacket::SetPacket (uint64_t id, Ptr<Packet> packet)
{
  NS_ASSERT_MSG (id && packet, "Invalid packet metadata values.");
  m_valid = true;
  m_packet = packet;
  m_ids.push_back (id);
}

Ptr<Packet>
OFSwitch13Device::PipelinePacket::GetPacket (void) const
{
  NS_ASSERT_MSG (IsValid (), "Invalid packet metadata.");
  return m_packet;
}

void
OFSwitch13Device::PipelinePacket::Invalidate (void)
{
  m_valid = false;
  m_packet = 0;
  m_ids.clear ();
}

bool
OFSwitch13Device::PipelinePacket::IsValid (void) const
{
  return m_valid;
}

void
OFSwitch13Device::PipelinePacket::NewCopy (uint64_t id)
{
  NS_ASSERT_MSG (m_valid, "Invalid packet metadata.");
  m_ids.push_back (id);
}

bool
OFSwitch13Device::PipelinePacket::DelCopy (uint64_t id)
{
  NS_ASSERT_MSG (m_valid, "Invalid packet metadata.");

  std::vector<uint64_t>::iterator it;
  for (it = m_ids.begin (); it != m_ids.end (); it++)
    {
      if (*it == id)
        {
          m_ids.erase (it);
          break;
        }
    }
  if (m_ids.size () == 0)
    {
      Invalidate ();
    }
  return m_valid;
}

bool
OFSwitch13Device::PipelinePacket::HasId (uint64_t id)
{
  NS_ASSERT_MSG (m_valid, "Invalid packet metadata.");

  std::vector<uint64_t>::iterator it;
  for (it = m_ids.begin (); it != m_ids.end (); it++)
    {
      if (*it == id)
        {
          return true;
        }
    }
  return false;
}

} // namespace ns3
