from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import in_proto
from ryu.lib.packet import icmp
from ryu.ofproto import inet


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
    
        self.logger.debug("firewall")	    
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPTableMod(datapath, 0, 3)
        datapath.send_msg(req)

        self.logger.debug("UDP")	    
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPTableMod(datapath, 1, 3)
        datapath.send_msg(req)

        self.logger.debug("HTTP")	    
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPTableMod(datapath, 2, 3)
        datapath.send_msg(req)

        self.logger.debug("Other")	    
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPTableMod(datapath, 3, 3)
        datapath.send_msg(req)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions,0,0,0,0)

    def add_flow(self, datapath, priority, match, actions, tableid,firecheck,gototab1,gototab2,buffer_id=None):

        self.logger.info("inside addflow")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info("table is %d",tableid)

        if firecheck==100:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS,[])]

            if buffer_id:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,table_id=0,
                                        priority=priority, match=match,
                                        instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,table_id=0,
                                        match=match, instructions=inst)
            datapath.send_msg(mod)
    
        elif gototab1==200:
            self.logger.info("inside 200")
            goto = parser.OFPInstructionGotoTable(1)
            self.logger.info("datapath is  %s",datapath)
            self.logger.info("table_id is  %s",tableid)
            if buffer_id:
                #mod = parser.OFPFlowMod([goto],datapath=datapath, buffer_id=buffer_id,table_id=0,
                  #                      priority=priority, match=match)
                 mod = parser.OFPFlowMod(ofproto.OFPP_ANY,ofproto.OFPG_ANY,ofproto.OFPFF_SEND_FLOW_REM,ofproto.OFPFC_ADD,[goto],match=match,datapath=datapath,table_id=tableid,priority=priority, buffer_id=buffer_id)
            
            else:
                #mod = parser.OFPFlowMod([goto],datapath=datapath, priority=priority,table_id=0,
                 #                       match=match)
                mod = parser.OFPFlowMod(ofproto.OFPP_ANY,ofproto.OFPG_ANY,ofproto.OFPFF_SEND_FLOW_REM,ofproto.OFPFC_ADD,[goto],match=match,datapath=datapath,table_id=tableid,priority=priority)
            datapath.send_msg(mod)  
               
        elif gototab2==300:
            goto = parser.OFPInstructionGotoTable(2)   
            if buffer_id:
                mod = parser.OFPFlowMod([goto],datapath=datapath, buffer_id=buffer_id,table_id=0,
                                        priority=priority, match=match)
            else:
                mod = parser.OFPFlowMod([goto],datapath=datapath, priority=priority,table_id=0,
                                        match=match)
            datapath.send_msg(mod) 
        else:
            self.logger.info("inside addflow else")
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            if buffer_id:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,table_id=tableid,
                                        priority=priority, match=match,
                                        instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,table_id=tableid,
                                        match=match, instructions=inst)
            datapath.send_msg(mod)











        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info("inside addflow")
        table_id=tableid
        datapath = datapath
        priority=priority
        match= match
        action=actions
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        
        if buffer_id:
            req = parser.OFPFlowMod(table_id, ofproto.OFPFC_ADD,ofproto.OFPP_ANY,ofproto.OFPG_ANY,ofproto.OFPFF_SEND_FLOW_REM,datapath,priority,buffer_id, match,inst)
            datapath.send_msg(req)	
        else:
            req = parser.OFPFlowMod(table_id, ofproto.OFPFC_ADD,ofproto.OFPP_ANY,ofproto.OFPG_ANY,ofproto.OFPFF_SEND_FLOW_REM,datapath,priority,match,inst)
            datapath.send_msg(req)	
        '''









    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        reader1=["94:de:80:42:a6:fb","94:de:80:42:a6:49",17]
        reader2=["94:de:80:42:a8:d5","94:de:80:42:a6:49",3333]
        reader3=['','',17]
        reader4=['','',80]
        self.logger.info("inside packet handler")
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        #self.logger.info("packet is %s",pkt)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        eth1 = pkt.get_protocol(ipv4.ipv4)
        http = pkt.get_protocol(tcp.tcp)
        self.logger.info("eth1 ipv4 is %s",eth1)
        self.logger.info("http is %s",http)
        #eth2 = pkt.get_protocol(udp.udp)
        #self.logger.info("eths ipv4 is %s",eth1.proto)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD



        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.logger.info("inside not flood")
            self.logger.info("dst is %s",dst)
            '''
            #firewall
            if reader1[0]==src and reader1[1]==dst and  protocol_num ==17:
                self.logger.info("inside ethi not none - firewall")
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst,ip_proto=17)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions,0,100,0,0,msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match,actions,0,100,0,0)           
            
            elif reader2[0]==src and reader2[1]==dst and reader2[2]==80 :
                self.logger.info("inside ethi not none - firewall")
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst,tcp_src=80)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions,0,100,0,0,msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match,actions,0,100,0,0)   

            elif reader3[2]== :
                self.logger.info("inside ethi not none - firewall")
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst,tcp_src=80)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions,0,0,200,0,msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match,actions,0,0,200,0)    

            elif reader3[2]==80 :
                self.logger.info("inside ethi not none - firewall")
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst,tcp_src=80)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions,0,0,0,300,msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match,actions,0,0,0,300)     
        '''



           # self.logger.info("above if udp, protocol number is %s",protocol_num)
            self.logger.info("eth1 is NOT NONE %s",eth1 is not None)
            self.logger.info("http is NONE %s",http is None)
            if eth1 is not None and http is None:  #  to check if firewall
                self.logger.info("inside eth1 not none and HTTP none")
                protocol_num = eth1.proto      
                if reader1[0]==src and reader1[1]==dst and  protocol_num ==17:          
                    self.logger.info("protocol number inside UDP firewall is %s",protocol_num )
                    self.logger.info("inside UDP firewall to call addflow function")
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst,ip_proto=17)
                    # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1250, match, actions,0,100,0,0, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1250, match,actions,0,100,0,0)
                self.logger.info("reader1 src is %s",reader1[0])
                self.logger.info("reader1 dst is %s",reader1[1])
                self.logger.info("src mac type is %s",src)
                self.logger.info("dst mac is %s",dst)
                self.logger.info("reader1[0] is not src : %s",(reader1[0] != src))
                self.logger.info("reader1[1] is not dst : %s",(reader1[1] != dst))
                self.logger.info("protocol_num ==17 %s",(protocol_num ==17))

                if (reader1[0] != src or reader1[1] != dst) and  protocol_num ==17:          
                    self.logger.info("protocol number inside UDP is %s",protocol_num )
                    self.logger.info("inside UDP to call addflow function")
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst,ip_proto=17)
                    # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions,1,0,0,0, msg.buffer_id)
                        #self.add_flow(datapath, 1, match,actions,0,0,200,0,msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match,actions,1,0,0,0)
                        #self.add_flow(datapath, 1, match,actions,0,0,200,0)
                    
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data

                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)

                elif protocol_num != 17:  #  to check if packet is other
                   # self.logger.info("inside if other, protocol number is %s",protocol_num)
                    self.logger.info("inside other except UDP to call addflow function ")
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                    # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions,3,0,0,0, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match,actions,3,0,0,0)
                    
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data

                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)  




                    '''

                        actions = [parser.OFPActionOutput(out_port)]
                        match = parser.OFPMatch(in_port=in_port, eth_dst=dst,ip_proto=17)
                        # verify if we have a valid buffer_id, if yes avoid to send both
                        # flow_mod & packet_out
                        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                            self.add_flow(datapath, 1, match, actions,1,0,0,0, msg.buffer_id)
                            return
                        else:
                            self.add_flow(datapath, 1, match,actions,1,0,0,0)
                        
                        data = None
                        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                            data = msg.data

                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions, data=data)
                        datapath.send_msg(out)  
                  '''

            if http is not None :  #  to check if http
                self.logger.info("inside http not none")
                sourceport = http.dst_port      
                self.logger.info("reader2[0] == src : %s",(reader2[0] == src))
                self.logger.info("reader2[1] == dst : %s",(reader2[1] == dst))
                self.logger.info("sourceport ==3333 : %s",(sourceport ==3333))
                self.logger.info("sourceport : %s",(sourceport))
                

                if reader2[0]==src and reader2[1]==dst and  sourceport ==3333:
                    self.logger.info("source port inside HTTP firewall is %s",sourceport)
                    self.logger.info("inside http-firewall to call addflow function")
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst,tcp_src=3333)
                    # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1250, match, actions,0,100,0,0, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1250, match,actions,0,100,0,0)
                
                self.logger.info("reader2[0] != src : %s",(reader2[0] != src))
                self.logger.info("reader2[1] != dst : %s",(reader2[1] != dst))
                self.logger.info("sourceport ==3333 : %s",(sourceport ==3333))
                if (reader2[0] != src or reader2[1] != dst) and  sourceport ==3333:
                    self.logger.info("source port inside HTTP is %s",sourceport)
                    self.logger.info("inside http to call addflow function")
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst,tcp_src=3333)
                    # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions,2,0,0,0, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match,actions,2,0,0,0)
                    
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data

                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)

                elif sourceport != 3333:  #  to check if packet is other
                   # self.logger.info("inside if other, protocol number is %s",protocol_num)
                    self.logger.info("inside other except http port to call addflow function ")
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                    # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions,3,0,0,0, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match,actions,3,0,0,0)
                    
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data

                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)  
            
            
            else:  #  to check if packet is other
               # self.logger.info("inside if other, protocol number is %s",protocol_num)
                self.logger.info("inside othersssssssssss to call addflow function")
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions,3,0,0,0, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match,actions,3,0,0,0)
                
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)               

            '''
            

            if eth1 is not None: #  to check if packet is HTTP
                self.logger.info("inside ethi not none")
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst,ip_proto=17)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions,2,0,0,0,msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match,actions,2,0,0,0)

                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)  
            '''
        if out_port == ofproto.OFPP_FLOOD: 
            actions = [parser.OFPActionOutput(out_port)]  
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)



#100 for firewall
#200 for goto table 1
#300 for goto table 2
