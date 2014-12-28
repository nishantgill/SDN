package net.floodlightcontroller.simplefirewall;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.Wildcards;
import org.openflow.protocol.Wildcards.Flag;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.LRULinkedHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.IPv4;

public class MySimpleFirewall implements IFloodlightModule, IOFMessageListener {

	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;
    protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 100; // in seconds
    protected static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
    protected static short FLOWMOD_PRIORITY = 100;
    protected Map<IOFSwitch, Map<String,Short>> ipToSwitchPortMap; // Map to store IP to switch port mappings
    protected static final int MAX_MACS_PER_SWITCH  = 1000;
    public static final long COOKIE = (long) (1 & ((1 << 12) - 1)) << 52;
	
	@Override
	public String getName() {
	    return MySimpleFirewall.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
	    Collection<Class<? extends IFloodlightService>> l =
	            new ArrayList<Class<? extends IFloodlightService>>();
	        l.add(IFloodlightProviderService.class);
	        return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
	    floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        ipToSwitchPortMap = new ConcurrentHashMap<IOFSwitch, Map<String,Short>>();
	    logger = LoggerFactory.getLogger(MySimpleFirewall.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
	    floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

	}
	   
       public Short getFromPortMap(IOFSwitch sw, String ip) {
	        Map<String,Short> swMap = ipToSwitchPortMap.get(sw);
	        if (swMap != null)
	            return swMap.get(ip);
	        // if none found
	        return null;

       }
	 
       protected void addToPortMap(IOFSwitch sw, String ip, short portVal) {
    	   Map<String,Short> swMap = ipToSwitchPortMap.get(sw);

	        if (swMap == null) {
	            swMap = Collections.synchronizedMap(new LRULinkedHashMap<String,Short>(MAX_MACS_PER_SWITCH));
	            ipToSwitchPortMap.put(sw, swMap);
	        }
	        swMap.put(ip, portVal);   
       }
       
	   private void pushPacket(IOFSwitch sw, OFMatch match, OFPacketIn pi, short outport) {
	        if (pi == null || pi.getInPort() == outport) {
	            return;
	        }
	        OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
	                                                .getMessage(OFType.PACKET_OUT);
	        // set actions
	        List<OFAction> actions = new ArrayList<OFAction>();
	        actions.add(new OFActionOutput(outport, (short) 0xffff));

	        po.setActions(actions)
	          .setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);
	        short poLength =
	                (short) (po.getActionsLength() + OFPacketOut.MINIMUM_LENGTH);
	        po.setInPort(pi.getInPort());

	        // If the buffer id is none or the switch doesn's support buffering
	        // we send the data with the packet out
	        if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
	            byte[] packetData = pi.getPacketData();
	            poLength += packetData.length;
	            po.setPacketData(packetData);
	        }

	        po.setLength(poLength);

	        try {
	            sw.write(po, null);
	        } catch (IOException e) {
	            logger.error("Failure writing packet out", e);
	        }

	   }
	   
	   private void writeFlowMod(IOFSwitch sw, short command, int bufferId,
	            OFMatch match, short outPort) {

	        OFFlowMod flowMod = (OFFlowMod) floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);	        
	        List<OFAction> actions = new ArrayList<OFAction>();	        
	        flowMod.setMatch(match);
	        flowMod.setCookie(COOKIE);
	        flowMod.setCommand(command);
	        flowMod.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT);
	        flowMod.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT);
	        flowMod.setPriority(FLOWMOD_PRIORITY);
	        flowMod.setBufferId(bufferId);

	        flowMod.setFlags((command == OFFlowMod.OFPFC_DELETE) ? 0 : (short) (1 << 0)); // OFPFF_SEND_FLOW_REM
	        if(!(outPort == (short)-1)){
		        flowMod.setOutPort((command == OFFlowMod.OFPFC_DELETE) ? outPort : OFPort.OFPP_NONE.getValue());
	        	flowMod.setActions(Arrays.asList((OFAction) new OFActionOutput(outPort, (short) 0xffff)));
		        flowMod.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
	        }
	        else
	        	flowMod.setLength((short) (OFFlowMod.MINIMUM_LENGTH));



        if (logger.isTraceEnabled()) {
	            logger.trace("{} {} flow mod {}",
	                      new Object[]{ sw, (command == OFFlowMod.OFPFC_DELETE) ? "deleting" : "adding", flowMod });
	        }

	        // and write it out
	        try {
	            sw.write(flowMod, null);
	        } catch (IOException e) {
	            logger.error("Failed to write {} to switch {}", new Object[]{ flowMod, sw }, e);
	        }
	    }

	   
	    private void writePacketOutForPacketIn(IOFSwitch sw,
                OFPacketIn packetInMessage,
                short egressPort) {
	        OFPacketOut packetOutMessage = (OFPacketOut) floodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT);
	        short packetOutLength = (short)OFPacketOut.MINIMUM_LENGTH; // starting length

	        // Set buffer_id, in_port, actions_len
	        packetOutMessage.setBufferId(packetInMessage.getBufferId());
	        packetOutMessage.setInPort(packetInMessage.getInPort());
	        packetOutMessage.setActionsLength((short)OFActionOutput.MINIMUM_LENGTH);
	        packetOutLength += OFActionOutput.MINIMUM_LENGTH;

	        // set actions
	        List<OFAction> actions = new ArrayList<OFAction>(1);
	        actions.add(new OFActionOutput(egressPort, (short) 0));
	        packetOutMessage.setActions(actions);

	        // set data - only if buffer_id == -1
	        if (packetInMessage.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
	            byte[] packetData = packetInMessage.getPacketData();
	            packetOutMessage.setPacketData(packetData);
	            packetOutLength += (short)packetData.length;
	        }

	        // finally, set the total length
	        packetOutMessage.setLength(packetOutLength);

	        // and write it out
	        try {
	        //    counterStore.updatePktOutFMCounterStoreLocal(sw, packetOutMessage);
	            sw.write(packetOutMessage, null);
	        } catch (IOException e) {
	            logger.error("Failed to write {} to switch {}: {}", new Object[]{ packetOutMessage, sw, e });
	        }

	    }
	   
		public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
	        OFPacketIn pi = (OFPacketIn)msg;   
	        OFMatch match = new OFMatch();
	        match.loadFromPacket(pi.getPacketData(), pi.getInPort());
	    //    Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
	      //  Long destMac = Ethernet.toLong(match.getDataLayerDestination());
	        String sourceIP = IPv4.fromIPv4Address(match.getNetworkSource());
	        String destIP = IPv4.fromIPv4Address(match.getNetworkDestination());
        	String H2_ip = "10.0.0.2";
        	String H3_ip = "10.0.0.3";
        	if ((sourceIP.equals(H2_ip) && destIP.equals(H3_ip)) || (sourceIP.equals(H3_ip) && destIP.equals(H2_ip))){
        		this.writeFlowMod(sw, OFFlowMod.OFPFC_ADD, OFPacketOut.BUFFER_ID_NONE, match, (short)-1);
        		return Command.CONTINUE;
        	}
	        this.addToPortMap(sw, sourceIP, pi.getInPort());

	        // Now output flow-mod and/or packet
	        //Short outPort = getFromPortMap(sw, destMac, vlan);
	        Short outPort = getFromPortMap(sw, destIP);
	        if (outPort == null) {
	            // If we haven't learned the output port for this source/destination IP address pair, then flood the packet.
	            this.writePacketOutForPacketIn(sw, pi, OFPort.OFPP_FLOOD.getValue());
	        } else if (outPort == match.getInputPort()) {
	        	//ignoring packet that arrived on same port as learned destination.
	        } else {
	        		//set the Wildcards for Flow Mode rule. Note that we are setting the rules based on the input port and source and destination IP address.
	        		//Reference for Wildcards tutorial- http://docs.projectfloodlight.org/display/floodlightcontroller/Wildcards+Mini-Tutorial
	        		//This will create rules by matching all bits of the IP addresses.
	        		match.setWildcards(Wildcards.FULL.matchOn(Flag.IN_PORT).matchOn(Flag.DL_TYPE).withNwSrcMask(32).withNwDstMask(32));
	                this.pushPacket(sw, match, pi, outPort);
		            this.writeFlowMod(sw, OFFlowMod.OFPFC_ADD, OFPacketOut.BUFFER_ID_NONE, match, outPort);
	        }
	        return Command.CONTINUE;
			
		    }

	}
