package net.floodlightcontroller.app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.Timer;
import java.util.TimerTask;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.HexString;
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
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.BasePacket;

public class MyNewApp implements IFloodlightModule, IOFMessageListener {
	private IFloodlightProviderService floodlightProvider;
    private BasePacket pkt;
    private static Logger log;
	private Map<String, Long> trustedIpToMacMap=new ConcurrentHashMap<String, Long>();
    private Map<String, Long> suspectedIpToMacMap=new ConcurrentHashMap<String, Long>();
    private Map<String, Long> startTimeMap=new ConcurrentHashMap<String, Long>();
    private List<String> seenIP=new ArrayList<String>();
    private List<Long> maliciousHosts;
    private boolean inconsistentHeader;
    private boolean spoofed;
	private String tcpPacketGenerator;
	private ARP arp;
	private Ethernet eth;
	private Long frameSourceMac;
	private Long frameDestMac;
	private Long aRPSourceMac;
	private Long aRPDestMac;
	private String frameSourceIP;
	private IPv4 ipPacket;
	private TCP tcpPacket;
	private final Long waitTime=new Long(1000);
	public Timer timer = new Timer();
	
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "MyNewApp";
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
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		return this.processPacketInMessage(sw, (OFPacketIn) msg, cntx);
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
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
	    floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	    trustedIpToMacMap = new ConcurrentHashMap<String, Long>();
	    suspectedIpToMacMap = new ConcurrentHashMap<String, Long>();
	    startTimeMap=new ConcurrentHashMap<String, Long>();
	    maliciousHosts = new ArrayList<Long>();
	    seenIP = new ArrayList<String>();
	    log = LoggerFactory.getLogger(MyNewApp.class);
	    timer = new Timer();

	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
	    floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	    timer.scheduleAtFixedRate(new TimerTask() {
	    	  @Override
	    	  public void run() {
	    	    if(!seenIP.isEmpty()){
	    	    	int i=0;
	    	    	while(seenIP.isEmpty()==false){
	    	    		String ip = seenIP.get(i++);
	    	    		if(startTimeMap.containsKey(ip)){
	    	    			if(startTimeMap.get(ip)-System.currentTimeMillis() > waitTime){
	    	    				spoofed=false;
	    		        		if(suspectedIpToMacMap.containsKey(frameSourceIP))
	    		        			suspectedIpToMacMap.remove(frameSourceIP);
	    		        		trustedIpToMacMap.put(frameSourceIP,frameSourceMac);
	    	    			}
	    	    		}
	    	    	}
	    	    }
	    	  }
	    	}, 1000, 1000);

	}

    public void setFloodlightProvider(IFloodlightProviderService floodlightProvider) {
        this.floodlightProvider = floodlightProvider;
    }
    
    public boolean isspoofed()
    {
        if (spoofed == true || inconsistentHeader == true)
            return true;
        else
            return false;
    }
    
    public void setPkt(BasePacket pkt) {
        this.pkt = pkt;
    }
    
    private Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
    	setPkt((BasePacket) IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD));
        OFMatch match = new OFMatch();
        match.loadFromPacket(pi.getPacketData(), pi.getInPort());
        eth = IFloodlightProviderService.bcStore.get(cntx,
                IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
    	frameSourceMac = Ethernet.toLong(eth.getSourceMACAddress());
        frameDestMac = Ethernet.toLong(eth.getDestinationMACAddress());
        frameSourceIP= IPv4.fromIPv4Address(match.getNetworkSource());
        //System.out.println(frameSourceIP);
       if (trustedIpToMacMap.containsKey(frameSourceIP)){
    		Long trustedsavedMac = trustedIpToMacMap.get(frameSourceIP); 
    		if(trustedsavedMac != frameSourceMac){
				spoofed = true;
				System.out.println(HexString.toHexString(frameSourceMac) + " is a malicious host");
				maliciousHosts.add(frameSourceMac);
				return Command.CONTINUE;
				//write found a new malicious host.... and list till now.
			}
			else
				return Command.CONTINUE;	
        }
    	//Host is not present in our trusted database. So we need to test its authenticity.
		//All hosts that are under verification will be stored in suspectedIpToMacMap.
        
        if (suspectedIpToMacMap.containsKey(frameSourceIP) == false){
			suspectedIpToMacMap.put(frameSourceIP, frameSourceMac);
			//Look for ARP packets
			if(eth.getEtherType() == Ethernet.TYPE_ARP){
				//System.out.println("Hi");
            	arp = (ARP)eth.getPayload();
            	//Get ARP header details
            	aRPSourceMac = Ethernet.toLong(arp.getSenderHardwareAddress());
            	aRPDestMac = Ethernet.toLong(arp.getTargetHardwareAddress());
            	//MAC - ARP Header Anomaly detection
            	if((arp.getOpCode()==ARP.OP_REQUEST) && !(frameSourceMac.equals(aRPSourceMac))){
            		inconsistentHeader=true;
            	}
            	else if((arp.getOpCode() == ARP.OP_REPLY) && (!(frameSourceMac.equals(aRPSourceMac)) || !(frameDestMac.equals(aRPDestMac)))){
            		inconsistentHeader=true;
            	}
            	else{//MAC and ARP Headers are consistent, move to further tests.
                    try {
                    	System.out.println("Sending TCP SYN packet to " + frameSourceIP);
                        tcpPacketGenerator = "hping3 -c 1 -S " + frameSourceIP;
                        Runtime r = Runtime.getRuntime();
                        Process p = r.exec(tcpPacketGenerator);
                        startTimeMap.put(frameSourceIP, System.currentTimeMillis());
                    }
                    catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    } 	
            	}  	
        	}
        }
		else{//Mac is present in suspected hosts map. this means that it is still under verification. 
			//So look for a TCP ACK Reply message
	        if(eth.getEtherType() == Ethernet.TYPE_IPv4){    
	        	ipPacket= (IPv4)eth.getPayload();
	        	if(ipPacket.getProtocol() == IPv4.PROTOCOL_TCP){
		        	tcpPacket = (TCP)ipPacket.getPayload();
		        	short flags = tcpPacket.getFlags();
		        	int isAck = (flags>>4) & 1;
		        	int isRpt = (flags>>2) & 1;
		        	if (isAck ==1 || isRpt == 1){//We have received TCP ACK or RST packet
		        		if(!seenIP.contains(frameSourceIP)){//if this is first tcp packet 
		        			seenIP.add(frameSourceIP);
	        				System.out.println("TCP ACK received "+HexString.toHexString(frameSourceMac) + " - " + frameSourceIP + " seems to be a legitimate host. Will wait for "+ waitTime + " milliseconds to see if we receive another packet");
		        		}
		        		else{
		        			if(System.currentTimeMillis()-startTimeMap.get(frameSourceIP) < waitTime){
		        				spoofed=true;
		        				System.out.println("Received second TCP packet from: " + HexString.toHexString(frameSourceMac) + " - " + frameSourceIP + " Some malicious host is spoofing packets. Cannot determine the correct MAC address between these two hosts");
		        			}
		        		}
		        	}
		        	else{
		        		spoofed = true;
		        		System.out.println(HexString.toHexString(frameSourceMac) + " is a malicious host");
		        	}
	        	} 
	        }	
		}
        return Command.CONTINUE;
    }
}
