package net.floodlightcontroller.app;

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.easymock.EasyMock.createMock;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightTestModuleLoader;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.test.MockFloodlightProvider;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.test.FloodlightTestCase;

import org.junit.Before;
import org.junit.Test;
import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketIn.OFPacketInReason;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionType;
import org.openflow.util.HexString;


public class MyNewAppTests extends FloodlightTestCase{
       protected IPacket ARPPacket1;
       protected IPacket TCPPacket1;
       protected byte[] serializedARPPacket1;
       protected byte[] serializedTCPPacket1;
       protected OFPacketIn packetInARP1;
       protected OFPacketIn packetInTCP1;
       protected IPacket ARPPacket2;
       protected IPacket TCPPacket2;
       protected IPacket TCPPacket3;
       protected byte[] serializedARPPacket2;
       protected byte[] serializedTCPPacket2;
       protected byte[] serializedTCPPacket3;
       protected OFPacketIn packetInARP2;
       protected OFPacketIn packetInTCP2;
       protected OFPacketIn packetInTCP3;
       
       private   MockFloodlightProvider mockFloodlightProvider;
       private MyNewApp arpspoof;
       private boolean result;
       
       @Before
       public void setUp() throws Exception {
           super.setUp();

           mockFloodlightProvider = getMockFloodlightProvider();
           arpspoof = new MyNewApp();
           mockFloodlightProvider.addOFMessageListener(OFType.PACKET_IN,arpspoof);
           arpspoof.setFloodlightProvider(mockFloodlightProvider);
           
           // Build our test packet
           this.ARPPacket1 = new Ethernet()
               .setDestinationMACAddress("ff:ff:ff:ff:ff:ff")
               .setSourceMACAddress("00:44:33:22:11:00")
               .setEtherType(Ethernet.TYPE_ARP)
               .setPayload(
                   new ARP()
                   .setOpCode(ARP.OP_REQUEST)
                   .setHardwareType(ARP.HW_TYPE_ETHERNET)
                   .setHardwareAddressLength((byte)0x06)
                   .setSenderHardwareAddress(HexString.fromHexString("00:44:33:22:11:00"))
                   .setTargetHardwareAddress(HexString.fromHexString("ff:ff:ff:ff:ff:ff"))
                   .setProtocolType(ARP.PROTO_TYPE_IP)
                   .setProtocolAddressLength((byte)0x04)
                   .setSenderProtocolAddress(IPv4.toIPv4AddressBytes("192.168.0.8"))
                   .setTargetProtocolAddress(IPv4.toIPv4AddressBytes("192.168.1.8")));
           this.serializedARPPacket1 = ARPPacket1.serialize();

           this.TCPPacket1 = new Ethernet()
           .setDestinationMACAddress("00:00:00:00:00:01")
           .setSourceMACAddress("00:44:33:22:11:00")
           .setEtherType(Ethernet.TYPE_IPv4)
           .setPayload(
               new IPv4()
               .setSourceAddress("192.168.0.8")
               .setDestinationAddress("192.168.1.8")
               .setProtocol(IPv4.PROTOCOL_TCP)
               .setPayload(new TCP()
                           .setSourcePort((short) 5000)
                           .setDestinationPort((short) 5001)
                           .setSequence(0)
                           .setAcknowledge(100)
                           //.setFlags((short)0x0000)
                           .setFlags((short)0x0014)
                           .setPayload(new Data(new byte[] {0x01}))));
           this.serializedTCPPacket1 = TCPPacket1.serialize();
           
           // Build the PacketIn
           this.packetInARP1 = ((OFPacketIn) mockFloodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_IN))
               .setBufferId(-1)
               .setInPort((short) 1)
               .setPacketData(this.serializedARPPacket1)
               .setReason(OFPacketInReason.NO_MATCH)
               .setTotalLength((short) this.serializedARPPacket1.length);
           
           this.packetInTCP1 = ((OFPacketIn) mockFloodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_IN))
                   .setBufferId(-1)
                   .setInPort((short) 1)
                   .setPacketData(this.serializedTCPPacket1)
                   .setReason(OFPacketInReason.NO_MATCH)
                   .setTotalLength((short) this.serializedTCPPacket1.length);
    
           this.ARPPacket2 = new Ethernet()
           .setDestinationMACAddress("ff:ff:ff:ff:ff:ff")
           .setSourceMACAddress("00:55:33:22:11:00")
           .setEtherType(Ethernet.TYPE_ARP)
           .setPayload(
               new ARP()
               .setOpCode(ARP.OP_REQUEST)
               .setHardwareType(ARP.HW_TYPE_ETHERNET)
               .setHardwareAddressLength((byte)0x06)
               .setSenderHardwareAddress(HexString.fromHexString("00:55:33:22:11:00"))
               .setTargetHardwareAddress(HexString.fromHexString("ff:ff:ff:ff:ff:ff"))
               .setProtocolType(ARP.PROTO_TYPE_IP)
               .setProtocolAddressLength((byte)0x04)
               .setSenderProtocolAddress(IPv4.toIPv4AddressBytes("192.168.1.1"))
               .setTargetProtocolAddress(IPv4.toIPv4AddressBytes("192.168.1.2")));
       this.serializedARPPacket2 = ARPPacket2.serialize();

       this.TCPPacket2 = new Ethernet()
       .setDestinationMACAddress("00:00:00:00:00:01")
       .setSourceMACAddress("00:55:33:22:11:00")
       .setEtherType(Ethernet.TYPE_IPv4)
       .setPayload(
           new IPv4()
           .setSourceAddress("192.168.1.1")
           .setDestinationAddress("192.168.1.2")
           .setProtocol(IPv4.PROTOCOL_TCP)
           .setPayload(new TCP()
                       .setSourcePort((short) 5000)
                       .setDestinationPort((short) 5001)
                       .setSequence(0)
                       .setAcknowledge(100)                       
                       .setFlags((short)0x0014)
                       .setPayload(new Data(new byte[] {0x01}))));
       this.serializedTCPPacket2 = TCPPacket2.serialize();
       
       this.TCPPacket3 = new Ethernet()
       .setDestinationMACAddress("00:00:00:00:00:01")
       .setSourceMACAddress("00:66:33:22:11:00")
       .setEtherType(Ethernet.TYPE_IPv4)
       .setPayload(
           new IPv4()
           .setSourceAddress("192.168.1.1")
           .setDestinationAddress("192.168.1.2")
           .setProtocol(IPv4.PROTOCOL_TCP)
           .setPayload(new TCP()
                       .setSourcePort((short) 5000)
                       .setDestinationPort((short) 5001)
                       .setSequence(0)
                       .setAcknowledge(100)
                       //.setFlags((short)0x0000)
                       .setFlags((short)0x0014)
                       .setPayload(new Data(new byte[] {0x01}))));
       this.serializedTCPPacket3 = TCPPacket3.serialize();
       
       // Build the PacketIn
       this.packetInARP2 = ((OFPacketIn) mockFloodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_IN))
           .setBufferId(-1)
           .setInPort((short) 1)
           .setPacketData(this.serializedARPPacket2)
           .setReason(OFPacketInReason.NO_MATCH)
           .setTotalLength((short) this.serializedARPPacket2.length);
       
       this.packetInTCP2 = ((OFPacketIn) mockFloodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_IN))
               .setBufferId(-1)
               .setInPort((short) 1)
               .setPacketData(this.serializedTCPPacket2)
               .setReason(OFPacketInReason.NO_MATCH)
               .setTotalLength((short) this.serializedTCPPacket2.length);
       this.packetInTCP3 = ((OFPacketIn) mockFloodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_IN))
               .setBufferId(-1)
               .setInPort((short) 1)
               .setPacketData(this.serializedTCPPacket3)
               .setReason(OFPacketInReason.NO_MATCH)
               .setTotalLength((short) this.serializedTCPPacket3.length);
           
       }

       @Test
       public void testARPSpoof1() throws Exception {
           // build our expected flooded packetOut
           OFPacketOut pARP = ((OFPacketOut) mockFloodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT))
               .setActions(Arrays.asList(new OFAction[] {new OFActionOutput().setPort(OFPort.OFPP_FLOOD.getValue())}))
               .setActionsLength((short) OFActionOutput.MINIMUM_LENGTH)
               .setBufferId(-1)
               .setInPort((short) 1)
               .setPacketData(this.serializedARPPacket1);
           pARP.setLengthU(OFPacketOut.MINIMUM_LENGTH + pARP.getActionsLengthU()
                   + this.serializedARPPacket1.length);
           
           OFPacketOut pTCP = ((OFPacketOut) mockFloodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT))
                   .setActions(Arrays.asList(new OFAction[] {new OFActionOutput().setPort(OFPort.OFPP_FLOOD.getValue())}))
                   .setActionsLength((short) OFActionOutput.MINIMUM_LENGTH)
                   .setBufferId(-1)
                   .setInPort((short) 1)
                   .setPacketData(this.serializedTCPPacket1);
           pTCP.setLengthU(OFPacketOut.MINIMUM_LENGTH + pTCP.getActionsLengthU()
                       + this.serializedTCPPacket1.length);

           
           IOFSwitch mockSwitch = createMock(IOFSwitch.class);
           
           IOFMessageListener listener = mockFloodlightProvider.getListeners().get(OFType.PACKET_IN).get(0);
           listener.receive(mockSwitch, this.packetInARP1,
                            parseAndAnnotate(this.packetInARP1));
           

           listener = mockFloodlightProvider.getListeners().get(OFType.PACKET_IN).get(0);
           listener.receive(mockSwitch, this.packetInTCP1,
                            parseAndAnnotate(this.packetInTCP1));

           //Get the result          
           result = arpspoof.isspoofed();
           //if its true that means its a spoofed packet else false
           assertEquals(false, result);
                     
       }
       
       @Test
       public void testARPSpoof2() throws Exception {
           // build our expected flooded packetOut
           OFPacketOut pARP = ((OFPacketOut) mockFloodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT))
               .setActions(Arrays.asList(new OFAction[] {new OFActionOutput().setPort(OFPort.OFPP_FLOOD.getValue())}))
               .setActionsLength((short) OFActionOutput.MINIMUM_LENGTH)
               .setBufferId(-1)
               .setInPort((short) 1)
               .setPacketData(this.serializedARPPacket2);
           pARP.setLengthU(OFPacketOut.MINIMUM_LENGTH + pARP.getActionsLengthU()
                   + this.serializedARPPacket2.length);
           
           OFPacketOut pTCP = ((OFPacketOut) mockFloodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT))
                   .setActions(Arrays.asList(new OFAction[] {new OFActionOutput().setPort(OFPort.OFPP_FLOOD.getValue())}))
                   .setActionsLength((short) OFActionOutput.MINIMUM_LENGTH)
                   .setBufferId(-1)
                   .setInPort((short) 1)
                   .setPacketData(this.serializedTCPPacket2);
           pTCP.setLengthU(OFPacketOut.MINIMUM_LENGTH + pTCP.getActionsLengthU()
                       + this.serializedTCPPacket2.length);

           OFPacketOut pTCP2 = ((OFPacketOut) mockFloodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT))
                   .setActions(Arrays.asList(new OFAction[] {new OFActionOutput().setPort(OFPort.OFPP_FLOOD.getValue())}))
                   .setActionsLength((short) OFActionOutput.MINIMUM_LENGTH)
                   .setBufferId(-1)
                   .setInPort((short) 1)
                   .setPacketData(this.serializedTCPPacket3);
           pTCP2.setLengthU(OFPacketOut.MINIMUM_LENGTH + pTCP.getActionsLengthU()
                       + this.serializedTCPPacket3.length);

           
           IOFSwitch mockSwitch = createMock(IOFSwitch.class);
           
           IOFMessageListener listener = mockFloodlightProvider.getListeners().get(OFType.PACKET_IN).get(0);
           listener.receive(mockSwitch, this.packetInARP2,
                            parseAndAnnotate(this.packetInARP2));
           

           listener = mockFloodlightProvider.getListeners().get(OFType.PACKET_IN).get(0);
           listener.receive(mockSwitch, this.packetInTCP2,
                            parseAndAnnotate(this.packetInTCP2));
           
           listener = mockFloodlightProvider.getListeners().get(OFType.PACKET_IN).get(0);
           listener.receive(mockSwitch, this.packetInTCP3,
                            parseAndAnnotate(this.packetInTCP3));

           //Get the result          
           result = arpspoof.isspoofed();
           //if its true that means its a spoofed packet else false
           assertEquals(true, result);
                     
       }


}
