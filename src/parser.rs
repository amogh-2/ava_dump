use etherparse::{SlicedPacket, InternetSlice, TransportSlice};
use crate::store::FlowKey;
use crate::features::PacketInfo;
use std::net::IpAddr;

pub fn parse_packet(packet_data: &[u8], timestamp: f64) -> Option<(FlowKey, PacketInfo)> {
    let sliced = SlicedPacket::from_ethernet(packet_data).ok()?;
    
    let (src_ip, dst_ip, protocol) = match sliced.net? {
        InternetSlice::Ipv4(ipv4) => (
            IpAddr::V4(ipv4.header().source_addr()),
            IpAddr::V4(ipv4.header().destination_addr()),
            ipv4.header().protocol(),
        ),
        InternetSlice::Ipv6(ipv6) => (
            IpAddr::V6(ipv6.header().source_addr()),
            IpAddr::V6(ipv6.header().destination_addr()),
            ipv6.header().next_header(),
        ),
    };
    
    let (src_port, dst_port, syn, ack, fin, rst) = match sliced.transport? {
        TransportSlice::Tcp(tcp) => (
            tcp.source_port(),
            tcp.destination_port(),
            tcp.syn(),
            tcp.ack(),
            tcp.fin(),
            tcp.rst(),
        ),
        TransportSlice::Udp(udp) => (
            udp.source_port(),
            udp.destination_port(),
            false,
            false,
            false,
            false,
        ),
        _ => return None,
    };
    
    let key = FlowKey {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol: protocol.into(),
    };
    
    let info = PacketInfo {
        timestamp,
        length: packet_data.len() as u64,
        is_fwd: true, // Will be set by FlowEngine correctly
        syn,
        ack,
        fin,
        rst,
    };
    
    Some((key, info))
}
