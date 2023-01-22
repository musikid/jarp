extern crate jarp;

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

const INTERFACE: &str = "enp0s7";
const TEST_IP: &str = "192.168.1.4";

fn main() {
    let interface = jarp::get_interface(Some(INTERFACE)).unwrap();
    let mut channel = jarp::get_channel(&interface, None).unwrap();

    let local_ip = match interface.ips[0].ip() {
        IpAddr::V4(i) => i,
        _ => panic!(),
    };

    let test_mac = jarp::arp::query_mac_addr(
        &mut channel,
        &interface.mac_address(),
        &local_ip,
        &Ipv4Addr::from_str(TEST_IP).unwrap(),
    )
    .unwrap();

    println!("{}", test_mac);
}
