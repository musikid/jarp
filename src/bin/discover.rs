extern crate jarp;

use std::net::IpAddr;

fn main() {
    let interface = jarp::get_interface(None).unwrap();

    let local_ip = match interface.ips[0].ip() {
        IpAddr::V4(i) => i,
        _ => panic!(),
    };
    let channel = jarp::get_channel(&interface, None).unwrap();

    let pool = jarp::get_pool().unwrap();

    println!("IP address        MAC address");
    for peer in jarp::arp::discover_peers(
        pool,
        &channel,
        &interface.mac_address(),
        &local_ip,
        Some(std::time::Duration::from_millis(500)),
        &interface.name,
    )
    .unwrap()
    {
        println!("{}    {}", peer.ip, peer.mac);
    }
}
