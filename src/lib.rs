extern crate ipnetwork;
extern crate num_cpus;
extern crate pnet;
extern crate rayon;

pub mod arp;
mod error;

use self::error::{ChannelError, NetResult};
use pnet::datalink;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct NetChannel {
    pub sender: Arc<Mutex<Box<dyn datalink::DataLinkSender>>>,
    pub receiver: Arc<Mutex<Box<dyn datalink::DataLinkReceiver>>>,
}

pub fn get_interface(interface: Option<&str>) -> NetResult<datalink::NetworkInterface> {
    let interface = if let Some(interface) = interface {
        datalink::interfaces()
            .into_iter()
            .filter(|iface| iface.name == interface)
            .next()
    } else {
        datalink::interfaces()
            .into_iter()
            .filter(|iface| iface.is_up() && !iface.is_loopback())
            .next()
    };

    match interface {
        Some(i) => Ok(i),
        None => Err(ChannelError::NoInterface),
    }
}

pub fn get_channel(
    interface: &datalink::NetworkInterface,
    read_timeout: Option<Duration>,
) -> NetResult<NetChannel> {
    match datalink::channel(
        interface,
        datalink::Config {
            read_timeout,
            ..Default::default()
        },
    ) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => Ok(NetChannel {
            sender: Arc::new(Mutex::new(tx)),
            receiver: Arc::new(Mutex::new(rx)),
        }),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Error when creating datalink channel: {}", e),
    }
}

pub fn get_pool() -> NetResult<rayon::ThreadPool> {
    Ok(rayon::ThreadPoolBuilder::new()
        .num_threads(num_cpus::get())
        .build()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::datalink::interfaces;
    #[test]
    fn interface() {
        let host_interfaces = interfaces();
        let interface = get_interface(Some(&host_interfaces[0].name));
        //TODO: Real test
        assert!(interface.is_ok());
    }

    // #[test] XXX: Need to be root to test this
    // fn channel() {
    //     let interface = dummy::dummy_interface(0);
    //     let channel = get_channel(&interface, None);

    //     assert!(channel.is_ok());
    // }
}
