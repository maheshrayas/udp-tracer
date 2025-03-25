use crate::network::network_probe::TraceUdpSkelBuilder;
use crate::{error::Error, network::NetworkEventData};
use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, PerfBufferBuilder};
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::{task, task::JoinHandle};
use tracing::info;

pub fn ebpf_handle(
    network_event_sender: Sender<NetworkEventData>,
    mut rx: Receiver<u64>,
    mut ignore_ips: Receiver<String>,
    ignore_daemonset_traffic: bool,
) -> JoinHandle<Result<(), Error>> {
    task::spawn_blocking(move || {
        let mut open_object = MaybeUninit::uninit();
        let skel_builder = TraceUdpSkelBuilder::default();
        let network_probe_skel = skel_builder.open(&mut open_object).unwrap();
        let mut network_sk = network_probe_skel.load().unwrap();
        network_sk.attach().unwrap();

 
        let network_perf = PerfBufferBuilder::new(&network_sk.maps.tracept_events)
            .sample_cb(move |_cpu, data: &[u8]| {
                let network_event_data: NetworkEventData =
                    unsafe { *(data.as_ptr() as *const NetworkEventData) };

                if let Err(e) = network_event_sender.blocking_send(network_event_data) {
                    // eprintln!("Failed to send TCP event: {:?}", e);
                    // TODO: If SendError, possibly the receiver is closed, restart the controller
                }
            })
            .build()
            .unwrap();


        loop {
            network_perf
                .poll(std::time::Duration::from_millis(100))
                .unwrap();
         
            // Process any incoming messages from the pod watcher
            if let Ok(inum) = rx.try_recv() {
                network_sk
                    .maps
                    .inode_num
                    .update(&inum.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY)
                    .unwrap();
            
            }
            if ignore_daemonset_traffic {
                if let Ok(ip) = ignore_ips.try_recv() {
                    let ip: Ipv4Addr = ip.parse().unwrap();
                    let ip_u32 = u32::from(ip).to_be(); // Ensure the IP is in network byte order
                    network_sk
                        .maps
                        .ignore_ips
                        .update(&ip_u32.to_ne_bytes(), &1_u32.to_ne_bytes(), MapFlags::ANY)
                        .unwrap();
                }
            }
        }
    })
}
