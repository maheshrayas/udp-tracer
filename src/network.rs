use crate::{Error, PodInspect, PodTraffic};
use chrono::Utc;
use moka::future::Cache;
use serde_json::json;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info};
use uuid::Uuid;
use std::collections::HashMap;

lazy_static::lazy_static! {
    static ref TRAFFIC_CACHE: Arc<Cache<TrafficKey, ()>> = Arc::new(Cache::new(10000));
}

pub mod network_probe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/trace_udp.skel.rs"
    ));
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct TrafficKey {
    pod_name: String,
    pod_ip: String,
    pod_port: String,
    traffic_in_out_ip: String,
    traffic_in_out_port: String,
    traffic_type: String,
    ip_protocol: String,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEventData {
    pub inum: u64,
    saddr: u32,
    sport: u16,
    daddr: u32,
    dport: u16,
    pub kind: u16,
}

pub async fn handle_network_events(
    mut event_receiver: tokio::sync::mpsc::Receiver<NetworkEventData>,
    container_map_tcp: Arc<Mutex<BTreeMap<u64, PodInspect>>>,
    counter_map: Arc<Mutex<HashMap<String, u64>>>,
) -> Result<(), Error> {
    while let Some(event) = event_receiver.recv().await {
        let container_map = container_map_tcp.lock().await;
        let counter_map= Arc::clone(&counter_map);
        if let Some(pod_inspect) = container_map.get(&event.inum) {
            process_network_event(&event, pod_inspect, counter_map ).await?
        }
    }
    Ok(())
}

pub async fn process_network_event(
    data: &NetworkEventData,
    pod_data: &PodInspect,
    counter :  Arc<Mutex<HashMap<String, u64>>>,
) -> Result<(), Error> {
    let src = u32::from_be(data.saddr);
    let dst = u32::from_be(data.daddr);
    let sport = data.sport;
    let dport = data.dport;
    let mut protocol = "";
    let mut pod_port = sport;
    let traffic_in_out_ip = IpAddr::V4(Ipv4Addr::from(dst)).to_string();
    let mut traffic_in_out_port = dport;
    let mut traffic_type = "";

    // if data.kind.eq(&3) {
    //     traffic_type = "INGRESS";
    //     pod_port = 0;
    //     traffic_in_out_port = dport;
    //     protocol = "UDP"
    // }

    // info!(
    //     "Inum : {} src {}:{},dst {}:{}, trafic type {:?} kind {:?}",
    //     data.inum,
    //     IpAddr::V4(Ipv4Addr::from(src)),
    //     sport,
    //     IpAddr::V4(Ipv4Addr::from(dst)),
    //     dport,
    //     traffic_type,
    //     data.kind
    // );

    {
        let mut counts = counter.lock().await;
        let entry = counts.entry(pod_data.status.pod_name.to_owned()).or_insert(0);
        *entry += 1;
    }

    debug!(
        "Inum : {} pod_name {} pod_namespace {:?},dst {}:{}, trafic type {:?} kind {:?}",
        data.inum,
        pod_data.status.pod_name,
        pod_data.status.pod_namespace,
        IpAddr::V4(Ipv4Addr::from(dst)),
        dport,
        traffic_type,
        data.kind
    );
    

    Ok(())
}

pub async fn print_live_stats(counter: Arc<Mutex<HashMap<String, u64>>>) -> Result<(), Error> {
    let interval_duration = std::time::Duration::from_secs(5);
    loop {
        tokio::time::sleep(interval_duration).await;

        let counts = counter.lock().await;

        // Sort by value (requests) in descending order
        let mut sorted_counts: Vec<_> = counts.iter().collect();
        sorted_counts.sort_by(|a, b| b.1.cmp(a.1)); // Sort in descending order

        // ANSI Escape Code to clear screen and move cursor to top-left
        print!("\x1B[2J\x1B[H"); 
        println!("=== Live Pod Request Counts ===");

        for (pod, count) in sorted_counts.iter() {
            println!("Pod: {} - Requests: {}", pod, count);
        }
        println!("===============================\n");

        // Flush stdout to ensure immediate display update
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
    }
}
