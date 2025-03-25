
use anyhow::Result;
use std::{collections::BTreeMap, env, sync::Arc};
use tokio::sync::{mpsc, Mutex};
use std::collections::HashMap;

use tracing::info;

use udp_tracer::bpf::ebpf_handle;
use udp_tracer::log::init_logger;
use udp_tracer::network::handle_network_events;

use udp_tracer::{
    error::Error, models::PodInspect, network::NetworkEventData,network::print_live_stats, pod_watcher::watch_pods,
};

type CounterMap = Arc<Mutex<HashMap<String, u64>>>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    init_logger();

    let counter: CounterMap = Arc::new(Mutex::new(HashMap::new()));
    let node_name = env::var("CURRENT_NODE").expect("cannot find node name: CURRENT_NODE ");

    let excluded_namespaces: Vec<String> = env::var("EXCLUDED_NAMESPACES")
        .unwrap_or_else(|_| "".to_string())
        .split(',')
        .map(|s| s.to_string())
        .collect();

    let ignore_daemonset_traffic = env::var("IGNORE_DAEMONSET_TRAFFIC")
        .unwrap_or_else(|_| "false".to_string()) // Default to true, dont log the daemonset traffic
        .parse::<bool>()
        .unwrap_or(false);

    let (tx, rx) = mpsc::channel(1000); // Use tokio's mpsc channel

    let (sender_ip, recv_ip) = mpsc::channel(1000); // Use tokio's mpsc channel

    let c: Arc<Mutex<BTreeMap<u64, PodInspect>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let pod_c = Arc::clone(&c);
    let container_map = Arc::clone(&c);
    let pods = watch_pods(
        node_name,
        tx,
        pod_c,
        &excluded_namespaces,
        sender_ip,
        ignore_daemonset_traffic,
    );
    //info!("Ignoring namespaces: {:?}", excluded_namespaces);

    let (network_event_sender, network_event_receiver) = mpsc::channel::<NetworkEventData>(1000);
   
    let network_event_handler =
        handle_network_events(network_event_receiver, Arc::clone(&container_map),counter.clone() );
   
    let ebpf_handle = ebpf_handle(
        network_event_sender,
        rx,
        recv_ip,
        ignore_daemonset_traffic,
    );
   
    let live_print_data = print_live_stats(counter.clone());
   
    // Wait for all tasks to complete (they should run indefinitely)
    _ = tokio::try_join!(
        pods,
        network_event_handler,
        async { ebpf_handle.await.unwrap() },
        live_print_data,
        
    )
    .unwrap();
    Ok(())

}
