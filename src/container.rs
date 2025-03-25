use crate::PodInspect;
use containerd_client::{
    connect,
    services::v1::{tasks_client::TasksClient, GetRequest},
    tonic::{transport::Channel, Request},
    with_namespace,
};
use procfs::process::Process;
use regex::Regex;
use std::ffi::OsString;
use tracing::*;

static REGEX_CONTAINERD: &str = "containerd://(?P<container_id>[0-9a-zA-Z]*)";

impl PodInspect {
    pub async fn get_pod_inspect(self, container_id: &str) -> Option<PodInspect> {
        let re = Regex::new(REGEX_CONTAINERD).unwrap();
        let container_id: Option<String> = re
            .captures(container_id)
            .map(|c| c["container_id"].parse().unwrap());

        if let Some(container_id) = container_id {
            let channel = connect("/run/containerd/containerd.sock").await.unwrap();
            Some(
                self.set_container_id(container_id)
                    .get_pid(channel)
                    .await
                    .get_net_namespace_id(),
            )
        } else {
            None
        }
    }

    fn set_container_id(mut self, container_id: String) -> Self {
        self.container_id = Some(container_id);
        self
    }

    async fn get_pid(mut self, channel: Channel) -> Self {
        let mut client = TasksClient::new(channel.clone());

        let req = GetRequest {
            container_id: self.container_id.to_owned().unwrap(),
            ..Default::default()
        };

        let req = with_namespace!(req, "k8s.io");
        match client.get(req).await {
            Ok(resp) => {
                let container_resp = resp.into_inner();
                self.pid = container_resp.process.map(|p| p.pid);
            }
            Err(err) => {
                debug!(
                    "Failed to get container response for container id {:?}, {:?}",
                    self.container_id, err
                );
                self.pid = None;
            }
        }
        self
    }

    fn get_net_namespace_id(mut self) -> Self {
        if self.pid.is_some() {
            if let Ok(process) = Process::new(self.pid.unwrap() as i32) {
                if let Ok(ns) = process.namespaces() {
                    if let Some(netns) = ns.0.get(&OsString::from("net")) {
                        self.inode_num = Some(netns.identifier);
                    }
                }
            }
        }
        self
    }
}
