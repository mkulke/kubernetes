#!/bin/bash

# Copyright 2014 The Kubernetes Authors All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


MASTER_ADDRESS=${1:-"8.8.8.18"}
ETCD_SERVERS=${2:-"http://8.8.8.18:4001"}
SERVICE_CLUSTER_IP_RANGE=${3:-"10.10.10.0/24"}

cat <<EOF >/opt/kubernetes/cfg/kube-apiserver
# --logtostderr=true: log to standard error instead of files
KUBE_LOGTOSTDERR="--logtostderr=true"

# --v=0: log level for V logs
KUBE_LOG_LEVEL="--v=4"

# --etcd-servers=[]: List of etcd servers to watch (http://ip:port), 
# comma separated. Mutually exclusive with -etcd-config
KUBE_ETCD_SERVERS="--etcd-servers=${ETCD_SERVERS}"

# --address=127.0.0.1: DEPRECATED: see --insecure-bind-address instead
KUBE_API_ADDRESS="--address=${MASTER_ADDRESS}"

# --port=8080: DEPRECATED: see --insecure-port instead
KUBE_API_PORT="--port=8080"

# --kubelet-port=10250: Kubelet port
MINION_PORT="--kubelet-port=10250"

# --allow-privileged=false: If true, allow privileged containers.
KUBE_ALLOW_PRIV="--allow-privileged=false"

# --service-cluster-ip-range=<nil>: A CIDR notation IP range from which to assign service cluster IPs. 
# This must not overlap with any IP ranges assigned to nodes for pods.
KUBE_SERVICE_ADDRESSES="--service-cluster-ip-range=${SERVICE_CLUSTER_IP_RANGE}"

# --admission-control="AlwaysAdmit": Ordered list of plug-ins 
# to do admission control of resources into cluster. 
# Comma-delimited list of: 
#   LimitRanger, AlwaysDeny, SecurityContextDeny, NamespaceExists, 
#   NamespaceLifecycle, NamespaceAutoProvision, DenyExecOnPrivileged, 
#   AlwaysAdmit, ServiceAccount, ResourceQuota
#KUBE_ADMISSION_CONTROL=""

EOF

KUBE_APISERVER_OPTS="   \${KUBE_LOGTOSTDERR}         \\
                        \${KUBE_LOG_LEVEL}           \\
                        \${KUBE_ETCD_SERVERS}        \\
                        \${KUBE_API_ADDRESS}         \\
                        \${KUBE_API_PORT}            \\
                        \${MINION_PORT}              \\
                        \${KUBE_ALLOW_PRIV}          \\
                        \${KUBE_SERVICE_ADDRESSES}"


cat <<EOF >/usr/lib/systemd/system/kube-apiserver.service
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
EnvironmentFile=-/opt/kubernetes/cfg/kube-apiserver
ExecStart=/opt/kubernetes/bin/kube-apiserver ${KUBE_APISERVER_OPTS}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable kube-apiserver
systemctl start kube-apiserver
