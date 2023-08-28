## controller ip
controller-ips:
  - {{ controller_ip }}

## controller listen port
#controller-port: 30035
## controller security authenticate port
#controller-tls-port: 30135

## controller certificate file prefix, contain path
## if certificate file exists, do certificate; or no
## certificate file naming rule is prefix.controller-ip
## example
## controller-cert-file-prefix is /etc/deepflow-server.cert
## controller ip is: 10.10.10.10
## so certificate file name is deepflow-server.cert.10.10.10.10 in /etc/
#controller-cert-file-prefix: ""

## logfile path
log-file: {{ log_file_path }}

## When running in the K8s environment, if this value is empty,
## deepflow-agent requests deepflow-server through the MD5 of the CA file of the K8s cluster to get k8s-cluster-id.
## You can also manually fill in an existing k8s-cluster-id in deepflow-server.
#kubernetes-cluster-id:

## When running in the K8s environment, if this is configured, deepflow-agent will carry this name when
## requesting to get k8s-cluster-id, and deepflow-server will use this name to mark the K8s cluster.
#kubernetes-cluster-name:

## 支持采集器自动加入组
#vtap-group-id-request: ""

## If specified, use this name for hostname
#override-os-hostname:

## Number of async worker threads, range [1, 32768), defaults to 16
## async workers are used mainly used for grpc calls, synchronizer and
## kubernetes api watcher
#async-worker-thread-number: 16
