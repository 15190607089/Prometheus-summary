1.3. Docker containers : google/cAdvisor (6 rules)[copy section]
# 1.3.1. Container killed
A container has disappeared[copy]
  # This rule can be very noisy in dynamic infra with legitimate container start/stop/deployment.
  - alert: ContainerKilled
    expr: time() - container_last_seen > 60
    for: 0m
    labels:
      severity: warning
    annotations:
      summary: Container killed (instance {{ $labels.instance }})
      description: "A container has disappeared\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

# 1.3.2. Container absent
A container is absent for 5 min[copy]
  # This rule can be very noisy in dynamic infra with legitimate container start/stop/deployment.
  - alert: ContainerAbsent
    expr: absent(container_last_seen)
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: Container absent (instance {{ $labels.instance }})
      description: "A container is absent for 5 min\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

# 1.3.3. Container CPU usage
Container CPU usage is above 80%[copy]
  - alert: ContainerCpuUsage
    expr: (sum(rate(container_cpu_usage_seconds_total{name!=""}[3m])) BY (instance, name) * 100) > 80
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: Container CPU usage (instance {{ $labels.instance }})
      description: "Container CPU usage is above 80%\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

# 1.3.4. Container Memory usage
Container Memory usage is above 80%[copy]
  # See https://medium.com/faun/how-much-is-too-much-the-linux-oomkiller-and-used-memory-d32186f29c9d
  - alert: ContainerMemoryUsage
    expr: (sum(container_memory_working_set_bytes{name!=""}) BY (instance, name) / sum(container_spec_memory_limit_bytes > 0) BY (instance, name) * 100) > 80
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: Container Memory usage (instance {{ $labels.instance }})
      description: "Container Memory usage is above 80%\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

# 1.3.5. Container Volume usage
Container Volume usage is above 80%[copy]
  - alert: ContainerVolumeUsage
    expr: (1 - (sum(container_fs_inodes_free{name!=""}) BY (instance) / sum(container_fs_inodes_total) BY (instance))) * 100 > 80
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: Container Volume usage (instance {{ $labels.instance }})
      description: "Container Volume usage is above 80%\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

# 1.3.6. Container high throttle rate
Container is being throttled[copy]
  - alert: ContainerHighThrottleRate
    expr: rate(container_cpu_cfs_throttled_seconds_total[3m]) > 1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: Container high throttle rate (instance {{ $labels.instance }})
      description: "Container is being throttled\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

# 1.4. Blackbox : prometheus/blackbox_exporter (9 rules)
1.4.1. Blackbox probe failed
Probe failed[copy]
  - alert: BlackboxProbeFailed
    expr: probe_success == 0
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: Blackbox probe failed (instance {{ $labels.instance }})
      description: "Probe failed\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

# 1.4.2. Blackbox configuration reload failure
Blackbox configuration reload failure[copy]
  - alert: BlackboxConfigurationReloadFailure
    expr: blackbox_exporter_config_last_reload_successful != 1
    for: 0m
    labels:
      severity: warning
    annotations:
      summary: Blackbox configuration reload failure (instance {{ $labels.instance }})
      description: "Blackbox configuration reload failure\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

# 1.4.3. Blackbox slow probe
Blackbox probe took more than 1s to complete[copy]
  - alert: BlackboxSlowProbe
    expr: avg_over_time(probe_duration_seconds[1m]) > 1
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: Blackbox slow probe (instance {{ $labels.instance }})
      description: "Blackbox probe took more than 1s to complete\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

# 1.4.4. Blackbox probe HTTP failure
HTTP status code is not 200-399[copy]
  - alert: BlackboxProbeHttpFailure
    expr: probe_http_status_code <= 199 OR probe_http_status_code >= 400
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: Blackbox probe HTTP failure (instance {{ $labels.instance }})
      description: "HTTP status code is not 200-399\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

# 1.4.5. Blackbox SSL certificate will expire soon
SSL certificate expires in 30 days[copy]
  - alert: BlackboxSslCertificateWillExpireSoon
    expr: probe_ssl_earliest_cert_expiry - time() < 86400 * 30
    for: 0m
    labels:
      severity: warning
    annotations:
      summary: Blackbox SSL certificate will expire soon (instance {{ $labels.instance }})
      description: "SSL certificate expires in 30 days\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

# 1.4.6. Blackbox SSL certificate will expire soon
SSL certificate expires in 3 days[copy]
  - alert: BlackboxSslCertificateWillExpireSoon
    expr: probe_ssl_earliest_cert_expiry - time() < 86400 * 3
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: Blackbox SSL certificate will expire soon (instance {{ $labels.instance }})
      description: "SSL certificate expires in 3 days\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

# 1.4.7. Blackbox SSL certificate expired
SSL certificate has expired already[copy]
  - alert: BlackboxSslCertificateExpired
    expr: probe_ssl_earliest_cert_expiry - time() <= 0
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: Blackbox SSL certificate expired (instance {{ $labels.instance }})
      description: "SSL certificate has expired already\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

# 1.4.8. Blackbox probe slow HTTP
HTTP request took more than 1s[copy]
  - alert: BlackboxProbeSlowHttp
    expr: avg_over_time(probe_http_duration_seconds[1m]) > 1
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: Blackbox probe slow HTTP (instance {{ $labels.instance }})
      description: "HTTP request took more than 1s\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

# 1.4.9. Blackbox probe slow ping
Blackbox ping took more than 1s[copy]
  - alert: BlackboxProbeSlowPing
    expr: avg_over_time(probe_icmp_duration_seconds[1m]) > 1
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: Blackbox probe slow ping (instance {{ $labels.instance }})
      description: "Blackbox ping took more than 1s\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"
      
      

Kubernetes : kube-state-metrics    
      
  - alert: KubernetesNodeReady
    expr: kube_node_status_condition{condition="Ready",status="true"} == 0
    for: 10m
    labels:
      severity: critical
    annotations:
      summary: Kubernetes Node ready (instance {{ $labels.instance }})
      description: "Node {{ $labels.node }} has been unready for a long time\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesMemoryPressure
    expr: kube_node_status_condition{condition="MemoryPressure",status="true"} == 1
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: Kubernetes memory pressure (instance {{ $labels.instance }})
      description: "{{ $labels.node }} has MemoryPressure condition\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesDiskPressure
    expr: kube_node_status_condition{condition="DiskPressure",status="true"} == 1
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: Kubernetes disk pressure (instance {{ $labels.instance }})
      description: "{{ $labels.node }} has DiskPressure condition\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesOutOfDisk
    expr: kube_node_status_condition{condition="OutOfDisk",status="true"} == 1
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: Kubernetes out of disk (instance {{ $labels.instance }})
      description: "{{ $labels.node }} has OutOfDisk condition\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesOutOfCapacity
    expr: sum by (node) ((kube_pod_status_phase{phase="Running"} == 1) + on(uid) group_left(node) (0 * kube_pod_info{pod_template_hash=""})) / sum by (node) (kube_node_status_allocatable{resource="pods"}) * 100 > 90
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: Kubernetes out of capacity (instance {{ $labels.instance }})
      description: "{{ $labels.node }} is out of capacity\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesContainerOomKiller
    expr: (kube_pod_container_status_restarts_total - kube_pod_container_status_restarts_total offset 10m >= 1) and ignoring (reason) min_over_time(kube_pod_container_status_last_terminated_reason{reason="OOMKilled"}[10m]) == 1
    for: 0m
    labels:
      severity: warning
    annotations:
      summary: Kubernetes container oom killer (instance {{ $labels.instance }})
      description: "Container {{ $labels.container }} in pod {{ $labels.namespace }}/{{ $labels.pod }} has been OOMKilled {{ $value }} times in the last 10 minutes.\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesJobFailed
    expr: kube_job_status_failed > 0
    for: 0m
    labels:
      severity: warning
    annotations:
      summary: Kubernetes Job failed (instance {{ $labels.instance }})
      description: "Job {{$labels.namespace}}/{{$labels.exported_job}} failed to complete\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesCronjobSuspended
    expr: kube_cronjob_spec_suspend != 0
    for: 0m
    labels:
      severity: warning
    annotations:
      summary: Kubernetes CronJob suspended (instance {{ $labels.instance }})
      description: "CronJob {{ $labels.namespace }}/{{ $labels.cronjob }} is suspended\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesPersistentvolumeclaimPending
    expr: kube_persistentvolumeclaim_status_phase{phase="Pending"} == 1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: Kubernetes PersistentVolumeClaim pending (instance {{ $labels.instance }})
      description: "PersistentVolumeClaim {{ $labels.namespace }}/{{ $labels.persistentvolumeclaim }} is pending\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesVolumeOutOfDiskSpace
    expr: kubelet_volume_stats_available_bytes / kubelet_volume_stats_capacity_bytes * 100 < 10
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: Kubernetes Volume out of disk space (instance {{ $labels.instance }})
      description: "Volume is almost full (< 10% left)\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesVolumeFullInFourDays
    expr: predict_linear(kubelet_volume_stats_available_bytes[6h], 4 * 24 * 3600) < 0
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: Kubernetes Volume full in four days (instance {{ $labels.instance }})
      description: "{{ $labels.namespace }}/{{ $labels.persistentvolumeclaim }} is expected to fill up within four days. Currently {{ $value | humanize }}% is available.\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesPersistentvolumeError
    expr: kube_persistentvolume_status_phase{phase=~"Failed|Pending", job="kube-state-metrics"} > 0
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: Kubernetes PersistentVolume error (instance {{ $labels.instance }})
      description: "Persistent volume is in bad state\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesStatefulsetDown
    expr: (kube_statefulset_status_replicas_ready / kube_statefulset_status_replicas_current) != 1
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: Kubernetes StatefulSet down (instance {{ $labels.instance }})
      description: "A StatefulSet went down\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesHpaScalingAbility
    expr: kube_horizontalpodautoscaler_status_condition{status="false", condition="AbleToScale"} == 1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: Kubernetes HPA scaling ability (instance {{ $labels.instance }})
      description: "Pod is unable to scale\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesHpaMetricAvailability
    expr: kube_horizontalpodautoscaler_status_condition{status="false", condition="ScalingActive"} == 1
    for: 0m
    labels:
      severity: warning
    annotations:
      summary: Kubernetes HPA metric availability (instance {{ $labels.instance }})
      description: "HPA is not able to collect metrics\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesHpaScaleCapability
    expr: kube_horizontalpodautoscaler_status_desired_replicas >= kube_horizontalpodautoscaler_spec_max_replicas
    for: 2m
    labels:
      severity: info
    annotations:
      summary: Kubernetes HPA scale capability (instance {{ $labels.instance }})
      description: "The maximum number of desired Pods has been hit\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesPodNotHealthy
    expr: min_over_time(sum by (namespace, pod) (kube_pod_status_phase{phase=~"Pending|Unknown|Failed"})[15m:1m]) > 0
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: Kubernetes Pod not healthy (instance {{ $labels.instance }})
      description: "Pod has been in a non-ready state for longer than 15 minutes.\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesPodCrashLooping
    expr: increase(kube_pod_container_status_restarts_total[1m]) > 3
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: Kubernetes pod crash looping (instance {{ $labels.instance }})
      description: "Pod {{ $labels.pod }} is crash looping\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesReplicassetMismatch
    expr: kube_replicaset_spec_replicas != kube_replicaset_status_ready_replicas
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: Kubernetes ReplicasSet mismatch (instance {{ $labels.instance }})
      description: "Deployment Replicas mismatch\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesDeploymentReplicasMismatch
    expr: kube_deployment_spec_replicas != kube_deployment_status_replicas_available
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: Kubernetes Deployment replicas mismatch (instance {{ $labels.instance }})
      description: "Deployment Replicas mismatch\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesStatefulsetReplicasMismatch
    expr: kube_statefulset_status_replicas_ready != kube_statefulset_status_replicas
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: Kubernetes StatefulSet replicas mismatch (instance {{ $labels.instance }})
      description: "A StatefulSet does not match the expected number of replicas.\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesDeploymentGenerationMismatch
    expr: kube_deployment_status_observed_generation != kube_deployment_metadata_generation
    for: 10m
    labels:
      severity: critical
    annotations:
      summary: Kubernetes Deployment generation mismatch (instance {{ $labels.instance }})
      description: "A Deployment has failed but has not been rolled back.\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesStatefulsetGenerationMismatch
    expr: kube_statefulset_status_observed_generation != kube_statefulset_metadata_generation
    for: 10m
    labels:
      severity: critical
    annotations:
      summary: Kubernetes StatefulSet generation mismatch (instance {{ $labels.instance }})
      description: "A StatefulSet has failed but has not been rolled back.\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesStatefulsetUpdateNotRolledOut
    expr: max without (revision) (kube_statefulset_status_current_revision unless kube_statefulset_status_update_revision) * (kube_statefulset_replicas != kube_statefulset_status_replicas_updated)
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: Kubernetes StatefulSet update not rolled out (instance {{ $labels.instance }})
      description: "StatefulSet update has not been rolled out.\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesDaemonsetRolloutStuck
    expr: kube_daemonset_status_number_ready / kube_daemonset_status_desired_number_scheduled * 100 < 100 or kube_daemonset_status_desired_number_scheduled - kube_daemonset_status_current_number_scheduled > 0
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: Kubernetes DaemonSet rollout stuck (instance {{ $labels.instance }})
      description: "Some Pods of DaemonSet are not scheduled or not ready\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesDaemonsetMisscheduled
    expr: kube_daemonset_status_number_misscheduled > 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: Kubernetes DaemonSet misscheduled (instance {{ $labels.instance }})
      description: "Some DaemonSet Pods are running where they are not supposed to run\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesCronjobTooLong
    expr: time() - kube_cronjob_next_schedule_time > 3600
    for: 0m
    labels:
      severity: warning
    annotations:
      summary: Kubernetes CronJob too long (instance {{ $labels.instance }})
      description: "CronJob {{ $labels.namespace }}/{{ $labels.cronjob }} is taking more than 1h to complete.\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesJobSlowCompletion
    expr: kube_job_spec_completions - kube_job_status_succeeded > 0
    for: 12h
    labels:
      severity: critical
    annotations:
      summary: Kubernetes job slow completion (instance {{ $labels.instance }})
      description: "Kubernetes Job {{ $labels.namespace }}/{{ $labels.job_name }} did not complete in time.\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesApiServerErrors
    expr: sum(rate(apiserver_request_total{job="apiserver",code=~"^(?:5..)$"}[1m])) / sum(rate(apiserver_request_total{job="apiserver"}[1m])) * 100 > 3
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: Kubernetes API server errors (instance {{ $labels.instance }})
      description: "Kubernetes API server is experiencing high error rate\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesApiClientErrors
    expr: (sum(rate(rest_client_requests_total{code=~"(4|5).."}[1m])) by (instance, job) / sum(rate(rest_client_requests_total[1m])) by (instance, job)) * 100 > 1
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: Kubernetes API client errors (instance {{ $labels.instance }})
      description: "Kubernetes API client is experiencing high error rate\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesClientCertificateExpiresNextWeek
    expr: apiserver_client_certificate_expiration_seconds_count{job="apiserver"} > 0 and histogram_quantile(0.01, sum by (job, le) (rate(apiserver_client_certificate_expiration_seconds_bucket{job="apiserver"}[5m]))) < 7*24*60*60
    for: 0m
    labels:
      severity: warning
    annotations:
      summary: Kubernetes client certificate expires next week (instance {{ $labels.instance }})
      description: "A client certificate used to authenticate to the apiserver is expiring next week.\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesClientCertificateExpiresSoon
    expr: apiserver_client_certificate_expiration_seconds_count{job="apiserver"} > 0 and histogram_quantile(0.01, sum by (job, le) (rate(apiserver_client_certificate_expiration_seconds_bucket{job="apiserver"}[5m]))) < 24*60*60
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: Kubernetes client certificate expires soon (instance {{ $labels.instance }})
      description: "A client certificate used to authenticate to the apiserver is expiring in less than 24.0 hours.\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"

  - alert: KubernetesApiServerLatency
    expr: histogram_quantile(0.99, sum(rate(apiserver_request_latencies_bucket{subresource!="log",verb!~"^(?:CONNECT|WATCHLIST|WATCH|PROXY)$"} [10m])) WITHOUT (instance, resource)) / 1e+06 > 1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: Kubernetes API server latency (instance {{ $labels.instance }})
      description: "Kubernetes API server has a 99th percentile latency of {{ $value }} seconds for {{ $labels.verb }} {{ $labels.resource }}.\n  VALUE = {{ $value }}\n  LABELS = {{ $labels }}"
