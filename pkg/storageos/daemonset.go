package storageos

import (
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/storageos/cluster-operator/pkg/util/k8s"
)

const (

	// First cluster user's username.
	BootstrapUsernameEnvVar = "BOOTSTRAP_USERNAME"
	// First cluster user's password.
	BootstrapPasswordEnvVar = "BOOTSTRAP_PASSWORD"
	// Namespace created on startup
	BootstrapNamespaceEnvVar = "BOOTSTRAP_NAMESPACE"

	// Path to the directory in which we persist storageos data locally
	RootDirEnvVar = "ROOT_DIR"

	// Hostname is the name we use to refer to a node.
	HostnameEnvVar = "HOSTNAME"

	// Fallback value for advertised IPs. If a service does not have a specific IP
	// specified, it will use this value.
	//
	// e.g: if no "GOSSIP_ADVERTISE_ADDRESS" env var is present the gossip
	// advertised IP will take on this value.
	AdvertiseIPEnvVar = "ADVERTISE_IP"
	// Fallback value for bind IPs. If a service does not have a specific IP
	// specified, it will use this value.
	//
	// e.g: if no "GOSSIP_BIND_ADDRESS" env var is present the gossip bind IP
	// will take on this value.
	//
	// defaults to 0.0.0.0:<servicePort> if none are specified
	//
	// see Default<service>Port constants for port values
	BindIPEnvVar = "BIND_IP"

	// bind address for the public (CLI/UI) API
	APIBindAddressEnvVar = "API_BIND_ADDRESS"

	// API TLS configuration information. Certificates need to be PEM encoded DER
	// bytes.
	APITLSCAEnvVar   = "API_TLS_CA"
	APITLSKeyEnvVar  = "API_TLS_KEY"
	APITLSCertEnvVar = "API_TLS_CERT"

	// Advertised gossip IP for gossip (health checking) operations
	GossipAdvertiseEnvVar = "GOSSIP_ADVERTISE_ADDRESS"
	// bind gossip IP for gossip (health checking) operations
	GossipBindEnvVar = "GOSSIP_BIND_ADDRESS"

	// Internal TLS configuration information. Certificates need to be PEM encoded
	// DER bytes.
	//
	// used to secure dataplane and internal CP communication
	InternalTLSCACertEnvVar   = "INTERNAL_TLS_CA_CERT"
	InternalTLSNodeKeyEnvVar  = "INTERNAL_TLS_KEY"
	InternalTLSNodeCertEnvVar = "INTERNAL_TLS_CERT"

	// Advertised IP for IO (dataplane) operations
	IOAdvertiseEnvVar = "IO_ADVERTISE_ADDRESS"
	// bind IP for IO (dataplane) operations
	IOBindEnvVar = "IO_BIND_ADDRESS"

	// Dataplane sync supervisor advertised address
	SupervisorAdvertiseEnvVar = "SUPERVISOR_ADVERTISE_ADDRESS"
	// Dataplane sync supervisor bind address
	SupervisorBindEnvVar = "SUPERVISOR_BIND_ADDRESS"

	// Advertised IP for the cluster's internal gRPC API
	InternalAPIAdvertiseEnvVar = "INTERNAL_API_ADVERTISE_ADDRESS"
	// Bind IP for the cluster's internal gRPC API
	InternalAPIBindEnvVar = "INTERNAL_API_BIND_ADDRESS"

	// Directory in which volumes are exported.
	//
	// Defaults to ROOT_DIR+/volumes
	DeviceDirEnvVar = "DEVICE_DIR"

	// Directory for the dataplane gRPC unix sockets.
	SocketDirEnvVar = "SOCKET_DIR"

	// Path to the dataplane binary directory.
	DataplaneBinaryDirEnvVar = "DATAPLANE_BINARY_DIR"

	// Path to the liocheck binary.
	LioCheckBinaryPathEnvVar = "LIOCHECK_BINARY_PATH"

	// Health checking duration values
	//
	// A duration string is a possibly signed sequence of decimal numbers, each
	// with optional fraction and a unit suffix, such as "300ms", "-1.5h" or
	// "2h45m". Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
	HealthProbeIntervalEnvVar = "HEALTH_PROBE_INTERVAL"
	HealthProbeTimeoutEnvVar  = "HEALTH_PROBE_TIMEOUT"
	HealthGracePeriodEnvVar   = "HEALTH_GRACE_PERIOD"

	// Node capacity update interval
	NodeCapacityUpdateIntervalEnvVar = "NODE_CAPACITY_INTERVAL"

	// General dial timeout settings (RPC, etcd...)
	//
	// A duration string is a possibly signed sequence of decimal numbers, each
	// with optional fraction and a unit suffix, such as "300ms", "-1.5h" or
	// "2h45m". Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
	//
	// defaults to 5s
	DialTimeoutEnvVar = "DIAL_TIMEOUT"

	// Path to kubernetes config file
	KubernetesConfigPathEnvVar = "KUBECONFIG"
	// Kubernetes namespace in which storageos operates. It defaults to
	// "storageos" if none are specified
	KubernetesNamespaceEnvVar = "K8S_NAMESPACE"
	// The kubernetes runtime orchestrator in which storageos is operating.
	// There is NO guarantee of this being populated OR correct. It should
	// only be used for telemetry.
	KubernetesDistributionEnvVar = "K8S_DISTRO"

	// bind address for the CSI version API
	CSIEndpointEnvVar = "CSI_ENDPOINT"
	// CSI version to use, if CSI_ENDPOINT is set
	CSIVersionEnvVar = "CSI_VERSION"

	// Logging file path. defaults to `$ROOT_DIR/logs/storageos.log` if
	// not specified
	LogFileEnvVar = "LOG_FILE"

	// Logging level. defaults to INFO if none are specified
	LogLevelEnvVar = "LOG_LEVEL"
	// Logger format, uses the default if none are specified.
	LogFormatEnvVar = "LOG_FORMAT"

	// When set to TRUE usage data will not be logged on StorageOS servers
	DisableTelemetryEnvVar = "DISABLE_TELEMETRY"
	// When set to TRUE cluster bugs will not be logged on StorageOS servers
	DisableCrashReportingEnvVar = "DISABLE_CRASH_REPORTING"
	// When set to TRUE version checks will not be carried out against StorageOS servers
	DisableVersionCheckEnvVar = "DISABLE_VERSION_CHECK"

	// ETCD TLS configuration information. The key/cert/CA need to be PEM encoded
	// DER bytes
	ETCDTLSClientKeyEnvVar  = "ETCD_TLS_CLIENT_KEY"
	ETCDTLSClientCertEnvVar = "ETCD_TLS_CLIENT_CERT"
	ETCDTLSClientCAEnvVar   = "ETCD_TLS_CLIENT_CA"

	// ETCD namespace in which to operate. All keys in ETCD will be prefixed by
	// this value, allowing for multiple clusters to operate on the same ETCD
	// instance.
	ETCDNamespaceEnvVar = "ETCD_NAMESPACE"
	// Comma separated list of endpoints on which we will try to connect to the
	// cluster's ETCD instances.
	ETCDEndpointsEnvVar = "ETCD_ENDPOINTS"

	// ETCD authentication information
	ETCDUsernameEnvVar = "ETCD_USERNAME"
	ETCDPasswordEnvVar = "ETCD_PASSWORD"

	// Jaeger Agent env vars
	JaegerServiceNameEnvVar = "JAEGER_SERVICE_NAME"
	JaegerEndpointEnvVar    = "JAEGER_ENDPOINT"

	// c1 below
	// hostnameEnvVar                      = "HOSTNAME"
	// adminUsernameEnvVar                 = "ADMIN_USERNAME"
	// adminPasswordEnvVar                 = "ADMIN_PASSWORD"
	// joinEnvVar                          = "JOIN"
	// advertiseIPEnvVar                   = "ADVERTISE_IP"
	// namespaceEnvVar                     = "NAMESPACE"
	// disableFencingEnvVar                = "DISABLE_FENCING"
	// disableTelemetryEnvVar              = "DISABLE_TELEMETRY"
	// disableTCMUEnvVar                   = "DISABLE_TCMU"
	// forceTCMUEnvVar                     = "FORCE_TCMU"
	// deviceDirEnvVar                     = "DEVICE_DIR"
	// csiEndpointEnvVar                   = "CSI_ENDPOINT"
	// csiVersionEnvVar                    = "CSI_VERSION"
	// csiRequireCredsCreateEnvVar         = "CSI_REQUIRE_CREDS_CREATE_VOL"
	// csiRequireCredsDeleteEnvVar         = "CSI_REQUIRE_CREDS_DELETE_VOL"
	// csiProvisionCredsUsernameEnvVar     = "CSI_PROVISION_CREDS_USERNAME"
	// csiProvisionCredsPasswordEnvVar     = "CSI_PROVISION_CREDS_PASSWORD"
	// csiRequireCredsCtrlPubEnvVar        = "CSI_REQUIRE_CREDS_CTRL_PUB_VOL"
	// csiRequireCredsCtrlUnpubEnvVar      = "CSI_REQUIRE_CREDS_CTRL_UNPUB_VOL"
	// csiControllerPubCredsUsernameEnvVar = "CSI_CTRL_PUB_CREDS_USERNAME"
	// csiControllerPubCredsPasswordEnvVar = "CSI_CTRL_PUB_CREDS_PASSWORD"
	// csiRequireCredsNodePubEnvVar        = "CSI_REQUIRE_CREDS_NODE_PUB_VOL"
	// csiNodePubCredsUsernameEnvVar       = "CSI_NODE_PUB_CREDS_USERNAME"
	// csiNodePubCredsPasswordEnvVar       = "CSI_NODE_PUB_CREDS_PASSWORD"
	addressEnvVar      = "ADDRESS"
	kubeNodeNameEnvVar = "KUBE_NODE_NAME"
	// kvAddrEnvVar                        = "KV_ADDR"
	// kvBackendEnvVar                     = "KV_BACKEND"
	// debugEnvVar                         = "LOG_LEVEL"
	// k8sDistroEnvVar                     = "K8S_DISTRO"

	// Operator vars
	daemonSetNameEnvVar      = "DAEMONSET_NAME"
	daemonSetNamespaceEnvVar = "DAEMONSET_NAMESPACE"

	sysAdminCap = "SYS_ADMIN"
	debugVal    = "xdebug"

	csiEndpointVal = "unix:///var/lib/kubelet/plugins_registry/storageos/csi.sock"
	csiVersionVal  = "v1"
)

func (s *Deployment) createDaemonSet() error {
	ls := podLabelsForDaemonSet(s.stos.Name)
	privileged := true
	mountPropagationBidirectional := corev1.MountPropagationBidirectional
	allowPrivilegeEscalation := true

	spec := &appsv1.DaemonSetSpec{
		Selector: &metav1.LabelSelector{
			MatchLabels: ls,
		},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels: ls,
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: DaemonsetSA,
				HostPID:            true,
				HostNetwork:        true,
				DNSPolicy:          corev1.DNSClusterFirstWithHostNet,
				InitContainers: []corev1.Container{
					{
						Name:  "storageos-init",
						Image: s.stos.Spec.GetInitContainerImage(),
						Env: []corev1.EnvVar{
							// Environmental variables for the init container to
							// help query the DaemonSet resource and get the
							// current StorageOS node container image.
							{
								Name:  daemonSetNameEnvVar,
								Value: daemonsetName,
							},
							{
								Name:  daemonSetNamespaceEnvVar,
								Value: s.stos.Spec.GetResourceNS(),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "kernel-modules",
								MountPath: "/lib/modules",
								ReadOnly:  true,
							},
							{
								Name:             "sys",
								MountPath:        "/sys",
								MountPropagation: &mountPropagationBidirectional,
							},
							{
								Name:             "state",
								MountPath:        "/var/lib/storageos",
								MountPropagation: &mountPropagationBidirectional,
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged: &privileged,
							Capabilities: &corev1.Capabilities{
								Add: []corev1.Capability{"SYS_ADMIN"},
							},
						},
					},
				},
				Containers: []corev1.Container{
					{
						Image: s.stos.Spec.GetNodeContainerImage(),
						Name:  "storageos",
						Args:  []string{"server"},
						Ports: []corev1.ContainerPort{{
							ContainerPort: 5705,
							Name:          "api",
						}},
						// LivenessProbe: &corev1.Probe{
						// 	InitialDelaySeconds: int32(65),
						// 	TimeoutSeconds:      int32(10),
						// 	FailureThreshold:    int32(5),
						// 	Handler: corev1.Handler{
						// 		HTTPGet: &corev1.HTTPGetAction{
						// 			Path: "/v1/health",
						// 			Port: intstr.IntOrString{Type: intstr.String, StrVal: "api"},
						// 		},
						// 	},
						// },
						// ReadinessProbe: &corev1.Probe{
						// 	InitialDelaySeconds: int32(65),
						// 	TimeoutSeconds:      int32(10),
						// 	FailureThreshold:    int32(5),
						// 	Handler: corev1.Handler{
						// 		HTTPGet: &corev1.HTTPGetAction{
						// 			Path: "/v1/health",
						// 			Port: intstr.IntOrString{Type: intstr.String, StrVal: "api"},
						// 		},
						// 	},
						// },
						Env: []corev1.EnvVar{
							{
								Name: HostnameEnvVar,
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "spec.nodeName",
									},
								},
							},
							{
								Name: BootstrapUsernameEnvVar,
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: initSecretName,
										},
										Key: "username",
									},
								},
							},
							{
								Name: BootstrapPasswordEnvVar,
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: initSecretName,
										},
										Key: "password",
									},
								},
							},
							{
								Name: AdvertiseIPEnvVar,
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "status.podIP",
									},
								},
							},
							{
								Name:  JaegerEndpointEnvVar,
								Value: "10.1.10.13:31386",
							},
							{
								Name:  JaegerServiceNameEnvVar,
								Value: "alexl-c2rc1-on-vanilla-k8s",
							},
							{
								Name:  KubernetesNamespaceEnvVar,
								Value: s.stos.Spec.GetResourceNS(),
							},
							// {
							// 	Name:  disableFencingEnvVar,
							// 	Value: strconv.FormatBool(s.stos.Spec.DisableFencing),
							// },
							{
								Name:  DisableTelemetryEnvVar,
								Value: strconv.FormatBool(s.stos.Spec.DisableTelemetry),
							},
							{
								Name:  KubernetesDistributionEnvVar,
								Value: s.stos.Spec.K8sDistro,
							},
							{
								Name:  LogFormatEnvVar,
								Value: "json",
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged: &privileged,
							Capabilities: &corev1.Capabilities{
								Add: []corev1.Capability{sysAdminCap},
							},
							AllowPrivilegeEscalation: &allowPrivilegeEscalation,
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "fuse",
								MountPath: "/dev/fuse",
							},
							{
								Name:      "sys",
								MountPath: "/sys",
							},
							{
								Name:             "state",
								MountPath:        "/var/lib/storageos",
								MountPropagation: &mountPropagationBidirectional,
							},
						},
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: "kernel-modules",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/lib/modules",
							},
						},
					},
					{
						Name: "fuse",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/dev/fuse",
							},
						},
					},
					{
						Name: "sys",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/sys",
							},
						},
					},
					{
						Name: "state",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/lib/storageos",
							},
						},
					},
				},
			},
		},
		// OnDelete update strategy by default.
		UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
			Type: appsv1.OnDeleteDaemonSetStrategyType,
		},
	}

	podSpec := &spec.Template.Spec
	nodeContainer := &podSpec.Containers[0]

	s.addPodPriorityClass(podSpec)

	s.addTLSEtcdCerts(podSpec)

	s.addNodeAffinity(podSpec)

	if err := s.addTolerations(podSpec); err != nil {
		return err
	}

	nodeContainer.Env = s.addKVBackendEnvVars(nodeContainer.Env)

	nodeContainer.Env = s.addDebugEnvVars(nodeContainer.Env)

	// nodeContainer.Env = s.addCSIEnvVars(nodeContainer.Env)

	s.addNodeContainerResources(nodeContainer)

	s.addSharedDir(podSpec)

	s.addCSI(podSpec)

	return s.k8sResourceManager.DaemonSet(daemonsetName, s.stos.Spec.GetResourceNS(), nil, spec).Create()
}

// addKVBackendEnvVars checks if KVBackend is set and sets the appropriate env
// vars. Note: In C2 it must be set and etcd is assumed.  This can be further
// simplified.
func (s *Deployment) addKVBackendEnvVars(env []corev1.EnvVar) []corev1.EnvVar {
	if s.stos.Spec.KVBackend.Address != "" {
		kvAddressEnv := corev1.EnvVar{
			Name:  ETCDEndpointsEnvVar,
			Value: s.stos.Spec.KVBackend.Address,
		}
		return append(env, kvAddressEnv)
	}
	return env
}

// addDebugEnvVars checks if the debug mode is set and set the appropriate env var.
func (s *Deployment) addDebugEnvVars(env []corev1.EnvVar) []corev1.EnvVar {
	if s.stos.Spec.Debug {
		debugEnvVar := corev1.EnvVar{
			Name:  LogLevelEnvVar,
			Value: debugVal,
		}
		return append(env, debugEnvVar)
	}
	return env
}

// addCSIEnvVars checks if the debug mode is set and set the appropriate env var.
func (s *Deployment) addCSIEnvVars(env []corev1.EnvVar) []corev1.EnvVar {
	if s.stos.Spec.CSI.Enable {
		CSIVersionEnvVar := corev1.EnvVar{
			Name:  CSIVersionEnvVar,
			Value: csiVersionVal,
		}
		CSIEndpointEnvVar := corev1.EnvVar{
			Name:  CSIEndpointEnvVar,
			Value: csiEndpointVal,
		}
		return append(env, CSIVersionEnvVar, CSIEndpointEnvVar)
	}
	return env
}

// podLabelsForDaemonSet takes the name of a cluster custom resource and returns
// labels for the pods of StorageOS node DaemonSet.
func podLabelsForDaemonSet(name string) map[string]string {
	// Combine DaemonSet specific labels with the default app labels.
	labels := map[string]string{
		"app":          appName,
		"storageos_cr": name,
		"kind":         daemonsetKind,
	}
	return k8s.AddDefaultAppLabels(name, labels)
}
