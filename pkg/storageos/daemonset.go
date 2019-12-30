package storageos

import (
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/storageos/cluster-operator/pkg/util/k8s"
)

const (
	hostnameEnvVar                      = "HOSTNAME"
	adminUsernameEnvVar                 = "ADMIN_USERNAME"
	adminPasswordEnvVar                 = "ADMIN_PASSWORD"
	joinEnvVar                          = "JOIN"
	advertiseIPEnvVar                   = "ADVERTISE_IP"
	namespaceEnvVar                     = "NAMESPACE"
	disableFencingEnvVar                = "DISABLE_FENCING"
	disableTelemetryEnvVar              = "DISABLE_TELEMETRY"
	disableTCMUEnvVar                   = "DISABLE_TCMU"
	forceTCMUEnvVar                     = "FORCE_TCMU"
	deviceDirEnvVar                     = "DEVICE_DIR"
	csiEndpointEnvVar                   = "CSI_ENDPOINT"
	csiVersionEnvVar                    = "CSI_VERSION"
	csiRequireCredsCreateEnvVar         = "CSI_REQUIRE_CREDS_CREATE_VOL"
	csiRequireCredsDeleteEnvVar         = "CSI_REQUIRE_CREDS_DELETE_VOL"
	csiProvisionCredsUsernameEnvVar     = "CSI_PROVISION_CREDS_USERNAME"
	csiProvisionCredsPasswordEnvVar     = "CSI_PROVISION_CREDS_PASSWORD"
	csiRequireCredsCtrlPubEnvVar        = "CSI_REQUIRE_CREDS_CTRL_PUB_VOL"
	csiRequireCredsCtrlUnpubEnvVar      = "CSI_REQUIRE_CREDS_CTRL_UNPUB_VOL"
	csiControllerPubCredsUsernameEnvVar = "CSI_CTRL_PUB_CREDS_USERNAME"
	csiControllerPubCredsPasswordEnvVar = "CSI_CTRL_PUB_CREDS_PASSWORD"
	csiRequireCredsNodePubEnvVar        = "CSI_REQUIRE_CREDS_NODE_PUB_VOL"
	csiNodePubCredsUsernameEnvVar       = "CSI_NODE_PUB_CREDS_USERNAME"
	csiNodePubCredsPasswordEnvVar       = "CSI_NODE_PUB_CREDS_PASSWORD"
	addressEnvVar                       = "ADDRESS"
	kubeNodeNameEnvVar                  = "KUBE_NODE_NAME"
	kvAddrEnvVar                        = "KV_ADDR"
	kvBackendEnvVar                     = "KV_BACKEND"
	debugEnvVar                         = "LOG_LEVEL"
	k8sDistroEnvVar                     = "K8S_DISTRO"
	daemonSetNameEnvVar                 = "DAEMONSET_NAME"
	daemonSetNamespaceEnvVar            = "DAEMONSET_NAMESPACE"

	sysAdminCap = "SYS_ADMIN"
	debugVal    = "xdebug"
)

func (s *Deployment) createDaemonSet() error {
	ls := podLabelsForDaemonSet(s.stos.Name)
	privileged := true
	mountPropagationBidirectional := corev1.MountPropagationBidirectional
	allowPrivilegeEscalation := true
	scName := "csi-cinder-classic"

	spec := &appsv1.StatefulSetSpec{
		ServiceName: "storageos",
		Selector: &metav1.LabelSelector{
			MatchLabels: ls,
		},
		VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "state",
				},
				Spec: corev1.PersistentVolumeClaimSpec{
					AccessModes: []corev1.PersistentVolumeAccessMode{
						"ReadWriteOnce",
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceStorage: resource.MustParse("50Gi"),
						},
					},
					StorageClassName: &scName,
				},
			},
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
						LivenessProbe: &corev1.Probe{
							InitialDelaySeconds: int32(65),
							TimeoutSeconds:      int32(10),
							FailureThreshold:    int32(5),
							Handler: corev1.Handler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/v1/health",
									Port: intstr.IntOrString{Type: intstr.String, StrVal: "api"},
								},
							},
						},
						ReadinessProbe: &corev1.Probe{
							InitialDelaySeconds: int32(65),
							TimeoutSeconds:      int32(10),
							FailureThreshold:    int32(5),
							Handler: corev1.Handler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/v1/health",
									Port: intstr.IntOrString{Type: intstr.String, StrVal: "api"},
								},
							},
						},
						Env: []corev1.EnvVar{
							{
								Name: hostnameEnvVar,
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "spec.nodeName",
									},
								},
							},
							{
								Name: adminUsernameEnvVar,
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
								Name: adminPasswordEnvVar,
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
								Name:  joinEnvVar,
								Value: s.stos.Spec.Join,
							},
							{
								Name: advertiseIPEnvVar,
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "status.podIP",
									},
								},
							},
							{
								Name:  namespaceEnvVar,
								Value: s.stos.Spec.GetResourceNS(),
							},
							{
								Name:  disableFencingEnvVar,
								Value: strconv.FormatBool(s.stos.Spec.DisableFencing),
							},
							{
								Name:  disableTelemetryEnvVar,
								Value: strconv.FormatBool(s.stos.Spec.DisableTelemetry),
							},
							{
								Name:  disableTCMUEnvVar,
								Value: strconv.FormatBool(s.stos.Spec.DisableTCMU),
							},
							{
								Name:  forceTCMUEnvVar,
								Value: strconv.FormatBool(s.stos.Spec.ForceTCMU),
							},
							{
								Name:  csiVersionEnvVar,
								Value: s.stos.Spec.GetCSIVersion(CSIV1Supported(s.k8sVersion)),
							},
							{
								Name:  k8sDistroEnvVar,
								Value: s.stos.Spec.K8sDistro,
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
				},
			},
		},
		// OnDelete update strategy by default.
		UpdateStrategy: appsv1.StatefulSetUpdateStrategy{
			Type: appsv1.OnDeleteStatefulSetStrategyType,
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

	s.addNodeContainerResources(nodeContainer)

	s.addSharedDir(podSpec)

	s.addCSI(podSpec)

	return s.k8sResourceManager.StatefulSet(daemonsetName, s.stos.Spec.GetResourceNS(), nil, spec).Create()
}

// addKVBackendEnvVars checks if KVBackend is set and sets the appropriate env vars.
func (s *Deployment) addKVBackendEnvVars(env []corev1.EnvVar) []corev1.EnvVar {
	kvStoreEnv := []corev1.EnvVar{}
	if s.stos.Spec.KVBackend.Address != "" {
		kvAddressEnv := corev1.EnvVar{
			Name:  kvAddrEnvVar,
			Value: s.stos.Spec.KVBackend.Address,
		}
		kvStoreEnv = append(kvStoreEnv, kvAddressEnv)
	}

	if s.stos.Spec.KVBackend.Backend != "" {
		kvBackendEnv := corev1.EnvVar{
			Name:  kvBackendEnvVar,
			Value: s.stos.Spec.KVBackend.Backend,
		}
		kvStoreEnv = append(kvStoreEnv, kvBackendEnv)
	}

	if len(kvStoreEnv) > 0 {
		return append(env, kvStoreEnv...)
	}
	return env
}

// addDebugEnvVars checks if the debug mode is set and set the appropriate env var.
func (s *Deployment) addDebugEnvVars(env []corev1.EnvVar) []corev1.EnvVar {
	if s.stos.Spec.Debug {
		debugEnvVar := corev1.EnvVar{
			Name:  debugEnvVar,
			Value: debugVal,
		}
		return append(env, debugEnvVar)
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
