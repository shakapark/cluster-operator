package storageos

import (
	"fmt"
	"path/filepath"
	"strconv"

	storageosv1 "github.com/storageos/cluster-operator/pkg/apis/storageos/v1"
)

const (

	// External ETCD config, V1 only.
	kvBackendEnvVar = "KV_BACKEND"
	kvAddrEnvVar    = "KV_ADDR"
	joinEnvVar      = "JOIN"

	// Comma separated list of endpoints on which we will try to connect to the
	// cluster's ETCD instances.
	etcdEndpointsEnvVar = "ETCD_ENDPOINTS"

	// TODO: ETCD TLS configuration information. The key/cert/CA need to be PEM encoded
	// DER bytes
	v1EtcdTLSClientKeyEnvVar  = "TLS_ETCD_CLIENT_KEY"
	v1EtcdTLSClientCertEnvVar = "TLS_ETCD_CLIENT_CERT"
	v1EtcdTLSClientCAEnvVar   = "TLS_ETCD_CA"
	v2EtcdTLSClientKeyEnvVar  = "ETCD_TLS_CLIENT_KEY"
	v2EtcdTLSClientCertEnvVar = "ETCD_TLS_CLIENT_CERT"
	v2EtcdTLSClientCAEnvVar   = "ETCD_TLS_CLIENT_CA"

	// TODO: ETCD authentication information
	etcdUsernameEnvVar = "ETCD_USERNAME"
	etcdPasswordEnvVar = "ETCD_PASSWORD"

	// TODO: ETCD namespace in which to operate. All keys in ETCD will be prefixed by
	// this value, allowing for multiple clusters to operate on the same ETCD
	// instance.
	etcdNamespaceEnvVar = "ETCD_NAMESPACE"

	// Feature flags (enabled by default)
	disableFencingEnvVar = "DISABLE_FENCING"
	disableTCMUEnvVar    = "DISABLE_TCMU"
	forceTCMUEnvVar      = "FORCE_TCMU"

	// When set to TRUE usage data will not be logged on StorageOS servers.
	disableTelemetryEnvVar = "DISABLE_TELEMETRY"

	// When set to TRUE cluster bugs will not be logged on StorageOS servers.
	disableCrashReportingEnvVar = "DISABLE_CRASH_REPORTING"

	// When set to TRUE checks for available updates will not be carried out
	// against StorageOS servers.
	disableVersionCheckEnvVar = "DISABLE_VERSION_CHECK"

	// Kubernetes namespace in which storageos operates.
	k8sNamespaceEnvVar = "K8S_NAMESPACE"

	// The kubernetes distribution in which storageos is operating.
	k8sDistroEnvVar = "K8S_DISTRO"

	// Enables the API's kubernetes specific scheduler extender endpoints.
	k8sSchedulerExtenderEnvVar = "K8S_ENABLE_SCHEDULER_EXTENDER"

	// TODO: Path to kubernetes config file.
	kubconfigPathEnvVar = "KUBECONFIG"

	// CSI API listen socket location.  CSI is disabled if not set.
	csiEndpointEnvVar = "CSI_ENDPOINT"

	// CSI version to use, if CSI_ENDPOINT is set.
	csiVersionEnvVar = "CSI_VERSION"

	// Directory in which devices are created.
	deviceDirEnvVar = "DEVICE_DIR"

	// TODO: add to StorageOSCluster CR and optionally create Certificate CR?
	// https://cert-manager.io/docs/usage/certificate/ Since secrets will be
	// used, probably needs to be implemented in DaemonSet.
	apiTLSCAEnvVar   = "API_TLS_CA"
	apiTLSKeyEnvVar  = "API_TLS_KEY"
	apiTLSCertEnvVar = "API_TLS_CERT"

	// TODO: add to StorageOSCluster CR
	// Health checking duration values
	//
	// A duration string is a possibly signed sequence of decimal numbers, each
	// with optional fraction and a unit suffix, such as "300ms", "-1.5h" or
	// "2h45m". Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
	healthProbeIntervalEnvVar = "HEALTH_PROBE_INTERVAL"
	healthProbeTimeoutEnvVar  = "HEALTH_PROBE_TIMEOUT"
	healthGracePeriodEnvVar   = "HEALTH_GRACE_PERIOD"

	// Node capacity update interval.
	nodeCapacityUpdateIntervalEnvVar = "NODE_CAPACITY_INTERVAL"

	// TODO: General dial timeout settings (RPC, etcd...)
	//
	// A duration string is a possibly signed sequence of decimal numbers, each
	// with optional fraction and a unit suffix, such as "300ms", "-1.5h" or
	// "2h45m". Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
	//
	// defaults to 5s.
	dialTimeoutEnvVar = "DIAL_TIMEOUT"

	// Logging level: debug, info, warn or error.
	logLevelEnvVar = "LOG_LEVEL"

	// Logger format: text or json.
	logFormatEnvVar = "LOG_FORMAT"

	// TODO: Jaeger Agent env vars.  Do we even want to expose this?  If we add
	// it the CR it becomes part of the public API.
	jaegerServiceNameEnvVar = "JAEGER_SERVICE_NAME"
	jaegerEndpointEnvVar    = "JAEGER_ENDPOINT"

	// Etcd TLS cert file names.
	tlsEtcdCA         = "etcd-client-ca.crt"
	tlsEtcdClientCert = "etcd-client.crt"
	tlsEtcdClientKey  = "etcd-client.key"

	// Etcd cert root path.
	tlsEtcdRootPath = "/run/storageos/pki"

	// Etcd certs volume name.
	tlsEtcdCertsVolume = "etcd-certs"
)

// createService creates a ConfigMap to store the node container configuration.
func (s *Deployment) createConfigMap() error {

	config := configFromSpec(s.stos.Spec, CSIV1Supported(s.k8sVersion), s.nodev2)

	labels := make(map[string]string)

	if err := s.k8sResourceManager.ConfigMap(configmapName, s.stos.Spec.GetResourceNS(), labels, config).Create(); err != nil {
		return err
	}

	return nil
}

func configFromSpec(spec storageosv1.StorageOSClusterSpec, csiv1 bool, nodev2 bool) map[string]string {

	config := make(map[string]string)

	// Config set in DaemonSet env vars:
	//   - HOSTNAME (reads from spec.nodeName)
	//   - ADVERTISE_IP (reads from status.podIP)
	//   - BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD (reads from secret)

	// Etcd endpoint, and join for V1.
	switch nodev2 {
	case true:
		// ETCD_ENDPOINTS must be set to a comma separated list of endpoints.
		config[etcdEndpointsEnvVar] = spec.KVBackend.Address
	case false:
		// Join must be set.
		config[joinEnvVar] = spec.Join

		// If external etcd is enabled, KV_BACKEND must be set to "etcd" and
		// KV_ADDRESS set to a comma separated list of endpoints.
		if spec.KVBackend.Backend != "" {
			config[kvBackendEnvVar] = spec.KVBackend.Backend
		}
		if spec.KVBackend.Address != "" {
			config[kvAddrEnvVar] = spec.KVBackend.Address
		}
	}

	// Append Etcd TLS config, if given.  Volumes are created in Podspec.
	if spec.TLSEtcdSecretRefName != "" && spec.TLSEtcdSecretRefNamespace != "" {
		config = addEtcdTLSConfig(config, nodev2)
	}

	// Always show telemetry and feature options to ensure they're visble.
	config[disableTelemetryEnvVar] = strconv.FormatBool(spec.DisableTelemetry)

	// TODO: separte CR items for version check and crash reports.  Use
	// Telemetry to enable/disable everything for now.
	if nodev2 {
		config[disableVersionCheckEnvVar] = strconv.FormatBool(spec.DisableTelemetry)
		config[disableCrashReportingEnvVar] = strconv.FormatBool(spec.DisableTelemetry)
	}

	// Features
	config[disableFencingEnvVar] = strconv.FormatBool(spec.DisableFencing)

	// DISABLE_TCMU and FORCE_TCMU should not be set unless under advice from
	// support.  Only show the vars if set.
	if spec.DisableTCMU {
		config[disableTCMUEnvVar] = strconv.FormatBool(spec.DisableTCMU)
	}
	if spec.ForceTCMU {
		config[forceTCMUEnvVar] = strconv.FormatBool(spec.ForceTCMU)
	}

	config[k8sNamespaceEnvVar] = spec.GetResourceNS()
	if spec.K8sDistro != "" {
		config[k8sDistroEnvVar] = spec.K8sDistro
	}

	// Since we're running in k8s, always listen on the the scheduler extender
	// api endpoints.  The feature can be disabled with the operator.  This
	// allows users to toggle the feature without restarting the cluster.
	config[k8sSchedulerExtenderEnvVar] = "true"

	// CSI is always enabled in V2, optional in V1.
	if nodev2 || spec.CSI.Enable {
		config[csiEndpointEnvVar] = spec.GetCSIEndpoint(csiv1)
		config[csiVersionEnvVar] = spec.GetCSIVersion(csiv1)
	}

	// If kubelet is running in a container, sharedDir should be set.
	if spec.SharedDir != "" {
		config[deviceDirEnvVar] = fmt.Sprintf("%s/devices", spec.SharedDir)
	}

	config[logLevelEnvVar] = "info"
	if spec.Debug {
		config[logLevelEnvVar] = debugVal
	}
	config[logFormatEnvVar] = "json"

	return config
}

// addEtcdTLSConfig adds the config entries for TLS config.  The ENV var names
// are different between V1 & V2.
func addEtcdTLSConfig(config map[string]string, v2 bool) map[string]string {

	caCert := v1EtcdTLSClientCAEnvVar
	clientKey := v1EtcdTLSClientKeyEnvVar
	clientCert := v1EtcdTLSClientCertEnvVar

	if v2 {
		caCert = v2EtcdTLSClientCAEnvVar
		clientKey = v2EtcdTLSClientKeyEnvVar
		clientCert = v2EtcdTLSClientCertEnvVar
	}

	config[caCert] = filepath.Join(tlsEtcdRootPath, tlsEtcdCA)
	config[clientKey] = filepath.Join(tlsEtcdRootPath, tlsEtcdClientKey)
	config[clientCert] = filepath.Join(tlsEtcdRootPath, tlsEtcdClientCert)

	return config
}
