package nfs

import (
	"fmt"
	"strings"

	"github.com/operator-framework/operator-sdk/pkg/metrics"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/storageos/cluster-operator/pkg/storageos"
)

const (
	appName         = "storageos"
	statefulsetKind = "statefulset"

	serviceAccountPrefix = "storageos-nfs"

	// DefaultNFSPort is the default port for NFS server.
	DefaultNFSPort = 2049
	// DefaultHTTPPort is the default port for NFS server health and metrics.
	DefaultHTTPPort = 80
	// NFSPortName is the name of the port that exposes the NFS server.
	NFSPortName = "nfs"
	// MetricsPortName is the name of the port that exposes the NFS metrics.
	MetricsPortName = "metrics"

	// HealthEndpointPath is the path to query on the HTTP Port for health.
	// This is hardcoded in the NFS container and not settable by the user.
	HealthEndpointPath = "/healthz"
)

var log = logf.Log.WithName("storageos.nfsserver")

// Deploy deploys a NFS server.
func (d *Deployment) Deploy() error {
	err := d.ensureService(DefaultNFSPort)
	if err != nil {
		return err
	}

	// Create metrics service.
	// Since we use ServiceMonitor, a separate service dedicated to metrics
	// ports helps avoid Prometheus targets endpoints that don't serve metrics.
	if err := d.createMetricsService(DefaultHTTPPort); err != nil {
		return err
	}

	if err := d.createNFSConfigMap(); err != nil {
		return err
	}

	if err := d.createServiceAccountForNFSServer(); err != nil {
		return err
	}

	// Grant OpenShift SCC permission for StatefulSet using the ClusterRole
	// created for the StorageOSCluster.
	if strings.Contains(d.cluster.Spec.K8sDistro, storageos.K8SDistroOpenShift) {
		if err := d.createClusterRoleBindingForSCC(); err != nil {
			return err
		}
	}

	// Get the NFS capacity.
	requestedCapacity := d.nfsServer.Spec.GetRequestedCapacity()
	size := &requestedCapacity

	pvcVS := d.nfsServer.Spec.PersistentVolumeClaim

	// If no existing PVC Volume Source is specified in the spec, create a new
	// PVC with NFS Server name.
	if pvcVS.ClaimName == "" {
		// Create a PVC with the same name as the NFS Server.
		if err := d.createPVC(size); err != nil {
			return err
		}
		pvcVS = corev1.PersistentVolumeClaimVolumeSource{
			ClaimName: d.nfsServer.Name,
		}
	}

	// Create a StatefulSet NFS Server with PVC Volume Source.
	if err := d.createStatefulSet(&pvcVS, DefaultNFSPort, DefaultHTTPPort); err != nil {
		return err
	}

	status, err := d.getStatus()
	if err != nil {
		return err
	}

	if err := d.updateStatus(status); err != nil {
		log.Error(err, "Failed to update status")
	}

	if err := d.createServiceMonitor(); err != nil {
		// Ignore if the ServiceMonitor already exists.
		if !errors.IsAlreadyExists(err) {
			log.Error(err, "Failed to create service monitor for metrics")
		}
	}

	return nil
}

// Due to https://github.com/kubernetes/kubernetes/issues/74916 fixed in
// 1.15, labels intended for the PVC must be set on the Pod template.
// In 1.15 and later we can just set the "app" and "nfsserver" labels here.  For
// now, pass all labels rather than check k8s versions.  The only downside is
// that the nfs pod gets storageos.com labels that don't do anything directly.
func (d *Deployment) labelsForStatefulSet() map[string]string {
	// Get labels from the NFS k8s resource manager and add NFS Server specific
	// labels.
	ssLabels := d.k8sResourceManager.GetLabels()
	// TODO: This is legacy label. Remove this with care. Ensure it's not used
	// by any label selectors.
	ssLabels["app"] = appName
	ssLabels["nfsserver"] = d.nfsServer.Name

	if !d.cluster.Spec.DisableFencing {
		ssLabels["storageos.com/fenced"] = "true"
	}

	return ssLabels
}

func (d *Deployment) createClusterRoleBindingForSCC() error {
	subjects := []rbacv1.Subject{
		{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      d.getServiceAccountName(),
			Namespace: d.nfsServer.Namespace,
		},
	}
	roleRef := &rbacv1.RoleRef{
		Kind:     "ClusterRole",
		Name:     storageos.OpenShiftSCCClusterRoleName,
		APIGroup: "rbac.authorization.k8s.io",
	}
	return d.k8sResourceManager.ClusterRoleBinding(d.getClusterRoleBindingName(), nil, subjects, roleRef).Create()
}

func (d *Deployment) getClusterRoleBindingName() string {
	return fmt.Sprintf("storageos:openshift-scc-nfs-%s", d.nfsServer.Name)
}

func (d *Deployment) getServiceAccountName() string {
	return fmt.Sprintf("%s-%s", serviceAccountPrefix, d.nfsServer.Name)
}

func (d *Deployment) createServiceAccountForNFSServer() error {
	return d.k8sResourceManager.ServiceAccount(d.getServiceAccountName(), d.nfsServer.Namespace, nil).Create()
}

func (d *Deployment) createServiceMonitor() error {

	metricsService, err := d.getMetricsService()
	if err != nil {
		return err
	}

	// Create the ServiceMonitor resource for the metrics service.
	_, err = metrics.CreateServiceMonitors(d.kConfig, d.nfsServer.Namespace, []*corev1.Service{metricsService})
	if err != nil {
		return err
	}

	return nil
}
