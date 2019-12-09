package nfsserver

import (
	"context"
	goerrors "errors"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/storageos/cluster-operator/internal/pkg/storageoscluster"
	storageosv1 "github.com/storageos/cluster-operator/pkg/apis/storageos/v1"
	stosClientset "github.com/storageos/cluster-operator/pkg/client/clientset/versioned"
	"github.com/storageos/cluster-operator/pkg/nfs"
	"github.com/storageos/cluster-operator/pkg/util/k8s"
)

// ErrNoCluster is the error when there's no associated running StorageOS
// cluster found for NFS server.
var ErrNoCluster = goerrors.New("no storageos cluster found")

var log = logf.Log.WithName("controller_nfsserver")

const (
	finalizer    = "finalizer.nfsserver.storageos.com"
	appComponent = "nfs-server"
)

// Add creates a new NFSServer Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	storageos := stosClientset.NewForConfigOrDie(mgr.GetConfig())
	return &ReconcileNFSServer{
		client:        mgr.GetClient(),
		kConfig:       mgr.GetConfig(),
		scheme:        mgr.GetScheme(),
		recorder:      mgr.GetEventRecorderFor("storageos-nfsserver"),
		stosClientset: storageos,
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("nfsserver-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource NFSServer.
	err = c.Watch(&source.Kind{Type: &storageosv1.NFSServer{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// Watch for changes to secondary resource StatefulSet and requeue the owner
	// NFSServer.
	err = c.Watch(&source.Kind{Type: &appsv1.StatefulSet{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &storageosv1.NFSServer{},
	})
	if err != nil {
		return err
	}

	// Watch for changes to secondary resource Service and requeue the owner
	// NFSServer.
	//
	// This is used to update the NFSServer Status with the connection endpoint
	// once it comes online.
	err = c.Watch(&source.Kind{Type: &corev1.Service{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &storageosv1.NFSServer{},
	})
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcileNFSServer implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileNFSServer{}

// ReconcileNFSServer reconciles a NFSServer object
type ReconcileNFSServer struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client        client.Client
	stosClientset stosClientset.Interface
	scheme        *runtime.Scheme
	recorder      record.EventRecorder
	// k8s rest config is needed for creating a k8s discovery client, used by
	// the osdk's metrics helpers to create Prometheus ServiceMonitor for NFS
	// Server.
	kConfig *rest.Config
}

// Reconcile reads that state of the cluster for a NFSServer object and makes changes based on the state read
// and what is in the NFSServer.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileNFSServer) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	// reqLogger.Info("Reconciling NFSServer")

	reconcilePeriod := 15 * time.Second
	reconcileResult := reconcile.Result{RequeueAfter: reconcilePeriod}

	// Fetch the NFSServer instance
	instance := &storageosv1.NFSServer{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcileResult, err
	}

	if err := r.reconcile(instance); err != nil {
		reqLogger.Info("Reconcile failed", "error", err)
		return reconcileResult, nil
	}

	return reconcileResult, nil
}

func (r *ReconcileNFSServer) reconcile(instance *storageosv1.NFSServer) error {
	// Add our finalizer immediately so we can cleanup a partial deployment.  If
	// this is not set, the CR can simply be deleted.
	if len(instance.GetFinalizers()) == 0 {

		// Add our finalizer so that we control deletion.
		if err := r.addFinalizer(instance); err != nil {
			return err
		}

		// Return here, as the update to add the finalizer will trigger another
		// reconcile.
		return nil
	}

	// Get a StorageOS cluster to associate the NFS server with.
	stosCluster, err := storageoscluster.GetCurrentStorageOSCluster(r.client)
	if err != nil {
		return err
	}

	// Update NFS spec with values inferred from the StorageOS cluster.
	updated, err := r.updateSpec(instance, stosCluster)
	if err != nil {
		return err
	}

	// Return here if the CR has been updated as the current instance is
	// outdated.
	if updated {
		return nil
	}

	// Prepare for NFS deployment.

	// Labels to be applied on all the k8s resources that are created for NFS
	// server. Inherit the labels from the CR.
	labels := instance.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	// Add default labels.
	// TODO: This is legacy label. Remove this with care. Ensure it's not used
	// by any label selectors.
	labels["app"] = "storageos"

	// Set the app component.
	labels[k8s.AppComponent] = appComponent

	// Add default resource app labels.
	labels = k8s.AddDefaultAppLabels(stosCluster.Name, labels)

	d := nfs.NewDeployment(r.client, r.kConfig, stosCluster, instance, labels, r.recorder, r.scheme)

	// If the CR has not been marked for deletion, ensure it is deployed.
	if instance.GetDeletionTimestamp() == nil {
		if err := d.Deploy(); err != nil {
			// Ignore "Operation cannot be fulfilled" error. It happens when the
			// actual state of object is different from what is known to the operator.
			// Operator would resync and retry the failed operation on its own.
			if !strings.HasPrefix(err.Error(), "Operation cannot be fulfilled") {
				r.recorder.Event(instance, corev1.EventTypeWarning, "FailedCreation", err.Error())
			}
			return err
		}
	} else {
		// Delete the deployment once the finalizers are set on the cluster
		// resource.
		r.recorder.Event(instance, corev1.EventTypeNormal, "Terminating", "Deleting the NFS server.")

		if err := d.Delete(); err != nil {
			return err
		}

		// Reset finalizers and let k8s delete the object.
		// When finalizers are set on an object, metadata.deletionTimestamp is
		// also set. deletionTimestamp helps the garbage collector identify
		// when to delete an object. k8s deletes the object only once the
		// list of finalizers is empty.
		instance.SetFinalizers([]string{})
		return r.client.Update(context.Background(), instance)
	}

	return nil
}

func (r *ReconcileNFSServer) addFinalizer(instance *storageosv1.NFSServer) error {

	instance.SetFinalizers(append(instance.GetFinalizers(), finalizer))

	// Update CR
	err := r.client.Update(context.TODO(), instance)
	if err != nil {
		return err
	}
	return nil
}

// updateSpec takes a NFSServer CR and a StorageOSCluster CR and updates
// NFSServer if needed. It returns true if there was an update. This result can
// be used to decide if the caller should continue with reconcile or return from
// reconcile due to an outdated CR instance.
func (r *ReconcileNFSServer) updateSpec(instance *storageosv1.NFSServer, cluster *storageosv1.StorageOSCluster) (bool, error) {
	needUpdate := false

	// Check if any CR property needs to be updated.

	sc := instance.Spec.GetStorageClassName(cluster.Spec.GetStorageClassName())
	if instance.Spec.StorageClassName != sc {
		instance.Spec.StorageClassName = sc
		needUpdate = true
	}

	image := instance.Spec.GetContainerImage(cluster.Spec.GetNFSServerImage())
	if instance.Spec.NFSContainer != image {
		instance.Spec.NFSContainer = image
		needUpdate = true
	}

	if needUpdate {
		// Update CR.
		err := r.client.Update(context.TODO(), instance)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func remove(list []string, s string) []string {
	for i, v := range list {
		if v == s {
			list = append(list[:i], list[i+1:]...)
		}
	}
	return list
}
