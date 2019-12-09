package scheduler

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/storageos/cluster-operator/internal/pkg/crv01/runtime/inject"
	"github.com/storageos/cluster-operator/internal/pkg/crv01/webhook/admission"
	"github.com/storageos/cluster-operator/internal/pkg/crv01/webhook/admission/types"
	"github.com/storageos/cluster-operator/internal/pkg/storageoscluster"
)

// PodSchedulerSetter is responsible for mutating and setting pod scheduler
// name.
type PodSchedulerSetter struct {
	client  client.Client
	decoder types.Decoder
	// Provisioners is a list of storage provisioners to check a pod volume
	// against.
	Provisioners []string
	// SchedulerName is the name of the scheduler to mutate pods with.
	SchedulerName string
	// SchedulerAnnotationKey is the pod annotation that can be set to skip or
	// apply the mutation.
	SchedulerAnnotationKey string
}

// Check if the Handler interface is implemented.
var _ admission.Handler = &PodSchedulerSetter{}

// Handle handles an admission request and mutates a pod object in the request.
func (p *PodSchedulerSetter) Handle(ctx context.Context, req types.Request) types.Response {
	// NOTE: Since this webhook handler is built from an internal copy of
	// controller-runtime webhook, the webhook admission decoder in the
	// controller manager doesn't get translated to the internal webhook
	// admission decoder correctly. As a workaround, since this handler is for
	// pods only, use client-go's default scheme to create a new decoder.
	// Client-go's default scheme contains pod scheme.
	if p.decoder == nil {
		decoder, err := admission.NewDecoder(kscheme.Scheme)
		if err != nil {
			log.Printf("failed to create a new decoder for the webhook handler: %v", err)
			return admission.ErrorResponse(http.StatusInternalServerError, err)
		}
		p.decoder = decoder
	}
	// Decode the pod in request to a pod variable.
	pod := &corev1.Pod{}
	if err := p.decoder.Decode(req, pod); err != nil {
		return admission.ErrorResponse(http.StatusBadRequest, err)
	}
	// Get the request namespace. This is needed because sometimes the decoded
	// pod object lacks namespace info.
	namespace := req.AdmissionRequest.Namespace

	// Create a copy of the pod to mutate.
	copy := pod.DeepCopy()
	if err := p.mutatePodsFn(ctx, copy, namespace); err != nil {
		// TODO: Add support for structured logging in this package.
		log.Printf("failed to mutate pod: %v", err)
		return admission.ErrorResponse(http.StatusInternalServerError, err)
	}
	return admission.PatchResponse(pod, copy)
}

// mutatePodFn mutates a given pod with a configured scheduler name if the pod
// is associated with volumes managed by the configured provisioners.
func (p *PodSchedulerSetter) mutatePodsFn(ctx context.Context, pod *corev1.Pod, namespace string) error {
	// Skip mutation if the pod annotation has false schedule annotation.
	if val, exists := pod.ObjectMeta.Annotations[p.SchedulerAnnotationKey]; exists {
		boolVal, err := strconv.ParseBool(val)
		// No error in parsing and the value is false, skip the pod.
		if err == nil && !boolVal {
			return nil
		}
	}

	managedVols := []corev1.Volume{}

	// Find all the managed volumes.
	for _, vol := range pod.Spec.Volumes {
		ok, err := p.IsManagedVolume(vol, namespace)
		if err != nil {
			return fmt.Errorf("failed to determine if the volume is managed: %v", err)
		}
		if ok {
			managedVols = append(managedVols, vol)
		}
	}

	// Set scheduler name only if there are managed volumes.
	if len(managedVols) > 0 {
		// Check if StorageOS scheduler is enabled before setting the scheduler.
		cluster, err := storageoscluster.GetCurrentStorageOSCluster(p.client)
		if err != nil {
			return err
		}
		if !cluster.Spec.DisableScheduler {
			pod.Spec.SchedulerName = p.SchedulerName
		}
	}

	return nil
}

// Check if the Client interface is implemented.
var _ inject.Client = &PodSchedulerSetter{}

// InjectClient injects a client into object.
func (p *PodSchedulerSetter) InjectClient(c client.Client) error {
	p.client = c
	return nil
}

// Check if the Decoder interface is implemented.
var _ inject.Decoder = &PodSchedulerSetter{}

// InjectDecoder injects a decoder into the object.
func (p *PodSchedulerSetter) InjectDecoder(d types.Decoder) error {
	p.decoder = d
	return nil
}
