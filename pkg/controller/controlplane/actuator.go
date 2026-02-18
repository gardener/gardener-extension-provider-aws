// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"encoding/json"
	"fmt"

	extensionsconfigv1alpha1 "github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1"
	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/controlplane"
	"github.com/gardener/gardener/extensions/pkg/util"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	admissionregistrationv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	// NetworkUnavailableConditionType is the type of the NetworkUnavailable condition
	NetworkUnavailableConditionType = "NetworkUnavailable"
	// CalicoIsUpReason is the reason set by Calico when it sets the NetworkUnavailable condition to indicate Calico is up
	CalicoIsUpReason = "CalicoIsUp"
	// CalicoIsDownReason is the reason set by Calico when it sets the NetworkUnavailable condition to indicate Calico is down
	CalicoIsDownReason = "CalicoIsDown"
	// MutatingAdmissionPolicyName is the name of the MutatingAdmissionPolicy
	MutatingAdmissionPolicyName = "block-calico-network-unavailable"
	// MutatingAdmissionPolicyBindingName is the name of the MutatingAdmissionPolicyBinding
	MutatingAdmissionPolicyBindingName = "block-calico-network-unavailable-binding"
	// AnnotationCalicoCleanupCompleted indicates that Calico condition cleanup has been completed
	AnnotationCalicoCleanupCompleted = "aws.provider.extensions.gardener.cloud/calico-cleanup-completed"
)

// NewActuator creates a new Actuator that wraps the generic actuator and adds cleanup logic.
func NewActuator(mgr manager.Manager, a controlplane.Actuator) controlplane.Actuator {
	return &actuator{
		Actuator: a,
		client:   mgr.GetClient(),
	}
}

// actuator is an Actuator that acts upon and updates the status of ControlPlane resources.
type actuator struct {
	controlplane.Actuator
	client client.Client
}

func (a *actuator) Reconcile(
	ctx context.Context,
	log logr.Logger,
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
) (bool, error) {
	// Call Reconcile on the composed Actuator
	ok, err := a.Actuator.Reconcile(ctx, log, cp, cluster)
	if err != nil {
		return ok, err
	}

	// Only clean up NetworkUnavailable conditions if overlay is disabled
	overlayEnabled, err := a.isOverlayEnabled(cluster.Shoot.Spec.Networking)
	if err != nil {
		log.Error(err, "Failed to determine if overlay is enabled")
		return ok, nil
	}

	// Check if MutatingAdmissionPolicy should be enabled
	mapEnabled := isMutatingAdmissionPolicyEnabled(cluster)

	// Clean up MutatingAdmissionPolicy resources if overlay is enabled OR if they should not be deployed
	// When overlay is enabled, the policy is no longer needed regardless of other conditions
	if overlayEnabled || !mapEnabled {
		if err := a.cleanupMutatingAdmissionPolicy(ctx, log, cp.Namespace, cluster); err != nil {
			log.Error(err, "Failed to cleanup MutatingAdmissionPolicy resources")
			// Don't fail the reconciliation if cleanup fails
		}
	}

	// Clean up NetworkUnavailable conditions set by Calico only when overlay is disabled
	// Only run cleanup if it hasn't been completed yet (annotation not present)
	if !overlayEnabled && cp.Annotations[AnnotationCalicoCleanupCompleted] != "true" {
		if err := a.cleanupCalicoNetworkUnavailableConditions(ctx, log, cp.Namespace, cluster); err != nil {
			log.Error(err, "Failed to cleanup Calico NetworkUnavailable conditions")
			// Don't fail the reconciliation if cleanup fails
		} else {
			// Mark cleanup as completed
			if err := a.markCleanupCompleted(ctx, cp); err != nil {
				log.Error(err, "Failed to mark cleanup as completed")
			}
		}
	}

	// Remove cleanup annotation when overlay is enabled so cleanup can run again if overlay is disabled later
	if overlayEnabled && cp.Annotations[AnnotationCalicoCleanupCompleted] == "true" {
		if err := a.removeCleanupAnnotation(ctx, cp); err != nil {
			log.Error(err, "Failed to remove cleanup annotation")
		}
	}

	return ok, nil
}

// cleanupCalicoNetworkUnavailableConditions removes NetworkUnavailable conditions from nodes
// that were set by Calico (identified by reason "CalicoIsUp").
func (a *actuator) cleanupCalicoNetworkUnavailableConditions(
	ctx context.Context,
	log logr.Logger,
	namespace string,
	cluster *extensionscontroller.Cluster,
) error {
	if extensionscontroller.IsHibernated(cluster) {
		return nil
	}

	_, shootClient, err := util.NewClientForShoot(ctx, a.client, namespace, client.Options{}, extensionsconfigv1alpha1.RESTOptions{})
	if err != nil {
		return fmt.Errorf("could not create shoot client: %w", err)
	}

	nodes := &corev1.NodeList{}
	if err := shootClient.List(ctx, nodes); err != nil {
		return fmt.Errorf("could not list nodes in shoot cluster: %w", err)
	}

	for _, node := range nodes.Items {
		if err := a.cleanupNodeNetworkUnavailableCondition(ctx, log, shootClient, &node); err != nil {
			log.Error(err, "Failed to cleanup NetworkUnavailable condition from node", "node", node.Name)
			// Continue with other nodes even if one fails
		}
	}

	return nil
}

// cleanupNodeNetworkUnavailableCondition removes the NetworkUnavailable condition from a node
// if it was set by Calico.
func (a *actuator) cleanupNodeNetworkUnavailableCondition(
	ctx context.Context,
	log logr.Logger,
	shootClient client.Client,
	node *corev1.Node,
) error {
	// Check if the node has a NetworkUnavailable condition set by Calico
	hasCondition := false
	for _, condition := range node.Status.Conditions {
		if condition.Type == NetworkUnavailableConditionType &&
			(condition.Reason == CalicoIsUpReason || condition.Reason == CalicoIsDownReason) {
			hasCondition = true
			break
		}
	}

	if !hasCondition {
		return nil
	}

	// Remove the NetworkUnavailable condition
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Get the latest version of the node
		currentNode := &corev1.Node{}
		if err := shootClient.Get(ctx, client.ObjectKey{Name: node.Name}, currentNode); err != nil {
			return err
		}

		// Filter out the NetworkUnavailable condition set by Calico
		var newConditions []corev1.NodeCondition
		removed := false
		for _, condition := range currentNode.Status.Conditions {
			if condition.Type == NetworkUnavailableConditionType &&
				(condition.Reason == CalicoIsUpReason || condition.Reason == CalicoIsDownReason) {
				removed = true
				log.Info("Removing NetworkUnavailable condition set by Calico", "node", currentNode.Name, "reason", condition.Reason)
				continue
			}
			newConditions = append(newConditions, condition)
		}

		// Only update if we actually removed a condition
		if !removed {
			return nil
		}

		currentNode.Status.Conditions = newConditions
		return shootClient.Status().Update(ctx, currentNode)
	})
}

// isOverlayEnabled checks if overlay networking is enabled in the cluster's network configuration.
func (a *actuator) isOverlayEnabled(network *gardencorev1beta1.Networking) (bool, error) {
	if network == nil || network.ProviderConfig == nil {
		return true, nil
	}

	// should not happen in practice because we will receive a RawExtension with Raw populated in production.
	networkProviderConfig, err := network.ProviderConfig.MarshalJSON()
	if err != nil {
		return false, err
	}

	if string(networkProviderConfig) == "null" {
		return true, nil
	}

	var networkConfig map[string]interface{}
	if err := json.Unmarshal(networkProviderConfig, &networkConfig); err != nil {
		return false, err
	}

	if overlay, ok := networkConfig["overlay"].(map[string]interface{}); ok {
		return overlay["enabled"].(bool), nil
	}

	return true, nil
}

// cleanupMutatingAdmissionPolicy removes MutatingAdmissionPolicy resources from the shoot cluster
// when they are no longer needed (e.g., when overlay is enabled or feature is disabled).
func (a *actuator) cleanupMutatingAdmissionPolicy(
	ctx context.Context,
	log logr.Logger,
	namespace string,
	cluster *extensionscontroller.Cluster,
) error {
	if extensionscontroller.IsHibernated(cluster) {
		return nil
	}

	_, shootClient, err := util.NewClientForShoot(ctx, a.client, namespace, client.Options{}, extensionsconfigv1alpha1.RESTOptions{})
	if err != nil {
		return fmt.Errorf("could not create shoot client: %w", err)
	}

	policy := &admissionregistrationv1alpha1.MutatingAdmissionPolicy{}
	policy.Name = MutatingAdmissionPolicyName
	if err := shootClient.Delete(ctx, policy); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("could not delete MutatingAdmissionPolicy: %w", err)
		}
	} else {
		log.Info("Successfully deleted MutatingAdmissionPolicy", "name", MutatingAdmissionPolicyName)
	}

	binding := &admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding{}
	binding.Name = MutatingAdmissionPolicyBindingName
	if err := shootClient.Delete(ctx, binding); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("could not delete MutatingAdmissionPolicyBinding: %w", err)
		}
	} else {
		log.Info("Successfully deleted MutatingAdmissionPolicyBinding", "name", MutatingAdmissionPolicyBindingName)
	}

	return nil
}

// markCleanupCompleted marks the cleanup as completed by adding an annotation to the ControlPlane resource.
func (a *actuator) markCleanupCompleted(ctx context.Context, cp *extensionsv1alpha1.ControlPlane) error {
	patch := client.MergeFrom(cp.DeepCopy())
	if cp.Annotations == nil {
		cp.Annotations = make(map[string]string)
	}
	cp.Annotations[AnnotationCalicoCleanupCompleted] = "true"
	return a.client.Patch(ctx, cp, patch)
}

// removeCleanupAnnotation removes the cleanup completion annotation from the ControlPlane resource.
func (a *actuator) removeCleanupAnnotation(ctx context.Context, cp *extensionsv1alpha1.ControlPlane) error {
	patch := client.MergeFrom(cp.DeepCopy())
	delete(cp.Annotations, AnnotationCalicoCleanupCompleted)
	return a.client.Patch(ctx, cp, patch)
}
