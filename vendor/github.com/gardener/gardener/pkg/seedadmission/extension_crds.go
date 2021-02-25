// Copyright (c) 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package seedadmission

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/operation/common"
)

var _ admission.Handler = &ExtensionDeletionProtection{}

// ExtensionDeletionProtection is a webhook handler validating DELETE requests for extension CRDs and extension
// resources, that are marked for deletion protection (`gardener.cloud/deletion-protected`).
type ExtensionDeletionProtection struct {
	logger  logr.Logger
	reader  client.Reader
	decoder *admission.Decoder
}

// InjectLogger inject a logger into the handler.
func (h *ExtensionDeletionProtection) InjectLogger(l logr.Logger) error {
	h.logger = l
	return nil
}

// InjectAPIReader injects a reader into the handler.
func (h *ExtensionDeletionProtection) InjectAPIReader(reader client.Reader) error {
	h.reader = reader
	return nil
}

// InjectDecoder injects a decoder capable of decoding objects included in admission requests.
func (h *ExtensionDeletionProtection) InjectDecoder(d *admission.Decoder) error {
	h.decoder = d
	return nil
}

// Handle implements the webhook handler for extension deletion protection.
func (h *ExtensionDeletionProtection) Handle(ctx context.Context, request admission.Request) admission.Response {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// If the request does not indicate the correct operation (DELETE) we allow the review without further doing.
	if request.Operation != admissionv1.Delete {
		return admission.Allowed("operation is not DELETE")
	}

	// Ignore all resources other than our expected ones
	switch request.Resource {
	case
		metav1.GroupVersionResource{Group: apiextensionsv1beta1.SchemeGroupVersion.Group, Version: apiextensionsv1beta1.SchemeGroupVersion.Version, Resource: "customresourcedefinitions"},
		metav1.GroupVersionResource{Group: apiextensionsv1.SchemeGroupVersion.Group, Version: apiextensionsv1.SchemeGroupVersion.Version, Resource: "customresourcedefinitions"},

		metav1.GroupVersionResource{Group: extensionsv1alpha1.SchemeGroupVersion.Group, Version: extensionsv1alpha1.SchemeGroupVersion.Version, Resource: "backupbuckets"},
		metav1.GroupVersionResource{Group: extensionsv1alpha1.SchemeGroupVersion.Group, Version: extensionsv1alpha1.SchemeGroupVersion.Version, Resource: "backupentries"},
		metav1.GroupVersionResource{Group: extensionsv1alpha1.SchemeGroupVersion.Group, Version: extensionsv1alpha1.SchemeGroupVersion.Version, Resource: "containerruntimes"},
		metav1.GroupVersionResource{Group: extensionsv1alpha1.SchemeGroupVersion.Group, Version: extensionsv1alpha1.SchemeGroupVersion.Version, Resource: "controlplanes"},
		metav1.GroupVersionResource{Group: extensionsv1alpha1.SchemeGroupVersion.Group, Version: extensionsv1alpha1.SchemeGroupVersion.Version, Resource: "extensions"},
		metav1.GroupVersionResource{Group: extensionsv1alpha1.SchemeGroupVersion.Group, Version: extensionsv1alpha1.SchemeGroupVersion.Version, Resource: "infrastructures"},
		metav1.GroupVersionResource{Group: extensionsv1alpha1.SchemeGroupVersion.Group, Version: extensionsv1alpha1.SchemeGroupVersion.Version, Resource: "networks"},
		metav1.GroupVersionResource{Group: extensionsv1alpha1.SchemeGroupVersion.Group, Version: extensionsv1alpha1.SchemeGroupVersion.Version, Resource: "operatingsystemconfigs"},
		metav1.GroupVersionResource{Group: extensionsv1alpha1.SchemeGroupVersion.Group, Version: extensionsv1alpha1.SchemeGroupVersion.Version, Resource: "workers"}:
	default:
		return admission.Allowed("resource is not deletion-protected")
	}

	obj, err := getRequestObject(ctx, h.reader, h.decoder, request)
	if apierrors.IsNotFound(err) {
		return admission.Allowed("object was not found")
	}
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	var operation string
	if strings.HasSuffix(obj.GetObjectKind().GroupVersionKind().Kind, "List") {
		operation = "DELETECOLLECTION"
	} else {
		operation = "DELETE"
	}

	log := h.logger.
		WithValues("resource", request.Resource).
		WithValues("operation", operation).
		WithValues("namespace", request.Namespace)

	log.Info("Handling request")

	if err := admitObjectDeletion(log, obj, request.Kind.Kind); err != nil {
		return admission.Denied(err.Error())
	}
	return admission.Allowed("")
}

// admitObjectDeletion checks if the object deletion is confirmed. If the given object is a list of objects then it
// performs the check for every single object.
func admitObjectDeletion(log logr.Logger, obj runtime.Object, kind string) error {
	if strings.HasSuffix(obj.GetObjectKind().GroupVersionKind().Kind, "List") {
		return meta.EachListItem(obj, func(o runtime.Object) error {
			return checkIfObjectDeletionIsConfirmed(log, o, kind)
		})
	}
	return checkIfObjectDeletionIsConfirmed(log, obj, kind)
}

// checkIfObjectDeletionIsConfirmed checks if the object was annotated with the deletion confirmation. If it is a custom
// resource definition then it is only considered if the CRD has the deletion protection label.
func checkIfObjectDeletionIsConfirmed(log logr.Logger, object runtime.Object, kind string) error {
	obj, ok := object.(client.Object)
	if !ok {
		return fmt.Errorf("%T does not implement client.Object", object)
	}

	log = log.WithValues("name", obj.GetName())

	if kind == "CustomResourceDefinition" && !crdMustBeConsidered(log, obj.GetLabels()) {
		return nil
	}

	if err := common.CheckIfDeletionIsConfirmed(obj); err != nil {
		log.Info("Deletion is not confirmed - preventing deletion")
		return err
	}

	log.Info("Deletion is confirmed - allowing deletion")
	return nil
}

// TODO: This function can be removed once the minimum seed Kubernetes version is bumped to >= 1.15. In 1.15, webhook
// configurations may use object selectors, i.e., we can get rid of this custom filtering.
func crdMustBeConsidered(log logr.Logger, labels map[string]string) bool {
	val, ok := labels[common.GardenerDeletionProtected]
	if !ok {
		log.Info("Ignoring CRD because it has no " + common.GardenerDeletionProtected + " label - allowing deletion")
		return false
	}

	if ok, _ := strconv.ParseBool(val); !ok {
		log.Info("Admitting CRD deletion because " + common.GardenerDeletionProtected + " label value is not true - allowing deletion")
		return false
	}

	return true
}
