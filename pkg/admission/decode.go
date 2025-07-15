// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package admission

import (
	"github.com/gardener/gardener/extensions/pkg/util"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// DecodeWorkloadIdentityConfig decodes the `WorkloadIdentityConfig` from the given `RawExtension`.
func DecodeWorkloadIdentityConfig(decoder runtime.Decoder, config *runtime.RawExtension) (*aws.WorkloadIdentityConfig, error) {
	workloadIdentityConfig := &aws.WorkloadIdentityConfig{}
	if err := util.Decode(decoder, config.Raw, workloadIdentityConfig); err != nil {
		return nil, err
	}

	return workloadIdentityConfig, nil
}
