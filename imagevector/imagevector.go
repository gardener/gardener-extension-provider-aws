// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package imagevector

import (
	_ "embed"

	"github.com/gardener/gardener/pkg/utils/imagevector"
	"k8s.io/apimachinery/pkg/util/runtime"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

// ImagesYAML contains the content of the images.yaml file
//
//go:embed images.yaml
var imagesYAML string
var imageVector imagevector.ImageVector

func init() {
	var err error

	imageVector, err = imagevector.Read([]byte(imagesYAML))
	runtime.Must(err)

	imageVector, err = imagevector.WithEnvOverride(imageVector, imagevector.OverrideEnv)
	runtime.Must(err)
}

// ImageVector is the image vector that contains all the needed images.
func ImageVector() imagevector.ImageVector {
	return imageVector
}

// TerraformerImage returns the Terraformer image.
func TerraformerImage() string {
	image, err := imageVector.FindImage(aws.TerraformerImageName)
	runtime.Must(err)
	return image.String()
}
