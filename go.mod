module github.com/gardener/gardener-extension-provider-aws

go 1.15

require (
	github.com/ahmetb/gen-crd-api-reference-docs v0.2.0
	github.com/aws/aws-sdk-go v1.21.10
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/coreos/go-systemd/v22 v22.1.0
	github.com/dsnet/compress v0.0.1 // indirect
	github.com/frankban/quicktest v1.9.0 // indirect
	github.com/gardener/etcd-druid v0.3.0
	github.com/gardener/gardener v1.15.0
	github.com/gardener/machine-controller-manager v0.33.0
	github.com/go-logr/logr v0.1.0
	github.com/gobuffalo/packr/v2 v2.8.1
	github.com/golang/mock v1.4.4-0.20200731163441-8734ec565a4d
	github.com/golang/snappy v0.0.2 // indirect
	github.com/google/go-cmp v0.4.1 // indirect
	github.com/nwaples/rardecode v1.1.0 // indirect
	github.com/onsi/ginkgo v1.14.0
	github.com/onsi/gomega v1.10.1
	github.com/pierrec/lz4 v2.4.1+incompatible // indirect
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/cobra v0.0.6
	github.com/spf13/pflag v1.0.5
	github.com/ulikunitz/xz v0.5.7 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	k8s.io/api v0.18.10
	k8s.io/apiextensions-apiserver v0.18.10
	k8s.io/apimachinery v0.18.10
	k8s.io/apiserver v0.18.10
	k8s.io/autoscaler v0.0.0-20190805135949-100e91ba756e
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/code-generator v0.18.10
	k8s.io/component-base v0.18.10
	k8s.io/gengo v0.0.0-20200413195148-3a45101e95ac
	k8s.io/klog v1.0.0
	k8s.io/kubelet v0.18.10
	k8s.io/utils v0.0.0-20200619165400-6e3d28b6ed19
	sigs.k8s.io/controller-runtime v0.6.3
)

replace (
	github.com/gardener/gardener => github.com/rfranzke/gardener v0.0.0-20210104171158-e39ac8ebda04
	github.com/prometheus/client_golang => github.com/prometheus/client_golang v0.9.2
	k8s.io/api => k8s.io/api v0.18.10
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.18.10
	k8s.io/apimachinery => k8s.io/apimachinery v0.18.10
	k8s.io/apiserver => k8s.io/apiserver v0.18.10
	k8s.io/client-go => k8s.io/client-go v0.18.10
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.18.10
	k8s.io/code-generator => k8s.io/code-generator v0.18.10
	k8s.io/component-base => k8s.io/component-base v0.18.10
	k8s.io/helm => k8s.io/helm v2.13.1+incompatible
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.18.10
)
