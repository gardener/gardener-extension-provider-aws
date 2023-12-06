# Using IPv4/IPv6 (dual-stack) Ingress in an IPv4 single-stack cluster

## Motivation

IPv6 adoption is continuously growing, already overtaking IPv4 in certain regions, e.g. India, or scenarios, e.g. mobile.
Even though most IPv6 installations deploy means to reach IPv4, it might still be beneficial to expose services
natively via IPv4 and IPv6 instead of just relying on IPv4.

## Disadvantages of full IPv4/IPv6 (dual-stack) Deployments

Enabling full IPv4/IPv6 (dual-stack) support in a kubernetes cluster is a major endeavor. It requires a lot of changes
and restarts of all pods so that all pods get addresses for both IP families. A side-effect of dual-stack networking
is that failures may be hidden as network traffic may take the other protocol to reach the target. For this reason and
also due to reduced operational complexity, service teams might lean towards staying in a single-stack environment as
much as possible. Luckily, this is possible with Gardener and IPv4/IPv6 (dual-stack) ingress on AWS.

## Simplifying IPv4/IPv6 (dual-stack) Ingress with Protocol Translation on AWS

Fortunately, the network load balancer on AWS supports automatic protocol translation, i.e. it can expose both IPv4 and
IPv6 endpoints while communicating with just one protocol to the backends. Under the hood, automatic protocol translation
takes place. Client IP address preservation can be achieved by using proxy protocol.

This approach enables users to expose IPv4 workload to IPv6-only clients without having to change the workload/service.
Without requiring invasive changes, it allows a fairly simple first step into the IPv6 world for services just requiring
ingress (incoming) communication.

## Necessary Shoot Cluster Configuration Changes for IPv4/IPv6 (dual-stack) Ingress

To be able to utilize IPv4/IPv6 (dual-stack) Ingress in an IPv4 shoot cluster, the cluster needs to meet two preconditions:
1. `dualStack.enabled` needs to be set to `true` to configure VPC/subnet for IPv6 and add a routing rule for IPv6.
   (This does not add IPv6 addresses to kubernetes nodes.)
2. `loadBalancerController.enabled` needs to be set to `true` as well to use the load balancer controller, which supports
   dual-stack ingress.

```yaml
apiVersion: core.gardener.cloud/v1beta1
kind: Shoot
...
spec:
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      dualStack:
        enabled: true
    controlPlaneConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: ControlPlaneConfig
      loadBalancerController:
        enabled: true
...
```

After adapting the shoot specification and reconciling the cluster, dual-stack load balancers can be created using
kubernetes services objects.

## Creating an IPv4/IPv6 (dual-stack) Ingress

With the preconditions set, creating an IPv4/IPv6 load balancer is as easy as annotating a service with the correct
annotations:

```yaml
apiVersion: v1
kind: Service
metadata:
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-ip-address-type: dualstack
    service.beta.kubernetes.io/aws-load-balancer-scheme: internet-facing
    service.beta.kubernetes.io/aws-load-balancer-nlb-target-type: instance
    service.beta.kubernetes.io/aws-load-balancer-type: external
  name: ...
  namespace: ...
spec:
  ...
  type: LoadBalancer
```

In case the client IP address should be preserved, the following annotation can be used to enable proxy protocol.
(The pod receiving the traffic needs to be configured for proxy protocol as well.)

```yaml
    service.beta.kubernetes.io/aws-load-balancer-proxy-protocol: "*"
```

Please note that changing an existing `Service` to dual-stack may cause the creation of a new load balancer without
deletion of the old AWS load balancer resource. While this helps in a seamless migration by not cutting existing
connections it may lead to wasted/forgotten resources. Therefore, the (manual) cleanup needs to be taken into account
when migrating an existing `Service` instance.

For more details see [AWS Load Balancer Documentation - Network Load Balancer](https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.4/guide/service/nlb/).
