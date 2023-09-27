{{- define "csi-driver-node.extensionsGroup" -}}
extensions.gardener.cloud
{{- end -}}

{{- define "csi-driver-node.name" -}}
provider-aws
{{- end -}}

{{- define "csi-driver-node.provisioner" -}}
ebs.csi.aws.com
{{- end -}}
