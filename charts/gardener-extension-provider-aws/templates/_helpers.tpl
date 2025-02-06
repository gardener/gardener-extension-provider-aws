{{- define "name" -}}
gardener-extension-provider-aws
{{- end -}}

{{- define "labels.app.key" -}}
app.kubernetes.io/name
{{- end -}}
{{- define "labels.app.value" -}}
{{ include "name" . }}
{{- end -}}

{{- define "labels" -}}
{{ include "labels.app.key" . }}: {{ include "labels.app.value" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{-  define "image" -}}
  {{- if hasPrefix "sha256:" .Values.image.tag }}
  {{- printf "%s@%s" .Values.image.repository .Values.image.tag }}
  {{- else }}
  {{- printf "%s:%s" .Values.image.repository .Values.image.tag }}
  {{- end }}
{{- end }}

{{- define "images.alpine" -}}
    {{- if .Values.images.alpine }}
      {{- .Values.images.alpine }}
    {{- else }}
      {{- include "image.alpine" .  }}
    {{- end }}
{{- end }}

{{- define "images.pause" -}}
    {{- if .Values.images.pause }}
      {{- .Values.images.pause }}
    {{- else }}
      {{- include "image.pause" .  }}
    {{- end }}
{{- end -}}

{{- define "deploymentversion" -}}
apps/v1
{{- end -}}

{{- define "topologyAwareRouting.enabled" -}}
  {{- if .Values.gardener.seed }}
{{- .Values.gardener.seed.spec.settings.topologyAwareRouting.enabled }}
  {{- else -}}
false
  {{- end }}
{{- end -}}

{{- define "seed.provider" -}}
  {{- if .Values.gardener.seed }}
{{- .Values.gardener.seed.provider }}
  {{- else -}}
""
  {{- end }}
{{- end -}}

{{- define "runtimeCluster.enabled" -}}
  {{- if .Values.gardener.runtimeCluster }}
{{- .Values.gardener.runtimeCluster.enabled }}
  {{- else -}}
false
  {{- end }}
{{- end -}}
