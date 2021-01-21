{{- define "join-quotes" -}}
{{- include "join-quotes-inner" . | trimSuffix "," -}}
{{- end -}}

{{- define "join-quotes-inner" -}}
{{- range . -}}
{{ . | quote }},
{{- end -}}
{{- end -}}
