{{- define "flowsight.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "flowsight.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "flowsight.labels" -}}
app.kubernetes.io/name: {{ include "flowsight.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "flowsight.selector" -}}
app.kubernetes.io/name: {{ include "flowsight.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* The Secret holding the token, when there is one. */}}
{{- define "flowsight.secretName" -}}
{{- if .Values.apiToken.existingSecret -}}
{{- .Values.apiToken.existingSecret -}}
{{- else if .Values.apiToken.value -}}
{{- include "flowsight.fullname" . -}}
{{- end -}}
{{- end -}}
