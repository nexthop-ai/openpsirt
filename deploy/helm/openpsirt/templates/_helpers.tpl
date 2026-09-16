{{- define "openpsirt.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "openpsirt.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "openpsirt.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "openpsirt.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "openpsirt.selectorLabels" -}}
app.kubernetes.io/name: {{ include "openpsirt.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "openpsirt.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "openpsirt.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Where a secret value comes from: a Secret the operator manages, or one the
chart creates from a value. One pair for all four, because the answer differs
by which of those it is rather than by which value it holds — and a Secret the
chart created carries a key of the chart's own, so consulting the operator's
key name for it asks for a key that is not there.

Called with the values block holding existingSecret and existingSecretKey, the
suffix the chart names its own Secret with, and the key it writes there.
*/}}
{{- define "openpsirt.secretName" -}}
{{- if .source.existingSecret }}
{{- .source.existingSecret }}
{{- else }}
{{- printf "%s-%s" (include "openpsirt.fullname" .top) .suffix }}
{{- end }}
{{- end }}

{{- define "openpsirt.secretKey" -}}
{{- if .source.existingSecret }}
{{- .source.existingSecretKey }}
{{- else }}
{{- .key }}
{{- end }}
{{- end }}
