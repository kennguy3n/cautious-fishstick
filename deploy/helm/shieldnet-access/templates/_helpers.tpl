{{/*
Common helpers for the shieldnet-access chart. The templates below
generate consistent names, labels, and per-service image refs so
every Deployment/Service/ConfigMap stays in sync without copy-paste.
*/}}

{{/* The release-wide name, capped at 63 chars (DNS label limit). */}}
{{- define "shieldnet-access.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* Standard chart labels applied to every resource. */}}
{{- define "shieldnet-access.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: shieldnet-access
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{/* Per-service selector labels. Call with (dict "name" "ztna-api" "ctx" .). */}}
{{- define "shieldnet-access.selectorLabels" -}}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
{{- end -}}

{{/* Resolve the image for a given service. The per-service tag
overrides fall back to .Chart.AppVersion. Call with
(dict "service" "ztna-api" "tag" "" "ctx" .). */}}
{{- define "shieldnet-access.image" -}}
{{- $tag := .tag | default .ctx.Chart.AppVersion -}}
{{- printf "%s/%s/%s:%s" .ctx.Values.image.registry .ctx.Values.image.repository .service $tag -}}
{{- end -}}
