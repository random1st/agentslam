{{- define "agentslam.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "agentslam.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "agentslam.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* agentslam.toml, rendered from values. */}}
{{- define "agentslam.config" -}}
{{- $url := required "publicUrl is required (the external https URL of agentslam)" .Values.publicUrl -}}
{{- if not (hasPrefix "https://" $url) -}}
{{- fail "publicUrl must start with https:// (agentslam refuses plain http off localhost)" -}}
{{- end -}}
{{- if not .Values.providers -}}
{{- fail "providers must list at least one sign-in provider" -}}
{{- end -}}
{{- range .Values.providers -}}
{{- if hasKey . "client_secret" -}}
{{- fail (printf "provider %s: put the secret in a Secret and use client_secret_env, never client_secret in values" .id) -}}
{{- end -}}
{{- end -}}
{{- $cfg := dict
  "bind" "0.0.0.0:8080"
  "public_url" $url
  "database" "/data/agentslam.db"
  "secure_cookies" true
  "providers" .Values.providers
  "oauth" (dict
    "allowed_clients" .Values.oauth.allowedClients
    "access_token_ttl_s" (int .Values.oauth.accessTokenTtlS)
    "refresh_token_ttl_s" (int .Values.oauth.refreshTokenTtlS)
    "code_ttl_s" (int .Values.oauth.codeTtlS))
  "summary" (dict
    "interval_s" (int .Values.summary.intervalS)
    "min_messages" (int .Values.summary.minMessages)
    "request_ttl_s" (int .Values.summary.requestTtlS))
  "allowed_domains" (.Values.allowedDomains | default list)
  "allowed_tenants" (.Values.allowedTenants | default list)
  "admins" .Values.admins -}}
{{- toToml $cfg -}}
{{- end -}}
