THIRD-PARTY SOFTWARE NOTICES AND INFORMATION

This project incorporates material from the projects listed below.
The original copyright notices and license terms are included below.
{{ range . }}
============================================================
Package: {{ .Name }}
License: {{ .LicenseName }}
URL:     {{ .LicenseURL }}
------------------------------------------------------------
{{ .LicenseText }}
{{ end }}
