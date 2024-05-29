#!/bin/bash
# This script generates default self-signed certificates (if not present)
CERT_FILE=/opt/discovery_app/config/default.cert
KEY_FILE=/opt/discovery_app/config/default.key

if [ ! -f "$CERT_FILE" ]
then
	echo "Generating default self-signed certificates..."
	openssl req -x509 -newkey rsa:4096 -nodes -out "$CERT_FILE" -keyout "$KEY_FILE" -days 365 -subj "/C=US/O=tw_org/OU=tw_ou/CN=threatworx_discovery_app_default"
fi

