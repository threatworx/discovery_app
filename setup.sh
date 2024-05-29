#!/bin/bash

CERT_FILE=./config/default.cert
KEY_FILE=./config/default.key

if [ ! -f "./config/config.ini" ]
then
    echo "Setting up config.ini"
    cp ./config/config.ini.template ./config/config.ini
fi
if [ ! -f "./config/uwsgi.ini" ]
then
    echo "Setting up uwsgi.ini"
    cp -f ./config/uwsgi.ini.template ./config/uwsgi.ini
fi

if [ ! -f "./config/uwsgi-local.ini" ]
then
    echo "Setting up uwsgi-local.ini"
    cp -f ./config/uwsgi-local.ini.template ./config/uwsgi-local.ini
fi

if [ ! -f "$CERT_FILE" ]
then
        echo "Generating default self-signed certificates for temporary use"
	openssl req -x509 -newkey rsa:4096 -nodes -out "$CERT_FILE" -keyout "$KEY_FILE" -days 365 -subj "/C=US/O=tw_org/OU=tw_ou/CN=threatworx_discovery_app_default"
	if [ $? -ne 0 ]; then
	    echo "Could not generate default self-signed certificates"
	    exit 1
	fi
fi

echo "Done"
