#!/bin/bash

CERT_FILE=./config/default.cert
KEY_FILE=./config/default.key
export RANDFILE=./config/.rnd

if [ ! -f "./config/config.ini" ]
then
    echo "Setting up config.ini"
    cp ./config/config.ini.template ./config/config.ini
else
    echo "config.ini exists. Please remove if you want to reconfigure"
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
else
    echo "uwsgi-local.ini exists. Please remove if you want to reconfigure"
fi

if [ ! -f "$CERT_FILE" ]
then
        echo "Generating default self-signed certificates for temporary use"
	openssl req -x509 -newkey rsa:4096 -nodes -out "$CERT_FILE" -keyout "$KEY_FILE" -days 365 -subj "/C=US/O=tw_org/OU=tw_ou/CN=threatworx_discovery_app_default"
	if [ $? -ne 0 ]; then
	    echo "Could not generate default self-signed certificates"
	    exit 1
	fi
else
    echo "Default self-signed certificate exists. Please remove if you want to recreate it"
fi

dd if=/dev/urandom of=$RANDFILE bs=256 count=1 >/dev/null 2>&1
while :
do
    echo -n "Enter app password:"
    read -s app_password
    echo
    echo -n "Re-enter app password:"
    read -s app_password_again
    echo
    if [ "$app_password" == "$app_password_again" ]
    then
        break
    fi
    echo "Passwords don't match. Try again"
done
echo $app_password | openssl rsautl -inkey $KEY_FILE -encrypt > ./config/app_credentials
echo "Setup done!"
