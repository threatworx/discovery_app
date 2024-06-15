#!/bin/bash

CERT_FILE=./config/default.cert
KEY_FILE=./config/default.key
APP_CREDS=./config/app_credentials
export RANDFILE=./config/.rnd

if [ ! -f "./config/config.ini" ] || [ "$1" == "-r" ]
then
    echo "Cleaning up old stuff"
    rm -f $APP_CREDS
    rm -f $CERT_FILE
    rm -f $KEY_FILE
    rm -f $RANDFILE
    rm -f ./config/*.key
    rm -f ./config/*.csv
    echo "Setting up new configuration"
    cp -f ./config/config.ini.template ./config/config.ini
    cp -f ./config/uwsgi.ini.template ./config/uwsgi.ini
    cp -f ./config/uwsgi-local.ini.template ./config/uwsgi-local.ini
    echo "Generating default self-signed certificates for temp use"
    /usr/bin/openssl req -x509 -newkey rsa:4096 -nodes -out "$CERT_FILE" -keyout "$KEY_FILE" -days 365 -subj "/C=US/O=tw_org/OU=tw_ou/CN=threatworx_discovery_app_default"
    if [ $? -ne 0 ]; then
        echo "Could not generate default self-signed certificates"
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
    echo $app_password | /usr/bin/openssl rsautl -inkey $KEY_FILE -encrypt > $APP_CREDS
    echo "Setup done!"
else
    echo "Found exiting configuration. Remove config.ini or use '-r' to reconfigure"
fi

