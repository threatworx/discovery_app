#!/bin/bash

export DISCOVERY_APP_CONFIG=config/config.ini 
/usr/local/bin/uwsgi --ini config/uwsgi-local.ini
