#!/bin/bash

export DISCOVERY_APP_CONFIG_PATH="$PWD"/config/
/usr/local/bin/uwsgi --ini config/uwsgi-local.ini
