#!/bin/bash
# Install app dependencies
pip3 install -r /tmp/requirements.txt
apt update -y
apt install vim
# Setup twigs update script
printf "#!/bin/bash\n/usr/sbin/service cron start\n/usr/local/bin/uwsgi --ini /opt/discovery_app/config/uwsgi.ini" > /usr/local/bin/run-app.sh
chmod +x /usr/local/bin/run-app.sh
# Cleanup /tmp
rm -f /tmp/*
