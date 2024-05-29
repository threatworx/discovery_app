#!/bin/bash
# Install app dependencies
pip3 install -r /tmp/requirements.txt
# Setup twigs update script
printf "#!/bin/bash\n/usr/share/discovery_app/default_cert.sh\n/usr/local/bin/uwsgi --ini /opt/discovery_app/config/uwsgi.ini" > /usr/local/bin/run-app.sh
chmod +x /usr/local/bin/run-app.sh
# Cleanup /tmp
rm -f /tmp/*
