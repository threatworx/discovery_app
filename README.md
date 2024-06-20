# ThreatWorx Discovery App

![Container image build](https://github.com/threatworx/discovery_app/actions/workflows/build.yml/badge.svg)

## _Automated Discovery Using 'twigs'_

A complete automated discovery solution built around 'twigs' discovery CLI, part of the ThreatWorx proactive security platform.

Provides a simple intuitive interface to automate and manage discovery scans using 'twigs'.

## Features

- Intuitive UI to schedule discovery scans
- Support for fingerprint, linux host, web application, GCP (and more) discovery modes.
- No need to share asset credentials with SaaS application - zero trust discovery and scan 
- Easy way to manage scheduled discovery runs and execute them on demand
- Can be run as a standalone app as well as a fully integrated container image
- Container auto upgrade using watchtower

## Requirements

- Standard linux system (Redhat, Ubuntu, CentOS etc.) with docker support (if running containerized version) and port 443 (https) inbound / outbound connectivity.
- For running as a local app, twigs and its dependencies (nmap etc.) and cron service will be required.
- SSL certificate for secure communication (optional). App supports and will allow creating self signed certificates if none are available.
- Python requirements (in requirements.txt)

## Quick start

- Ensure requirements are satisfied on linux system, especially docker support and https inbound / outbound connectivity

- Download / clone the [ThreatWorx Discovery App](https://github.com/threatworx/discovery_app) repository

```bash
git clone https://github.com/threatworx/discovery_app.git
```

- Run the setup.sh script
  
```bash
cd discovery_app
./setup.sh
```

> Defaults ports are 8080 if the app is run locally or 443 if the app is run as a container. Modify the ``uwsgi.ini`` or ``uwsgi.ini`` (for running the app locally) to pick your own ports for the app.
> 
> Setup will create self signed cerficates for the app. If you have your own ssl certificates, copy them to the ``config`` directory and edit either the ``uwsgi.ini`` or ``uwsgi-local.ini`` (for running app locally) to use your certificates.
> 
> Setup will also (optionally) create a password for the app, will encrypt it using cerfiticate keys and store it in the ``config`` directory.

- For the containerized app start the app service by running the ``docker compose`` or the ``docker-compose`` command

```bash
docker compose up -d
```

- For the local app start the app service by running the ``run.sh`` script

```bash
./run.sh
```

- Point a browser to ``https://linux-system:port`` to start using the app 

> For more details check the [Discovery App documentation](https://threatworx.io/docs-category/discovery-app/) 
