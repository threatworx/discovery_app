# ThreatWorx Discovery App

![Container image build](https://github.com/threatworx/discovery_app/actions/workflows/build.yml/badge.svg)

## _Zero Trust Automated AppSec for GitLab Enterprise_

A complete automated discovery solution built around 'twigs' discovery CLI, part of the ThreatWorx proactive security platform.

Provides a simple intuitive interface to automate and manage discovery scans using 'twigs'.

## Features

- Intuitive UI to schedule discovery scans
- Support for fingerprint, linux host and web application discovery modes (more in the pipeline).
- No need to share asset credentials with SaaS application - zero trust discovery and scan 
- Easy way to manage scheduled discovery runs and execute them on demand
- Can be run as a standalone app as well as a fully integrated container image
- Container auto upgrade using watchtower

## Requirements

- Standard linux system (Redhat, Ubuntu, CentOS etc.) with docker support (if running containerized version) and port 443 (https) inbound / outbound connectivity
- For running as a local app, twigs and its dependencies (nmap etc.) and cron service will be required
- SSL certificate for secure communication (optional). App supports and will allow creating self signed certificates if none are available

## Quick start - Install and configure the App Service

- Ensure requirements are satisfied on linux system, especially docker support and https inbound / outbound connectivity

- Download / clone the [ThreatWorx GitLab App](https://github.com/threatworx/gitlab_app) repository

```bash
git clone https://github.com/threatworx/gitlab_app.git
```

- Run the setup.sh script to create self signed certificates

```bash
cd gitlab_app
./setup.sh
```

> If you have ssl certificates, copy them to the ``config`` directory and edit either the ``uwsgi.ini`` or ``uwsgi-local.ini`` (for running app locally) to use your certificates

```
[uwsgi]
...
https = =0,/opt/discovery_app/config/my.cert,/opt/discovery_app/config/my.key,...
...
```

- For the containerized app start the app service by running the ``docker compose`` or the ``docker-compose`` command

```bash
docker compose up -d
```

- For the local app start the app service by running the ``run_local.sh`` script

```bash
run_local.sh
```

- Point a browser to ``https://linux-system`` to start using the app 

> The browser will complain about the self signed certificate if are using one
>
> Please be sure to replace it with an appropriate ssl certificate

- Discovery runs will be scheduled using the ``cron`` service
