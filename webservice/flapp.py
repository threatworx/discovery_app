import os
import sys
import signal
import atexit
import configparser
import subprocess
import csv
import string
import random
import psutil
import json
import traceback
import requests
from distutils.version import LooseVersion
from flask import Flask
from flask import request, redirect, render_template, url_for

from . import config_utils
from . import __version__

app = Flask(__name__)
authenticators = []

def handle_exit(*args):
    config_utils.unload_cron()

@app.route('/')
def index_page():
    config = config_utils.get_config()
    data = {s:dict(config.items(s)) for s in config.sections()}
    del data['threatworx']['token']
    config.remove_option('discovery_app','error_msg')
    config.remove_option('discovery_app','success_msg')
    config_utils.write_config(config)
    if config['discovery_app']['auth'] == 'no':
        return redirect("/authenticate")
    return render_template("login.html", data=data)

@app.route("/authenticate", methods=['POST','GET'])
def authenticate():
    global authenticators
    config = config_utils.get_config()
    if config['discovery_app']['auth'] == 'yes' and not config_utils.validate_password(request.form['password']):
        config.set('discovery_app','error_msg', "Authentication failed")
        config_utils.write_config(config)
        return redirect("/")
    letters = string.printable[:62]
    authenticator = ''.join(random.choice(letters) for i in range(32))
    authenticators.append(authenticator)
    return redirect(url_for('app_page',auth=authenticator))

def check_upgrade():
    out = ''
    url = 'https://hub.docker.com/v2/repositories/threatworx/discovery_app/tags/?page_size=2'
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            oj = json.loads(response.text)
            lver = oj['results'][1]['name']
            if LooseVersion(__version__) < LooseVersion(lver): 
                out = "(upgrade available)"
    except:
        pass
    return out

@app.route('/app')
def app_page():
    config = config_utils.get_config()
    auth = request.args.get('auth') 
    if not auth or auth not in authenticators:
        config.set('discovery_app','error_msg', "Not authenticated")
        config_utils.write_config(config)
        return redirect("/")
    data = {s:dict(config.items(s)) for s in config.sections()}
    data['authenticator'] = auth
    vstr = 'v'+__version__
    upgradestr = check_upgrade()
    data['discovery_app']['version'] = 'v'+__version__+' '+check_upgrade()
    #del data['threatworx']['token']
    config.remove_option('discovery_app','error_msg')
    config.remove_option('discovery_app','success_msg')
    config_utils.write_config(config)
    return render_template("config.html", data=data)

@app.route("/save_creds", methods=['POST'])
def handle_save_creds():
    config = config_utils.get_config()
    authenticator = request.args.get('auth') 

    config_utils.save_creds(config, request)
    config = config_utils.get_config()
    config_utils.refresh_tw_creds(config)
    config.set('discovery_app','success_msg', "Saved ThreatWorx credentials")
    config_utils.write_config(config)
    return redirect(url_for('app_page',auth=authenticator))

@app.route("/save_scan", methods=['POST'])
def handle_save_config():
    config = config_utils.get_config()
    authenticator = request.args.get('auth') 

    # Make sure threatworx credentials are already set
    if config['threatworx']['token'] == None or config['threatworx']['token'] == '':
        config.set('discovery_app','error_msg', "Error: Please save Threatworx credentials before configuring a discovery scan")
        config_utils.write_config(config)
        return redirect(url_for('app_page',auth=authenticator))

    scan_name = request.form['scan_name']

    config_utils.add_scan(config, request)
    config = config_utils.get_config()
    config_utils.refresh_tw_creds(config)
    twigs_cmd = config_utils.create_twigs_cmd(config, scan_name, request.form['scan_type'])
    config_utils.create_cron_entry(config, scan_name, twigs_cmd)
    if 'run_now' in request.form and request.form['run_now'] == 'on':
        proc = subprocess.Popen([twigs_cmd], shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
    config.set('discovery_app','success_msg', "Saved schedule for '"+scan_name+"'")
    config_utils.write_config(config)
    return redirect(url_for('app_page',auth=authenticator))

@app.route("/delete_scan", methods=['GET'])
def delete_config():
    authenticator = request.args.get('auth') 
    scan_name = request.args.get('scan_name')
    config = config_utils.get_config()
    if not config.has_section(scan_name):
        config.set('discovery_app','error_msg', "Error: Invalid discovery name '"+scan_name+"'")
        config_utils.write_config(config)
        return redirect("/app")
    config_utils.remove_cron_entry(config,scan_name)
    config.remove_section(scan_name)
    config_utils.remove_scan_files(scan_name)
    config.set('discovery_app','success_msg', "Deleted discovery configuration '"+scan_name+"'")
    config_utils.write_config(config)
    return redirect(url_for('app_page',auth=authenticator))

@app.route("/run_scan", methods=['GET'])
def run_config():
    authenticator = request.args.get('auth') 
    scan_name = request.args.get('scan_name')
    scan_type = request.args.get('scan_type')
    config = config_utils.get_config()

    # check if discovery is already in progress
    plist = psutil.process_iter()
    running = False
    for p in plist:
        try:
            if scan_name in p.cmdline() and '--run_id' in p.cmdline():
                running = True
        except:
            # exception in psutil ignore
            #traceback.print_exc()
            pass

    if running:
        config.set('discovery_app','error_msg', "Discovery is already in progress for '"+scan_name+"'")
        config_utils.write_config(config)
        return redirect(url_for('app_page',auth=authenticator))

    twigs_cmd = config_utils.create_twigs_cmd(config, scan_name, scan_type)
    proc = subprocess.Popen([twigs_cmd], shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
    config.set('discovery_app','success_msg', "Started new discovery run for '"+scan_name+"'")
    config_utils.write_config(config)
    return redirect(url_for('app_page',auth=authenticator))

@app.route("/view_log", methods=['GET'])
def view_log():
    scan_name = request.args.get('scan_name')
    log_file = "/tmp/"+scan_name
    
    if os.path.isfile(log_file):
        f = open(log_file, 'r')
        contents = f.read()
        f.close()

        return contents, 200, {'Content-Type': 'text/plain'}
    return 'Log for '+scan_name+' not available', 404, {'Content-Type': 'text/plain'}

@app.route("/logout")
def logout():
    global authenticators
    authenticator = request.args.get('auth')
    if authenticator in authenticators:
        authenticators.remove(authenticator)
    return redirect("/")

@app.route("/run_status")
def run_status():
    global authenticators
    auth = request.args.get('auth') 
    if not auth or auth not in authenticators:
        return '[]', 200, {'Content-Type': 'application/json'}
    plist = psutil.process_iter()
    config = config_utils.get_config()
    running_scans = []
    for p in plist:
        try:
            if '--run_id' not in p.cmdline():
                continue
            for s in config.sections():
                if s not in p.cmdline():
                    continue
                running_scans.append(s)
        except:
            # exception in psutil ignore
            pass

    return json.dumps(running_scans), 200, {'Content-Type': 'application/json'}

@app.route("/stop_scan", methods=['GET'])
def stop_scan():
    global authenticators
    config = config_utils.get_config()
    auth = request.args.get('auth') 
    if not auth or auth not in authenticators:
        return '[]', 200, {'Content-Type': 'application/json'}
    runid = request.args.get('run_id')
    if not runid or runid == '':
        config.set('discovery_app','error_msg', "Invalid discovery run Id") 
        config_utils.write_config(config)
        return redirect("/app")
    plist = psutil.process_iter()
    killed = False
    for p in plist:
        try:
            if runid in p.cmdline() and '--run_id' in p.cmdline():
                killed = True
                p.kill()
        except:
            # exception in psutil ignore
            #traceback.print_exc()
            pass

    if killed:
        config.set('discovery_app','success_msg', "Stopped discovery run for '"+runid+"'")
    else:
        config.set('discovery_app','error_msg', "No running discovery for '"+runid+"'")
    config_utils.write_config(config)
    return redirect(url_for('app_page',auth=auth))

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int("80"))
atexit.register(handle_exit)
signal.signal(signal.SIGTERM, handle_exit)
signal.signal(signal.SIGINT, handle_exit)
config_utils.reload_config()
