import os
import sys
import json
import traceback
import configparser
from crontab import CronTab
import subprocess
import re
import csv

from flask import Flask
from flask import request, redirect, render_template

app = Flask(__name__)
CONFIG_FILE = '/opt/discovery_app/config/config.ini'

# read the config.ini contents into memory
def get_config(force_read = False):
    global CONFIG_FILE
    env_config_path = os.environ.get("DISCOVERY_APP_CONFIG")
    if env_config_path is not None:
        CONFIG_FILE = env_config_path

    if os.path.isfile(CONFIG_FILE) == False:
        print("Error configuration file [%s] not found" % CONFIG_FILE)
        sys.exit(1)
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    return config

# write the current config to config.ini
def write_config(config):
    global CONFIG_FILE
    with open(CONFIG_FILE, 'w') as fd:
        config.write(fd)

# refresh TW credentials to local auth file for use with twigs command
def refresh_tw_creds(config):
    os.system('mkdir -p '+os.path.expanduser('~/.tw'))
    tw_dict = {}
    tw_dict['instance'] = config['threatworx']['instance']
    tw_dict['handle'] = config['threatworx']['handle']
    tw_dict['token'] = config['threatworx']['token']
    auth_str = json.dumps(tw_dict)
    f = open(os.path.expanduser('~/.tw/auth.json'),'w')
    f.write(auth_str)
    f.close()

def create_twigs_cmd(config, scan_name, scan_type):
    twigs_log = config['discovery_app']['log_level']
    log_switch = ''
    if twigs_log == 'info':
        log_switch = '-v'
    elif twigs_log == 'debug':
        log_switch = '-vv'
    twigs_cmd = "/usr/local/bin/twigs "+log_switch+" --run_id "+scan_name
    if scan_type == 'webapp':
        twigs_cmd = twigs_cmd + " webapp --url "+config[scan_name]['url']
    elif scan_type == 'nmap':
        twigs_cmd = twigs_cmd + " nmap --hosts "+config[scan_name]['hosts']
    elif scan_type == 'host':
        twigs_cmd = twigs_cmd + " host --host_list "+config[scan_name]['host_list']
    if 'no_ping' in config[scan_name] and config[scan_name]['no_ping'] == 'on':
        twigs_cmd = twigs_cmd + " --discovery_scan_type N"
    twigs_cmd = twigs_cmd + " 1> /tmp/"+scan_name+" 2>&1"
    return twigs_cmd

def create_cron_entry(config, scan_name, twigs_cmd):
    cron_comment = "TW_CRON_"+scan_name
    random_delay = '/bin/bash -c "sleep \$((RANDOM % 300))s";'
    twigs_cmd = random_delay + twigs_cmd
    schedule = config[scan_name]['schedule']
    with CronTab(user=True) as user_cron:
        ejobs = user_cron.find_comment(cron_comment)
        for ejob in ejobs:
            user_cron.remove(ejob)
        njob = user_cron.new(command=twigs_cmd, comment=cron_comment)
        njob.setall(schedule)

def remove_cron_entry(config, scan_name):
    cron_comment = "TW_CRON_"+scan_name
    with CronTab(user=True) as user_cron:
        ejobs = user_cron.find_comment(cron_comment)
        for ejob in ejobs:
            user_cron.remove(ejob)

# reload configuration if any changes have happened
def reload_config():
    config = get_config()
    refresh_tw_creds(config)
    with CronTab(user=True) as user_cron:
        # Get any existing jobs and remove those
        ejobs = user_cron.find_comment(re.compile(r'^TW_'))
        for ejob in ejobs:
            user_cron.remove(ejob)
    for s in config.sections():
        if s == 'threatworx' or s == 'discovery_app':
            continue
        twigs_cmd = create_twigs_cmd(config, s, config[s]['type'])
        create_cron_entry(config, s, twigs_cmd)

def create_host_csv(scan_name, hostname, user, passwd):
    csv_file = os.path.expanduser('~/.tw/'+scan_name+'.csv')
    with open(csv_file, mode='w') as csvfile:
         fieldnames = ['hostname','userlogin','userpwd','privatekey','assetname']
         writer = csv.DictWriter(csvfile, fieldnames=fieldnames, quoting=csv.QUOTE_NONE, escapechar='\\')
         writer.writeheader()
         rdict = {}
         rdict['hostname'] = hostname
         rdict['userlogin'] = user
         rdict['userpwd'] = passwd
         writer.writerow(rdict)
    return csv_file

@app.route('/')
def index_page():
    config = get_config()
    data = {s:dict(config.items(s)) for s in config.sections()}
    config.remove_option('discovery_app','error_msg')
    write_config(config)
    return render_template("index.html", data=data)

@app.route("/save_scan", methods=['POST'])
def save_config():
    config = get_config()
    scan_name = request.form['scan_name']
    if config.has_section(scan_name):
        config.set('discovery_app','error_msg', "Error: Discovery scan by the name '"+request.form['scan_name']+"' is already configured")
        write_config(config)
        return redirect("/")
    scan_type = request.form['scan_type']
    config['threatworx'] = {}
    config['threatworx']['instance'] = request.form['instance']
    config['threatworx']['handle'] = request.form['handle']
    config['threatworx']['token'] = request.form['token']
    config[scan_name] = {}
    config[scan_name]['type'] = scan_type
    config[scan_name]['schedule'] = request.form['schedule']
    if scan_type == 'webapp':
        config[scan_name]['url'] = request.form['url']
        if 'webapp_no_ping' in request.form and request.form['webapp_no_ping'] == 'on':
            config[scan_name]['no_ping'] = 'on'
        else:
            config[scan_name]['no_ping'] = 'off'
    elif scan_type == 'nmap':
        config[scan_name]['hosts'] = request.form['hosts']
        if 'nmap_no_ping' in request.form and request.form['nmap_no_ping'] == 'on':
            config[scan_name]['nmap_no_ping'] = 'on'
        else:
            config[scan_name]['nmap_no_ping'] = 'off'
    elif scan_type == 'host':
        config[scan_name]['host_list'] = create_host_csv(scan_name, request.form['host_list'], request.form['user_name'], request.form['user_passwd'])
    write_config(config)
    refresh_tw_creds(config)
    twigs_cmd = create_twigs_cmd(config, scan_name, scan_type)
    create_cron_entry(config, scan_name, twigs_cmd)
    if 'run_now' in request.form and request.form['run_now'] == 'on':
        proc = subprocess.Popen([twigs_cmd], shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
    return redirect("/")

@app.route("/delete_scan", methods=['GET'])
def delete_config():
    scan_name = request.args.get('scan_name')
    config = get_config()
    if not config.has_section(scan_name):
        config.set('discovery_app','error_msg', "Error: Invalid Scan name '"+request.form['scan_name']+"'")
        write_config(config)
        return redirect("/")
    remove_cron_entry(config,scan_name)
    config.remove_section(scan_name)
    write_config(config)
    return redirect("/")

@app.route("/run_scan", methods=['GET'])
def run_config():
    scan_name = request.args.get('scan_name')
    scan_type = request.args.get('scan_type')
    config = get_config()
    twigs_cmd = create_twigs_cmd(config, scan_name, scan_type)
    proc = subprocess.Popen([twigs_cmd], shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int("80"))
reload_config()
