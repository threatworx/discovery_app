import os
import sys
import json
import configparser
from crontab import CronTab
import subprocess
import re
import csv
import string
import shutil
from pathlib import Path

CONFIG_PATH = '/opt/discovery_app/config/'
env_config_path = os.environ.get("DISCOVERY_APP_CONFIG_PATH")
if env_config_path is not None:
   CONFIG_PATH = env_config_path
authenticators = []

# validate login password 
def validate_password(password):
    global CONFIG_PATH

    cred_file = CONFIG_PATH + "app_credentials"
    key_file = CONFIG_PATH + "default.key"

    cmd = "/usr/bin/openssl rsautl -inkey "+key_file+" -decrypt < "+cred_file
    output = None
    try:
        output = subprocess.check_output(cmd, shell=True)
    except CalledProcessError as e:
        print("Error authenticating")
        print(e.returncode)
        print(e.message)
        return False
    output = output.decode('utf-8').strip()
    if password == output:
        return True
    return False

# read the config.ini contents into memory
def get_config():
    global CONFIG_PATH

    config_file = CONFIG_PATH + "config.ini"

    if os.path.isfile(config_file) == False:
        print("Error configuration file [%s] not found" % config_file)
        sys.exit(1)
    config = configparser.ConfigParser()
    config.read(config_file)

    return config

# write the current config to config.ini
def write_config(config):
    global CONFIG_PATH

    config_file = CONFIG_PATH + "config.ini"
    with open(config_file, 'w') as fd:
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
    global CONFIG_PATH

    twigs_log = config['discovery_app']['log_level']
    log_switch = ''
    if twigs_log == 'info':
        log_switch = '-v'
    elif twigs_log == 'debug':
        log_switch = '-vv'
    twigs_cmd = "/usr/local/bin/twigs "+log_switch+" --run_id "+scan_name
    tags = ''
    if 'tags' in config[scan_name]:
        tags = config[scan_name]['tags'].strip()
    if tags and tags != '':
        for t in tags.split(','):
            twigs_cmd = twigs_cmd + " --tag "+t.strip()
    if scan_type == 'webapp':
        twigs_cmd = twigs_cmd + " webapp --url "+config[scan_name]['url']
        if 'no_ping' in config[scan_name] and config[scan_name]['no_ping'] == 'on':
            twigs_cmd = twigs_cmd + " --discovery_scan_type N"
    elif scan_type == 'nmap':
        twigs_cmd = twigs_cmd + " nmap --hosts "+config[scan_name]['hosts']
        if 'no_ping' in config[scan_name] and config[scan_name]['no_ping'] == 'on':
            twigs_cmd = twigs_cmd + " --discovery_scan_type N"
    elif scan_type == 'host':
        twigs_cmd = twigs_cmd + " host --host_list "+CONFIG_PATH+config[scan_name]['host_list']
    elif scan_type == 'gitlab':
        twigs_cmd = twigs_cmd + " gitlab --gl_access_token "+config[scan_name]['access_token'] + " --gl_host "+config[scan_name]['server']
        if config[scan_name]['sast'] == 'on':
            twigs_cmd = twigs_cmd + " --sast"
        if config[scan_name]['secrets'] == 'on':
            twigs_cmd = twigs_cmd + " --secrets_scan"
        if config[scan_name]['iac'] == 'on':
            twigs_cmd = twigs_cmd + " --iac_checks"
        if config[scan_name]['nocode'] == 'on':
            twigs_cmd = twigs_cmd + " --no_code"
    elif scan_type == 'github':
        twigs_cmd = twigs_cmd + " github --gh_identity "+config[scan_name]['identity']+" --gh_access_token "+config[scan_name]['access_token'] + " --gh_api_url "+config[scan_name]['api_url']
        if config[scan_name]['sast'] == 'on':
            twigs_cmd = twigs_cmd + " --sast"
        if config[scan_name]['secrets'] == 'on':
            twigs_cmd = twigs_cmd + " --secrets_scan"
        if config[scan_name]['iac'] == 'on':
            twigs_cmd = twigs_cmd + " --iac_checks"
        if config[scan_name]['nocode'] == 'on':
            twigs_cmd = twigs_cmd + " --no_code"
    elif scan_type == 'bitbucket':
        twigs_cmd = twigs_cmd + " bitbucket --bb_user "+config[scan_name]['user']+" --bb_app_password "+config[scan_name]['app_password'] + " --bb_repo_url "+config[scan_name]['url']
        if config[scan_name]['sast'] == 'on':
            twigs_cmd = twigs_cmd + " --sast"
        if config[scan_name]['secrets'] == 'on':
            twigs_cmd = twigs_cmd + " --secrets_scan"
        if config[scan_name]['iac'] == 'on':
            twigs_cmd = twigs_cmd + " --iac_checks"
        if config[scan_name]['nocode'] == 'on':
            twigs_cmd = twigs_cmd + " --no_code"
    elif scan_type == 'gcp':
        gcloud_cmd = shutil.which('gcloud')
        gcloud_cmd = gcloud_cmd + " auth activate-service-account --key-file "+CONFIG_PATH+config[scan_name]['key_file']
        twigs_cmd = twigs_cmd + " gcp --enable_tracking_tags"
        twigs_cmd = gcloud_cmd + " && " + twigs_cmd
    elif scan_type == 'gcp_cspm':
        gcloud_cmd = shutil.which('gcloud')
        gcloud_cmd = gcloud_cmd + " auth activate-service-account --key-file "+CONFIG_PATH+config[scan_name]['key_file']
        twigs_cmd = twigs_cmd + " gcp_cis --assetid "+config[scan_name]['asset_id']
        twigs_cmd = gcloud_cmd + " && " + twigs_cmd
    elif scan_type == 'gcr':
        gcloud_cmd = shutil.which('gcloud')
        docker_cmd = shutil.which('docker')
        gcloud_cmd = gcloud_cmd + " auth activate-service-account --key-file "+CONFIG_PATH+config[scan_name]['key_file']
        docker_cmd = "cat "+CONFIG_PATH+config[scan_name]['key_file']+" | "+docker_cmd+" login -u _json_key --password-stdin "+config[scan_name]['gcr_repo']
        twigs_cmd = twigs_cmd + " gcr --repository "+config[scan_name]['gcr_repo']+" --check_all_vulns"
        twigs_cmd = gcloud_cmd + " && " + docker_cmd + " && " + twigs_cmd

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

# remove any files, keys etc.  related to this scan config
def remove_scan_files(scan_name):
    global CONFIG_PATH

    for filename in Path(CONFIG_PATH).glob(scan_name+'.*'):
        filename.unlink()

# reload configuration if any changes have happened
def reload_config():
    global CONFIG_PATH
    print("Reloading app_configuration from "+CONFIG_PATH)
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

def create_gcp_key_file(scan_name, private_key):
    global CONFIG_PATH

    pk_file_name = None
    if private_key and len(private_key) > 0:
        pk_file_name = CONFIG_PATH+scan_name+'.key'
        with open(pk_file_name, mode='w') as pk_file:
            pk_file.write(private_key)
    return os.path.basename(pk_file_name)

def create_host_csv(scan_name, hostname, user, passwd, private_key):
    global CONFIG_PATH

    pk_file_name = None
    if private_key and len(private_key) > 0:
        pk_file_name = CONFIG_PATH+scan_name+'.key'
        with open(pk_file_name, mode='w') as pk_file:
            pk_file.write(private_key)
    csv_file = CONFIG_PATH+scan_name+'.csv'
    with open(csv_file, mode='w') as csvfile:
         fieldnames = ['hostname','userlogin','userpwd','privatekey','assetname']
         writer = csv.DictWriter(csvfile, fieldnames=fieldnames, quoting=csv.QUOTE_NONE, escapechar='\\')
         writer.writeheader()
         rdict = {}
         rdict['hostname'] = hostname
         rdict['userlogin'] = user
         if pk_file_name:
             rdict['privatekey'] = pk_file_name 
         else:
             rdict['userpwd'] = passwd
         writer.writerow(rdict)
    return os.path.basename(csv_file)

def save_creds(config, request):
    # process any change to threatworx configuration 
    saved_token = config['threatworx']['token']
    config['threatworx'] = {}
    config['threatworx']['instance'] = request.form['instance']
    config['threatworx']['handle'] = request.form['handle']
    if request.form['token'] is not None and request.form['token'] != '':
        config['threatworx']['token'] = request.form['token']
    else:
        config['threatworx']['token'] = saved_token
    write_config(config)

def add_scan(config, request):
    scan_type = request.form['scan_type']
    scan_name = request.form['scan_name']

    # add the new scan entry
    config[scan_name] = {}
    config[scan_name]['type'] = scan_type
    config[scan_name]['schedule'] = request.form['schedule']
    config[scan_name]['tags'] = request.form['tags']
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
        config[scan_name]['host_list'] = create_host_csv(scan_name, request.form['host_list'], request.form['user_name'], request.form['user_passwd'], request.form['user_private_key'])
    elif scan_type == 'gitlab':
        config[scan_name]['access_token'] = request.form['gitlab_access_token']
        config[scan_name]['server'] = request.form['gitlab_server']
        config[scan_name]['sast'] = 'off'
        config[scan_name]['secrets'] = 'off'
        config[scan_name]['iac'] = 'off'
        config[scan_name]['nocode'] = 'off'
        if 'gl_sast' in request.form and request.form['gl_sast'] == 'on':
            config[scan_name]['sast'] = 'on'
        if 'gl_secrets' in request.form and request.form['gl_secrets'] == 'on':
            config[scan_name]['secrets'] = 'on'
        if 'gl_iac' in request.form and request.form['gl_iac'] == 'on':
            config[scan_name]['iac'] = 'on'
        if 'gl_nocode' in request.form and request.form['gl_nocode'] == 'on':
            config[scan_name]['nocode'] = 'on'
    elif scan_type == 'github':
        config[scan_name]['access_token'] = request.form['github_access_token']
        config[scan_name]['identity'] = request.form['github_identity']
        config[scan_name]['api_url'] = request.form['github_url']
        config[scan_name]['sast'] = 'off'
        config[scan_name]['secrets'] = 'off'
        config[scan_name]['iac'] = 'off'
        config[scan_name]['nocode'] = 'off'
        if 'gh_sast' in request.form and request.form['gh_sast'] == 'on':
            config[scan_name]['sast'] = 'on'
        if 'gh_secrets' in request.form and request.form['gh_secrets'] == 'on':
            config[scan_name]['secrets'] = 'on'
        if 'gh_iac' in request.form and request.form['gh_iac'] == 'on':
            config[scan_name]['iac'] = 'on'
        if 'gh_nocode' in request.form and request.form['gh_nocode'] == 'on':
            config[scan_name]['nocode'] = 'on'
    elif scan_type == 'bitbucket':
        config[scan_name]['user'] = request.form['bb_user']
        config[scan_name]['app_password'] = request.form['bb_app_password']
        config[scan_name]['url'] = request.form['bb_url']
        config[scan_name]['sast'] = 'off'
        config[scan_name]['secrets'] = 'off'
        config[scan_name]['iac'] = 'off'
        config[scan_name]['nocode'] = 'off'
        if 'bb_sast' in request.form and request.form['bb_sast'] == 'on':
            config[scan_name]['sast'] = 'on'
        if 'bb_secrets' in request.form and request.form['bb_secrets'] == 'on':
            config[scan_name]['secrets'] = 'on'
        if 'bb_iac' in request.form and request.form['bb_iac'] == 'on':
            config[scan_name]['iac'] = 'on'
        if 'bb_nocode' in request.form and request.form['bb_nocode'] == 'on':
            config[scan_name]['nocode'] = 'on'
    elif scan_type == 'gcp':
        config[scan_name]['key_file'] = create_gcp_key_file(scan_name, request.form['gcp_private_key'])
    elif scan_type == 'gcp_cspm':
        config[scan_name]['asset_id'] = request.form['gcp_cspm_asset_id']
        config[scan_name]['key_file'] = create_gcp_key_file(scan_name, request.form['gcp_cspm_private_key'])
    elif scan_type == 'gcr':
        config[scan_name]['gcr_repo'] = request.form['gcr_repo']
        config[scan_name]['key_file'] = create_gcp_key_file(scan_name, request.form['gcr_private_key'])

    write_config(config)
