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
    config = configparser.ConfigParser(interpolation=None)
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

    twigs_log = 'info'
    if 'log_level' in config['discovery_app']:
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
        if 'plan_file' in config[scan_name]:
            twigs_cmd = twigs_cmd + " webapp --planfile "+config[scan_name]['plan_file']
        else:
            twigs_cmd = twigs_cmd + " webapp --url "+config[scan_name]['url']
    elif scan_type == 'nmap':
        twigs_cmd = twigs_cmd + " nmap --hosts "+config[scan_name]['hosts'] 
        if 'services' in config[scan_name]:
            twigs_cmd = twigs_cmd + ' --services '+config[scan_name]['services']
        if 'extra_ports' in config[scan_name] and config[scan_name]['extra_ports'] != '':
            twigs_cmd = twigs_cmd + ' --extra_ports '+config[scan_name]['extra_ports']
    elif scan_type == 'snmp':
        twigs_cmd = twigs_cmd + " nmap --hosts "+config[scan_name]['snmp_hosts'] + " --services snmp --snmp_community " + config[scan_name]['community_str']
        if config[scan_name]['security_name'] != '':
            twigs_cmd = twigs_cmd + " --snmp_security_name "+config[scan_name]['security_name']
    elif scan_type == 'printer':
        twigs_cmd = twigs_cmd + " nmap --hosts "+config[scan_name]['printer_hosts'] + " --services printers" 
    elif scan_type == 'cctv':
        twigs_cmd = twigs_cmd + " nmap --hosts "+config[scan_name]['cctv_hosts'] + " --services cctv" 
    elif scan_type == 'host':
        twigs_cmd = twigs_cmd + " host --host_list "+CONFIG_PATH+config[scan_name]['host_list']
    elif scan_type == 'win_host':
        twigs_cmd = twigs_cmd + " win_host --host_list "+CONFIG_PATH+config[scan_name]['win_host_list']
    elif scan_type == 'vmware':
        twigs_cmd = twigs_cmd + " vmware --host "+config[scan_name]['vcenter_host']+" --user "+config[scan_name]['vcenter_user']+" --password '"+config[scan_name]['vcenter_passwd']+"'"
    elif scan_type == 'cisco_meraki':
        twigs_cmd = twigs_cmd + " meraki --api_key '"+config[scan_name]['meraki_api_key']+"'"
        if config[scan_name]['meraki_base_url'] != '':
            twigs_cmd = twigs_cmd = " --base_url '"+config[scan_name]['meraki_base_url']+"'"
    elif scan_type == 'cisco_dna_center':
        twigs_cmd = twigs_cmd + " dna_center --url '"+config[scan_name]['dna_center_url']+"' --user '"+config[scan_name]['dna_center_user']+"' --password '"+config[scan_name]['dna_center_password']+"'"
    elif scan_type == 'defender':
        twigs_cmd = twigs_cmd + " o365 --tenant_id "+config[scan_name]['tenant_id']+" --application_id "+config[scan_name]['app_id']+" --application_key '"+config[scan_name]['app_key']+"'"
        if 'all_devices' in config[scan_name] and config[scan_name]['all_devices'] == 'on':
            twigs_cmd = twigs_cmd + " --all"
    elif scan_type == 'servicenow':
        if 'snow_client_id' in config[scan_name]:
            twigs_cmd = twigs_cmd + " servicenow --snow_instance "+config[scan_name]['snow_instance']+" --snow_client_id "+config[scan_name]['snow_client_id']+" --snow_client_secret '"+config[scan_name]['snow_client_secret']+"'"
        else:
            twigs_cmd = twigs_cmd + " servicenow --snow_instance "+config[scan_name]['snow_instance']+" --snow_user "+config[scan_name]['snow_user']+" --snow_user_pwd '"+config[scan_name]['snow_password']+"'"
    elif scan_type == 'gitlab':
        twigs_cmd = twigs_cmd + " gitlab --gl_access_token='"+config[scan_name]['access_token'] + "' --gl_host "+config[scan_name]['server']
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
    elif scan_type == 'gcp-cspm':
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
    elif scan_type == 'aws':
        twigs_cmd = twigs_cmd + " aws --aws_account '"+config[scan_name]['aws_account']+"' --aws_access_key '"+config[scan_name]['aws_access_key']+"' --aws_secret_key '"+config[scan_name]['aws_secret_key']+"' --aws_s3_bucket "+config[scan_name]['aws_s3_bucket']+" --aws_region "+config[scan_name]['aws_region']+" --enable_tracking_tags"
    elif scan_type == 'aws-cspm':
        twigs_cmd = twigs_cmd + " aws_cis --assetid "+config[scan_name]['asset_id']+" --aws_access_key '"+config[scan_name]['aws_access_key']+"' --aws_secret_key '"+config[scan_name]['aws_secret_key']+"'"
    elif scan_type == 'ecr':
        aws_cmd = shutil.which('aws')
        aws_cmd = "AWS_ACCESS_KEY_ID='"+config[scan_name]['ecr_access_key']+"' AWS_SECRET_ACCESS_KEY='"+config[scan_name]['ecr_secret_key']+"' " + aws_cmd + " ecr get-login-password --region "+config[scan_name]['ecr_region']+" | docker login --username AWS --password-stdin '"+config[scan_name]['ecr_account']+".dkr.ecr."+config[scan_name]['ecr_region']+".amazonaws.com'"
        twigs_cmd_prefix = "AWS_ACCESS_KEY_ID='"+config[scan_name]['ecr_access_key']+"' AWS_SECRET_ACCESS_KEY='"+config[scan_name]['ecr_secret_key']+"' AWS_DEFAULT_REGION="+config[scan_name]['ecr_region']
        twigs_cmd = twigs_cmd_prefix + " " + twigs_cmd + " ecr --registry "+config[scan_name]['ecr_account']+" --check_all_vulns"
        twigs_cmd = aws_cmd + " && " + twigs_cmd
    elif scan_type == 'azure':
        azure_cmd = shutil.which('az')
        azure_cmd = azure_cmd + " login --service-principal -u '%s' -p '%s' --tenant '%s'" % (config[scan_name]['azure_sp'], config[scan_name]['azure_sp_secret'], config[scan_name]['azure_tenant'])
        twigs_cmd = twigs_cmd + " azure --azure_workspace '"+config[scan_name]['azure_workspace']+"' --enable_tracking_tags"
        twigs_cmd = azure_cmd + " && " + twigs_cmd
    elif scan_type == 'azure-cspm':
        azure_cmd = shutil.which('az')
        azure_cmd = azure_cmd + " login --service-principal -u '%s' -p '%s' --tenant '%s'" % (config[scan_name]['azure_cspm_sp'], config[scan_name]['azure_cspm_sp_secret'], config[scan_name]['azure_cspm_tenant'])
        twigs_cmd = twigs_cmd + " azure_cis --assetid "+config[scan_name]['azure_cspm_asset_id']
        twigs_cmd = azure_cmd + " && " + twigs_cmd
    elif scan_type == 'acr':
        azure_cmd = shutil.which('az')
        azure_cmd = azure_cmd + " login --service-principal -u '%s' -p '%s' --tenant '%s'" % (config[scan_name]['acr_sp'], config[scan_name]['acr_sp_secret'], config[scan_name]['acr_tenant'])
        twigs_cmd = twigs_cmd + " acr --registry '"+config[scan_name]['acr_registry']+"' --check_all_vulns"
        twigs_cmd = azure_cmd + " && " + twigs_cmd
    elif scan_type == 'oci':
        twigs_cmd = twigs_cmd + " oci --config_file "+CONFIG_PATH+config[scan_name]['config_file']+" --enable_tracking_tags"
    elif scan_type == 'oci-cspm':
        twigs_cmd = twigs_cmd + " oci_cis --assetid "+config[scan_name]['asset_id']+" --config_file "+CONFIG_PATH+config[scan_name]['config_file']
    elif scan_type == 'ocr':
        docker_login_cmd = "echo '%s' | docker login 'ocir.%s.oci.oraclecloud.com' -u '%s' --password-stdin" % (config[scan_name]['docker_passwd'], config[scan_name]['region'], config[scan_name]['docker_login'])
        twigs_cmd = twigs_cmd + " ocr --region "+config[scan_name]['region']+" --config_file "+CONFIG_PATH+config[scan_name]['config_file']+" --check_all_vulns"
        twigs_cmd = docker_login_cmd + " && " + twigs_cmd
        if 'repository' in config[scan_name] and config[scan_name]['repository'] != '':
            twigs_cmd = twigs_cmd + " --repository "+config[scan_name]['repository']

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

def create_key_file(scan_name, private_key):
    global CONFIG_PATH

    pk_file_name = None
    if private_key and len(private_key) > 0:
        pk_file_name = CONFIG_PATH+scan_name+'.key'
        with open(pk_file_name, mode='w') as pk_file:
            pk_file.write(private_key)
    os.chmod(pk_file_name, 0o644)
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

def create_win_host_csv(scan_name, hostname, user, passwd):
    global CONFIG_PATH

    csv_file = CONFIG_PATH+scan_name+'.csv'
    with open(csv_file, mode='w') as csvfile:
         fieldnames = ['hostname','userlogin','userpwd']
         writer = csv.DictWriter(csvfile, fieldnames=fieldnames, quoting=csv.QUOTE_NONE, escapechar='\\')
         writer.writeheader()
         rdict = {}
         rdict['hostname'] = hostname
         rdict['userlogin'] = user
         rdict['userpwd'] = passwd
         writer.writerow(rdict)
    return os.path.basename(csv_file)

def create_oci_config(scan_name, userid, tenancy, region, key_file):
    global CONFIG_PATH

    # get fingerprint for private key
    cmd = "/usr/bin/openssl rsa -in "+CONFIG_PATH+key_file+" -pubout -outform DER | /usr/bin/openssl md5 -c "
    output = None
    try:
        output = subprocess.check_output(cmd, shell=True)
    except CalledProcessError as e:
        print(e.returncode)
        print(e.message)
        return None 
    output = output.decode('utf-8').strip()
    fingerprint = output.split("=")[1].strip()

    config_file_name = CONFIG_PATH+scan_name+'.config'
    with open(config_file_name, mode='w') as config_file:
        config_file.write("[DEFAULT]\n")
        config_file.write("user="+userid+"\n")
        config_file.write("fingerprint="+fingerprint+"\n")
        config_file.write("key_file="+CONFIG_PATH+key_file+"\n")
        config_file.write("tenancy="+tenancy+"\n")
        config_file.write("region="+region+"\n")
    os.chmod(config_file_name, 0o444)
    return os.path.basename(config_file_name)

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
    config['discovery_app']['log_level'] = 'info' 
    if 'debug_log' in request.form:
        config['discovery_app']['log_level'] = 'debug' 
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
        plan = request.form['zap_plan_yaml']
        if plan and len(plan) > 0:
            plan_file_name = CONFIG_PATH+scan_name+'.yaml'
            with open(plan_file_name, mode='w') as plan_file:
                plan_file.write(plan)
            config[scan_name]['plan_file'] = plan_file_name
        else:
            config[scan_name]['url'] = request.form['url']
        if 'webapp_no_ping' in request.form and request.form['webapp_no_ping'] == 'on':
            config[scan_name]['no_ping'] = 'on'
        else:
            config[scan_name]['no_ping'] = 'off'
    elif scan_type == 'nmap':
        config[scan_name]['hosts'] = request.form['hosts']
        items = request.form.items()
        stypes = []
        for key, value in request.form.items():
            if key.startswith('stype'):
                stypes.append(key.replace('stype_',''))
        if len(stypes) == 0:
            stypes = 'web'
        else:
            stypes = ' '.join(stypes)
        config[scan_name]['services'] = stypes
        config[scan_name]['extra_ports'] = request.form['extra_ports']
    elif scan_type == 'snmp':
        config[scan_name]['snmp_hosts'] = request.form['snmp_hosts']
        config[scan_name]['community_str'] = 'public'
        if 'community_str' in request.form and request.form['community_str'] != '':
            config[scan_name]['community_str'] = request.form['community_str']
        config[scan_name]['security_name'] = ''
        if 'security_name' in request.form and request.form['security_name'] != '':
            config[scan_name]['security_name'] = request.form['security_name']
    elif scan_type == 'printer':
        config[scan_name]['printer_hosts'] = request.form['printer_hosts']
    elif scan_type == 'cctv':
        config[scan_name]['cctv_hosts'] = request.form['cctv_hosts']
    elif scan_type == 'host':
        config[scan_name]['original_host_list'] = request.form['host_list']
        if 'user_private_key' in request.form:
            config[scan_name]['user_private_key'] = request.form['user_private_key']
        config[scan_name]['user_name'] = request.form['user_name']
        config[scan_name]['user_passwd'] = request.form['user_passwd']
        config[scan_name]['host_list'] = create_host_csv(scan_name, request.form['host_list'], request.form['user_name'], request.form['user_passwd'], request.form['user_private_key'])
    elif scan_type == 'win_host':
        config[scan_name]['original_win_host_list'] = request.form['win_host_list']
        config[scan_name]['win_user_name'] = request.form['win_user_name']
        config[scan_name]['win_user_passwd'] = request.form['win_user_passwd']
        config[scan_name]['win_host_list'] = create_win_host_csv(scan_name, request.form['win_host_list'], request.form['win_user_name'], request.form['win_user_passwd'])
    elif scan_type == 'vmware':
        config[scan_name]['vcenter_host'] = request.form['vcenter_host']
        config[scan_name]['vcenter_user'] = request.form['vcenter_user']
        config[scan_name]['vcenter_passwd'] = request.form['vcenter_passwd']
    elif scan_type == 'cisco_meraki':
        config[scan_name]['meraki_base_url'] = request.form['meraki_base_url']
        config[scan_name]['meraki_api_key'] = request.form['meraki_api_key']
    elif scan_type == 'cisco_dna_center':
        config[scan_name]['dna_center_url'] = request.form['dna_center_url']
        config[scan_name]['dna_center_user'] = request.form['dna_center_user']
        config[scan_name]['dna_center_password'] = request.form['dna_center_password']
    elif scan_type == 'defender':
        config[scan_name]['tenant_id'] = request.form['defender_tenant']
        config[scan_name]['app_id'] = request.form['defender_app_id']
        config[scan_name]['app_key'] = request.form['defender_app_key']
        config[scan_name]['all_devices'] = 'off'
        if 'defender_all_devices' in request.form:
            config[scan_name]['all_devices'] = 'on'
    elif scan_type == 'servicenow':
        config[scan_name]['snow_instance'] = request.form['snow_instance']
        if request.form['snow_client_id'] != None and request.form['snow_client_id'] != '':
            config[scan_name]['snow_client_id'] = request.form['snow_client_id']
            config[scan_name]['snow_client_secret'] = request.form['snow_client_secret']
        else:
            config[scan_name]['snow_user'] = request.form['snow_user']
            config[scan_name]['snow_password'] = request.form['snow_password']
    elif scan_type == 'gitlab':
        config[scan_name]['access_token'] = request.form['gitlab_access_token']
        config[scan_name]['server'] = request.form['gitlab_server']
        config[scan_name]['sast'] = 'off'
        config[scan_name]['secrets'] = 'off'
        config[scan_name]['iac'] = 'off'
        config[scan_name]['nocode'] = 'off'
        if 'gl_sast' in request.form :
            config[scan_name]['sast'] = 'on'
        if 'gl_secrets' in request.form:
            config[scan_name]['secrets'] = 'on'
        if 'gl_iac' in request.form:
            config[scan_name]['iac'] = 'on'
        if 'gl_nocode' in request.form:
            config[scan_name]['nocode'] = 'on'
    elif scan_type == 'github':
        config[scan_name]['access_token'] = request.form['github_access_token']
        config[scan_name]['identity'] = request.form['github_identity']
        config[scan_name]['api_url'] = request.form['github_url']
        config[scan_name]['sast'] = 'off'
        config[scan_name]['secrets'] = 'off'
        config[scan_name]['iac'] = 'off'
        config[scan_name]['nocode'] = 'off'
        if 'gh_sast' in request.form:
            config[scan_name]['sast'] = 'on'
        if 'gh_secrets' in request.form:
            config[scan_name]['secrets'] = 'on'
        if 'gh_iac' in request.form:
            config[scan_name]['iac'] = 'on'
        if 'gh_nocode' in request.form:
            config[scan_name]['nocode'] = 'on'
    elif scan_type == 'bitbucket':
        config[scan_name]['user'] = request.form['bb_user']
        config[scan_name]['app_password'] = request.form['bb_app_password']
        config[scan_name]['url'] = request.form['bb_url']
        config[scan_name]['sast'] = 'off'
        config[scan_name]['secrets'] = 'off'
        config[scan_name]['iac'] = 'off'
        config[scan_name]['nocode'] = 'off'
        if 'bb_sast' in request.form:
            config[scan_name]['sast'] = 'on'
        if 'bb_secrets' in request.form:
            config[scan_name]['secrets'] = 'on'
        if 'bb_iac' in request.form:
            config[scan_name]['iac'] = 'on'
        if 'bb_nocode' in request.form:
            config[scan_name]['nocode'] = 'on'
    elif scan_type == 'gcp':
        config[scan_name]['private_key'] = request.form['gcp_private_key']
        config[scan_name]['key_file'] = create_key_file(scan_name, request.form['gcp_private_key'])
    elif scan_type == 'gcp-cspm':
        config[scan_name]['asset_id'] = request.form['gcp_cspm_asset_id']
        config[scan_name]['key_file'] = create_key_file(scan_name, request.form['gcp_cspm_private_key'])
        config[scan_name]['private_key'] = request.form['gcp_cspm_private_key']
    elif scan_type == 'gcr':
        config[scan_name]['gcr_repo'] = request.form['gcr_repo']
        config[scan_name]['private_key'] = request.form['gcr_private_key']
        config[scan_name]['key_file'] = create_key_file(scan_name, request.form['gcr_private_key'])
    elif scan_type == 'aws':
        config[scan_name]['aws_account'] = request.form['aws_account']
        config[scan_name]['aws_access_key'] = request.form['aws_access_key']
        config[scan_name]['aws_secret_key'] = request.form['aws_secret_key']
        config[scan_name]['aws_s3_bucket'] = request.form['aws_s3_bucket']
        config[scan_name]['aws_region'] = request.form['aws_region']
    elif scan_type == 'aws-cspm':
        config[scan_name]['asset_id'] = request.form['aws_cspm_asset_id']
        config[scan_name]['aws_access_key'] = request.form['aws_cspm_access_key']
        config[scan_name]['aws_secret_key'] = request.form['aws_cspm_secret_key']
    elif scan_type == 'ecr':
        config[scan_name]['ecr_account'] = request.form['ecr_account']
        config[scan_name]['ecr_access_key'] = request.form['ecr_access_key']
        config[scan_name]['ecr_secret_key'] = request.form['ecr_secret_key']
        config[scan_name]['ecr_region'] = request.form['ecr_region']
    elif scan_type == 'azure':
        config[scan_name]['azure_sp'] = request.form['azure_sp']
        config[scan_name]['azure_sp_secret'] = request.form['azure_sp_secret']
        config[scan_name]['azure_tenant'] = request.form['azure_tenant']
        config[scan_name]['azure_workspace'] = request.form['azure_workspace']
    elif scan_type == 'azure-cspm':
        config[scan_name]['azure_cspm_asset_id'] = request.form['azure_cspm_asset_id']
        config[scan_name]['azure_cspm_sp'] = request.form['azure_cspm_sp']
        config[scan_name]['azure_cspm_sp_secret'] = request.form['azure_cspm_sp_secret']
        config[scan_name]['azure_cspm_tenant'] = request.form['azure_cspm_tenant']
    elif scan_type == 'acr':
        config[scan_name]['acr_registry'] = request.form['acr_registry']
        config[scan_name]['acr_sp'] = request.form['acr_sp']
        config[scan_name]['acr_sp_secret'] = request.form['acr_sp_secret']
        config[scan_name]['acr_tenant'] = request.form['acr_tenant']
    elif scan_type == 'oci':
        config[scan_name]['oci_user'] = request.form['oci_user']
        config[scan_name]['oci_tenancy'] = request.form['oci_tenancy']
        config[scan_name]['oci_region'] = request.form['oci_region']
        config[scan_name]['oci_user_private_key'] = request.form['oci_user_private_key']
        key_file = create_key_file(scan_name, request.form['oci_user_private_key'])
        config[scan_name]['key_file'] = key_file
        config_file_name = create_oci_config(scan_name, request.form['oci_user'], request.form['oci_tenancy'], request.form['oci_region'], key_file)
        config[scan_name]['config_file'] = config_file_name
    elif scan_type == 'oci-cspm':
        config[scan_name]['oci_cspm_user'] = request.form['oci_cspm_user']
        config[scan_name]['oci_cspm_tenancy'] = request.form['oci_cspm_tenancy']
        config[scan_name]['oci_cspm_region'] = request.form['oci_cspm_region']
        config[scan_name]['oci_cspm_user_private_key'] = request.form['oci_cspm_user_private_key']
        key_file = create_key_file(scan_name, request.form['oci_cspm_user_private_key'])
        config[scan_name]['key_file'] = key_file
        config_file_name = create_oci_config(scan_name, request.form['oci_cspm_user'], request.form['oci_cspm_tenancy'], request.form['oci_cspm_region'], key_file)
        config[scan_name]['config_file'] = config_file_name
        config[scan_name]['asset_id'] = request.form['oci_cspm_asset_id']
    elif scan_type == 'ocr':
        key_file = create_key_file(scan_name, request.form['ocr_user_private_key'])
        config[scan_name]['key_file'] = key_file
        config_file_name = create_oci_config(scan_name, request.form['ocr_user'], request.form['ocr_tenancy'], request.form['ocr_region'], key_file)
        config[scan_name]['config_file'] = config_file_name
        config[scan_name]['user'] = request.form['ocr_user'] 
        config[scan_name]['tenancy'] = request.form['ocr_tenancy'] 
        config[scan_name]['region'] = request.form['ocr_region'] 
        config[scan_name]['repository'] = request.form['ocr_repository'] 
        config[scan_name]['private_key'] = request.form['ocr_user_private_key'] 
        config[scan_name]['docker_login'] = request.form['ocr_docker_login'] 
        config[scan_name]['docker_passwd'] = request.form['ocr_docker_passwd'] 

    write_config(config)

def unload_cron():
    global CONFIG_PATH
    config = get_config()
    if 'purge_cron_on_exit' in config['discovery_app'] and config['discovery_app']['purge_cron_on_exit'] == 'yes':
        print("Unloading cron entries")
        with CronTab(user=True) as user_cron:
            # Get any existing jobs and remove those
            ejobs = user_cron.find_comment(re.compile(r'^TW_'))
            for ejob in ejobs:
                user_cron.remove(ejob)
