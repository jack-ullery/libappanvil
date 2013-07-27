#4093
#382-430
#480-525
# No old version logs, only 2.6 + supported
#global variable names corruption
from __future__ import with_statement
import inspect
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
import atexit
import tempfile

import apparmor.config
import apparmor.severity
import LibAppArmor

from apparmor.common import (AppArmorException, error, debug, msg, 
                             open_file_read, readkey, valid_path,
                             hasher, open_file_write)

from apparmor.ui import *

DEBUGGING = False
debug_logger = None

# Setup logging incase of debugging is enabled
if os.getenv('LOGPROF_DEBUG', False):
    DEBUGGING = True
    logprof_debug = '/var/log/apparmor/logprof.log'
    logging.basicConfig(filename=logprof_debug, level=logging.DEBUG)
    debug_logger = logging.getLogger('logprof')


CONFDIR = '/etc/apparmor'
running_under_genprof = False
unimplemented_warning = False

# The database for severity
sev_db = None
# The file to read log messages from
### Was our
filename = None

cfg = None
repo_cfg = None

parser = None
ldd = None
logger = None
profile_dir = None
extra_profile_dir = None
### end our
# To keep track of previously included profile fragments
include = dict()

existing_profiles = dict()

seen_events = 0     # was our
# To store the globs entered by users so they can be provided again
user_globs = []

## Variables used under logprof
### Were our
t = dict()   
transitions = dict() 
aa = dict()  # Profiles originally in sd, replace by aa
original_aa =  dict()
extras = dict()  # Inactive profiles from extras
### end our
log = []
pid = None

seen = dir()
profile_changes = dict()
prelog = dict()
log_dict = hasher()#dict()
changed = dict()
created = []
helpers = dict() # Preserve this between passes # was our
### logprof ends

filelist = dict()    # File level variables and stuff in config files

AA_MAY_EXEC = 1
AA_MAY_WRITE = 2
AA_MAY_READ = 4
AA_MAY_APPEND = 8
AA_MAY_LINK = 16
AA_MAY_LOCK = 32
AA_EXEC_MMAP = 64
AA_EXEC_UNSAFE = 128
AA_EXEC_INHERIT = 256
AA_EXEC_UNCONFINED = 512
AA_EXEC_PROFILE = 1024
AA_EXEC_CHILD = 2048
AA_EXEC_NT = 4096
AA_LINK_SUBSET = 8192
AA_OTHER_SHIFT = 14
AA_USER_MASK = 16384 - 1

AA_EXEC_TYPE = (AA_MAY_EXEC | AA_EXEC_UNSAFE | AA_EXEC_INHERIT |
                AA_EXEC_UNCONFINED | AA_EXEC_PROFILE | AA_EXEC_CHILD | AA_EXEC_NT)

ALL_AA_EXEC_TYPE = AA_EXEC_TYPE # The same value

# Modes and their values
MODE_HASH = {'x': AA_MAY_EXEC, 'X': AA_MAY_EXEC, 
             'w': AA_MAY_WRITE, 'W': AA_MAY_WRITE,
             'r': AA_MAY_READ, 'R': AA_MAY_READ,
             'a': AA_MAY_APPEND, 'A': AA_MAY_APPEND,
             'l': AA_MAY_LINK, 'L': AA_MAY_LINK,
             'k': AA_MAY_LOCK, 'K': AA_MAY_LOCK,
             'm': AA_EXEC_MMAP, 'M': AA_EXEC_MMAP,
             'i': AA_EXEC_INHERIT, 'I': AA_EXEC_INHERIT,
             'u': AA_EXEC_UNCONFINED + AA_EXEC_UNSAFE,  # Unconfined + Unsafe
              'U': AA_EXEC_UNCONFINED,
              'p': AA_EXEC_PROFILE + AA_EXEC_UNSAFE,    # Profile + unsafe
              'P': AA_EXEC_PROFILE,
              'c': AA_EXEC_CHILD + AA_EXEC_UNSAFE,  # Child + Unsafe
              'C': AA_EXEC_CHILD,
              'n': AA_EXEC_NT + AA_EXEC_UNSAFE,
              'N': AA_EXEC_NT
              }

# Used by netdomain to identify the operation types
OPERATION_TYPES = {
                   # New socket names
                   'create': 'net',
                   'post_create': 'net',
                   'bind': 'net',
                   'connect': 'net',
                   'listen': 'net',
                   'accept': 'net',
                   'sendmsg': 'net',
                   'recvmsg': 'net',
                   'getsockname': 'net',
                   'getpeername': 'net',
                   'getsockopt': 'net',
                   'setsockopt': 'net',
                   'sock_shutdown': 'net'
                   }

ARROWS = {'A': 'UP', 'B': 'DOWN', 'C': 'RIGHT', 'D': 'LEFT'}

def on_exit():
    """Shutdowns the logger and records exit if debugging enabled"""
    if DEBUGGING:
        debug_logger.debug('Exiting..')
        logging.shutdown()
        
# Register the on_exit method with atexit
atexit.register(on_exit)

def op_type(operation):
    """Returns the operation type if known, unkown otherwise"""
    operation_type = OPERATION_TYPES.get(operation, 'unknown')
    return operation_type

def getkey():
    key = readkey()
    if key == '\x1B':
        key = readkey()
        if key == '[':
            key = readkey()
            if(ARROWS.get(key, False)):
                key = ARROWS[key]
    return key

def check_for_LD_XXX(file):
    """Returns True if specified program contains references to LD_PRELOAD or 
    LD_LIBRARY_PATH to give the Px/Ux code better suggestions"""
    found = False
    if not os.path.isfile(file):
        return False
    size = os.stat(file).st_size
    # Limit to checking files under 100k for the sake of speed
    if size >100000:
        return False
    with open_file_read(file) as f_in:
        for line in f_in:
            if 'LD_PRELOAD' in line or 'LD_LIBRARY_PATH' in line:
                found = True
    return found

def fatal_error(message):
    if DEBUGGING:
        # Get the traceback to the message
        tb_stack = traceback.format_list(traceback.extract_stack())
        tb_stack = ''.join(tb_stack)
        # Append the traceback to message
        message = message + '\n' + tb_stack
        debug_logger.error(message)
    caller = inspect.stack()[1][3]
    
    # If caller is SendDataToYast or GetDatFromYast simply exit
    if caller == 'SendDataToYast' or caller== 'GetDatFromYast':
        sys.exit(1)
    
    # Else tell user what happened
    UI_Important(message)
    shutdown_yast()
    sys.exit(1)
     
def check_for_apparmor():
    """Finds and returns the mointpoint for apparmor None otherwise"""
    filesystem = '/proc/filesystems'
    mounts = '/proc/mounts'
    support_securityfs = False
    aa_mountpoint = None
    regex_securityfs = re.compile('^\S+\s+(\S+)\s+securityfs\s')
    if valid_path(filesystem):
        with open_file_read(filesystem) as f_in:
            for line in f_in:
                if 'securityfs' in line:
                    support_securityfs = True
    if valid_path(mounts):
        with open_file_read(mounts) as f_in:
            for line in f_in:
                if support_securityfs:
                    match = regex_securityfs.search(line)
                    if match:
                        mountpoint = match.groups()[0] + '/apparmor'
                        if valid_path(mountpoint):
                            aa_mountpoint = mountpoint    
    # Check if apparmor is actually mounted there
    if not valid_path(aa_mountpoint + '/profiles'):
        aa_mountpoint = None
    return aa_mountpoint

def which(file):
    """Returns the executable fullpath for the file, None otherwise"""
    env_dirs = os.getenv('PATH').split(':')
    for env_dir in env_dirs:
        env_path = env_dir + '/' + file
        # Test if the path is executable or not
        if os.access(env_path, os.X_OK):
            return env_path
    return None

def convert_regexp(regexp):
    ## To Do
    #regex_escape = re.compile('(?<!\\)(\.|\+|\$)')
    #regexp = regex_escape.sub('\\')
    new_reg = re.sub(r'(?<!\\)(\.|\+|\$)',r'\\\1',regexp)
    
    new_reg = new_reg.replace('?', '[^/\000]')
    dup='_SGDHBGFHFGFJFGBVHGFFGHF_MFMFH_'
    new_reg = new_reg.replace('**', dup)
    #de_dup=r'((?<=/)[^\000]*|(?<!/)[^\000]+)'
    de_dup=r'((?<=/).*|(?<!/).+)'
    #new_reg = new_reg.replace('*', r'((?<=/)[^/\000]*|(?<!/)[^/\000]+)')
    new_reg = new_reg.replace('*', r'((?<=/)[^/]*|(?<!/)[^/]+)')
    new_reg = new_reg.replace(dup, de_dup)
    return new_reg
    
    
def get_full_path(original_path):
    """Return the full path after resolving any symlinks"""
    path = original_path
    link_count = 0
    if not path.startswith('/'):
        path = os.getcwd() + '/' + path
    while os.path.islink(path):
        link_count += 1
        if link_count > 64:
            fatal_error("Followed too many links while resolving %s" % (original_path))
        direc, file = os.path.split(path)
        link = os.readlink(path)
        # If the link an absolute path
        if link.startswith('/'):
            path = link
        else:
            # Link is relative path
            path = direc + '/' + link
    return os.path.realpath(path)

def find_executable(bin_path):
    """Returns the full executable path for the binary given, None otherwise"""
    full_bin = None
    if os.path.exists(bin_path):
        full_bin = get_full_path(bin_path)
    else:
        if '/' not in bin_path:
            env_bin = which(bin_path)
            if env_bin:
                full_bin = get_full_path(env_bin)
    if full_bin and os.path.exists(full_bin):
        return full_bin
    return None

def get_profile_filename(profile):
    """Returns the full profile name"""
    if profile.startswith('/'):
        # Remove leading /
        profile = profile[1:]
    else:
        profile = "profile_" + profile
    profile.replace('/', '.')
    full_profilename = profile_dir + '/' + profile
    return full_profilename

def name_to_prof_filename(prof_filename):
    """Returns the profile"""
    if prof_filename.startswith(profile_dir):
        profile = prof_filename.split(profile_dir, 1)[1]
        return (prof_filename, profile)
    else:
        bin_path = find_executable(prof_filename)
        if bin_path:
            prof_filename = get_profile_filename(bin_path)
            if os.path.isfile(prof_filename):
                return (prof_filename, bin_path)
            else:
                return None, None

def complain(path):
    """Sets the profile to complain mode if it exists"""
    prof_filename, name = name_to_prof_filename(path)
    if not prof_filename :
        fatal_error("Can't find %s" % path)
    UI_Info('Setting %s to complain mode.' % name)
    set_profile_flags(prof_filename, 'complain')
    
def enforce(path):
    """Sets the profile to complain mode if it exists"""
    prof_filename, name = name_to_prof_filename(path)
    if not prof_filename :
        fatal_error("Can't find %s" % path)
    UI_Info('Setting %s to enforce moode' % name)
    set_profile_flags(prof_filename, '')
    
def head(file):
    """Returns the first/head line of the file"""
    first = ''
    if os.path.isfile(file):
        with open_file_read(file) as f_in:
            first = f_in.readline().rstrip()
    return first

def get_output(params):
    """Returns the return code output by running the program with the args given in the list"""
    program = params[0]
    args = params[1:]
    ret = -1
    output = []
    # program is executable
    if os.access(program, os.X_OK):
        try:
            # Get the output of the program
            output = subprocess.check_output(params)
        except OSError as e:
            raise  AppArmorException("Unable to fork: %s\n\t%s" %(program, str(e)))
            # If exit-codes besides 0
        except subprocess.CalledProcessError as e:
            output = e.output
            output = output.decode('utf-8').split('\n')
            ret = e.returncode
        else:
            ret = 0
            output = output.decode('utf-8').split('\n')
    # Remove the extra empty string caused due to \n if present
    if len(output) > 1:
        output.pop()             
    return (ret, output)   
        
def get_reqs(file):
    """Returns a list of paths from ldd output"""
    pattern1 = re.compile('^\s*\S+ => (\/\S+)')
    pattern2 = re.compile('^\s*(\/\S+)')
    reqs = []
    ret, ldd_out = get_output([ldd, file])
    if ret == 0:
        for line in ldd_out:
            if 'not a dynamic executable' in line:
                break
            if 'cannot read header' in line:
                break
            if 'statically linked' in line:
                break
            match = pattern1.search(line)
            if match:
                reqs.append(match.groups()[0])
            else:
                match = pattern2.search(line)
                if match:
                    reqs.append(match.groups()[0])
    return reqs

def handle_binfmt(profile, path):
    """Modifies the profile to add the requirements"""
    reqs_processed = dict()
    reqs = get_reqs(path)
    while reqs:
        library = reqs.pop()
        if not reqs_processed.get(library, False):
            reqs.append(get_reqs(library))
            reqs_processed[library] = True
        combined_mode = match_prof_incs_to_path(profile, 'allow', library)
        if combined_mode:
            continue
        library = glob_common(library)
        if not library:
            continue
        try:
            profile['allow']['path'][library]['mode'] |= str_to_mode('mr')
        except TypeError:
            profile['allow']['path'][library]['mode'] = str_to_mode('mr')
        try:
            profile['allow']['path'][library]['audit'] |= 0 
        except TypeError:
            profile['allow']['path'][library]['audit'] = 0
        
def get_inactive_profile(local_profile):
    if extras.get(local_profile, False):
        return {local_profile: extras[local_profile]}
    return dict()

def create_new_profile(localfile):
    local_profile = hasher()
    local_profile[localfile]['flags'] = 'complain'
    local_profile[localfile]['include']['abstractions/base'] = 1 
    #local_profile = {
    #                 localfile: {
    #                           'flags': 'complain',
    #                           'include': {'abstraction/base': 1},
    #                           'allow': {'path': {}}
    #                           }
    #                 }
    if os.path.isfile(localfile):
        hashbang = head(localfile)
        if hashbang.startswith('#!'):
            interpreter_path = get_full_path(hashbang.lstrip('#!').strip())
            
            interpreter = re.sub('^(/usr)?/bin/[^/]', '', interpreter_path)
            
            local_profile[localfile]['allow']['path'][localfile]['mode'] = local_profile[localfile]['allow']['path'][localfile].get('mode', str_to_mode('r')) | str_to_mode('r')
            
            local_profile[localfile]['allow']['path'][localfile]['audit'] = local_profile[localfile]['allow']['path'][localfile].get('audit', 0)
            
            local_profile[localfile]['allow']['path'][interpreter_path]['mode'] = local_profile[localfile]['allow']['path'][interpreter_path].get('mode', str_to_mode('ix')) | str_to_mode('ix')                                                               
            
            local_profile[localfile]['allow']['path'][interpreter_path]['audit'] = local_profile[localfile]['allow']['path'][interpreter_path].get('audit', 0)

            if interpreter == 'perl':
                local_profile[localfile]['include']['abstractions/perl'] = True
            elif interpreter == 'python':
                local_profile[localfile]['include']['abstractions/python'] = True
            elif interpreter == 'ruby':
                local_profile[localfile]['include']['abstractions/ruby'] = True
            elif interpreter in ['bash', 'dash', 'sh']:
                local_profile[localfile]['include']['abstractions/bash'] = True
            handle_binfmt(local_profile[localfile], interpreter_path)
        else:
            
            local_profile[localfile]['allow']['path'][localfile]['mode'] = local_profile[localfile]['allow']['path'][localfile].get('mode', str_to_mode('mr')) | str_to_mode('mr')
            
            local_profile[localfile]['allow']['path'][localfile]['audit'] = local_profile[localfile]['allow']['path'][localfile].get('audit', 0)

            handle_binfmt(local_profile[localfile], localfile)
    # Add required hats to the profile if they match the localfile      
    for hatglob in cfg['required_hats'].keys():
        if re.search(hatglob, localfile):
            for hat in sorted(cfg['required_hats'][hatglob].split()):
                local_profile[hat]['flags'] = 'complain'
    
    created.append(localfile)
    if DEBUGGING:
        debug_logger.debug("Profile for %s:\n\t%s" % (localfile, local_profile.__str__()))
    return {localfile: local_profile}
    
def delete_profile(local_prof):
    """Deletes the specified file from the disk and remove it from our list"""
    profile_file = get_profile_filename(local_prof)
    if os.path.isfile(profile_file):
        os.remove(profile_file)
    if aa.get(local_prof, False):
        aa.pop(local_prof)
        
    prof_unload(local_prof)
        
def get_profile(prof_name):
    profile_data = None
    distro = cfg['repository']['distro']
    repo_url = cfg['repository']['url']
    local_profiles = []
    profile_hash = hasher()
    if repo_is_enabled():
        UI_BusyStart('Coonecting to repository.....')
        status_ok, ret = fetch_profiles_by_name(repo_url, distro, prof_name)
        UI_BusyStop()
        if status_ok:
            profile_hash = ret
        else:
            UI_Important('WARNING: Error fetching profiles from the repository')
    inactive_profile = get_inactive_profile(prof_name)
    if inactive_profile:
        uname = 'Inactive local profile for %s' % prof_name
        inactive_profile[prof_name][prof_name]['flags'] = 'complain'
        inactive_profile[prof_name][prof_name].pop('filename')
        profile_hash[uname]['username'] = uname
        profile_hash[uname]['profile_type'] = 'INACTIVE_LOCAL'
        profile_hash[uname]['profile'] = serialize_profile(inactive_profile[prof_name], prof_name)
        profile_hash[uname]['profile_data'] = inactive_profile
    # If no profiles in repo and no inactive profiles
    if not profile_hash.keys():
        return None
    options = []
    tmp_list = []
    preferred_present = False
    preferred_user = cfg['repository'].get('preferred_user', 'NOVELL')
    
    for p in profile_hash.keys():
        if profile_hash[p]['username'] == preferred_user:
            preferred_present = True
        else:
            tmp_list.append(profile_hash[p]['username'])
            
    if preferred_present:
        options.append(preferred_user)
    options += tmp_list
    
    q = dict()
    q['headers'] = ['Profile', prof_name]
    q['functions'] = ['CMD_VIEW_PROFILE', 'CMD_USE_PROFILE', 'CMD_CREATE_PROFILE',
                      'CMD_ABORT', 'CMD_FINISHED']
    q['default'] = "CMD_VIEW_PROFILE"
    q['options'] = options
    q['selected'] = 0
    
    ans = ''
    while 'CMD_USE_PROFILE' not in ans and 'CMD_CREATE_PROFILE' not in ans:
        ans, arg = UI_PromptUser(q)
        p = profile_hash[options[arg]]
        q['selected'] = options.index(options[arg])
        if ans == 'CMD_VIEW_PROFILE':
            if UI_mode == 'yast':
                SendDataToYast({
                                'type': 'dialogue-view-profile',
                                'user': options[arg],
                                'profile': p['profile'],
                                'profile_type': p['profile_type']
                                })
                ypath, yarg = GetDataFromYast()
            else:
                pager = get_pager()
                proc = subprocess.Popen(pager, stdin=subprocess.PIPE)
                proc.communicate('Profile submitted by %s:\n\n%s\n\n' % 
                                 (options[arg], p['profile']))
                proc.kill()
        elif ans == 'CMD_USE_PROFILE':
            if p['profile_type'] == 'INACTIVE_LOCAL':
                profile_data = p['profile_data']
                created.append(prof_name)
            else:
                profile_data = parse_repo_profile(prof_name, repo_url, p)
    return profile_data

def activate_repo_profiles(url, profiles, complain):
    read_profiles()
    try:
        for p in profiles:
            pname = p[0]
            profile_data = parse_repo_profile(pname, url, p[1])
            attach_profile_data(aa, profile_data)
            write_profile(pname)
            if complain:
                fname = get_profile_filename(pname)
                set_profile_flags(fname, 'complain')
                UI_Info('Setting %s to complain mode.' % pname)
    except Exception as e:
            sys.stderr.write("Error activating profiles: %s" % e)

def autodep(bin_name, pname=''):
    bin_full = None
    if not bin_name and pname.startswith('/'):
        bin_name = pname
    if not repo_cfg and not cfg['repository'].get('url', False):
        repo_cfg = read_config('repository.conf')
        if not repo_cfg.get('repository', False) or repo_cfg['repository']['enabled'] == 'later':
            UI_ask_to_enable_repo()
    if bin_name:
        bin_full = find_executable(bin_name)
        #if not bin_full:
        #    bin_full = bin_name
        #if not bin_full.startswith('/'):
            #return None
        # Return if exectuable path not found
        if not bin_full:
            return None
    pname = bin_full
    read_inactive_profile()
    profile_data = get_profile(pname)
    # Create a new profile if no existing profile
    if not profile_data:
        profile_data = create_new_profile(pname)
    file = get_profile_filename(pname)
    attach_profile_data(aa, profile_data)
    attach_profile_data(aa_original, profile_data)
    if os.path.isfile(profile_dir + '/tunables/global'):
        if not filelist.get(file, False):
            filelist.file = hasher()
        filelist[file][include]['tunables/global'] = True
    write_profile_ui_feedback(pname)
    
def set_profile_flags(prof_filename, newflags):
    """Reads the old profile file and updates the flags accordingly"""
    regex_bin_flag = re.compile('^(\s*)(("??\/.+?"??)|(profile\s+("??.+?"??)))\s+(flags=\(.+\)\s+)*\{\s*$/')
    regex_hat_flag = re.compile('^([a-z]*)\s+([A-Z]*)((\s+#\S*)*)\s*$')
    a=re.compile('^([a-z]*)\s+([A-Z]*)((\s+#\S*)*)\s*$')
    regex_hat_flag = re.compile('^(\s*\^\S+)\s+(flags=\(.+\)\s+)*\{\s*(#*\S*)$')
    if os.path.isfile(prof_filename):
        with open_file_read(prof_filename) as f_in:
            tempfile = tempfile.NamedTemporaryFile('w', prefix=prof_filename , suffix='~', delete=False, dir='/etc/apparmor.d/')
            shutil.copymode('/etc/apparmor.d/' + prof_filename, tempfile.name)
            with open_file_write(tempfile.name) as f_out:
                for line in f_in:
                    if '#' in line:
                        comment = '#' + line.split('#', 1)[1].rstrip()
                    else:
                        comment = ''
                    match = regex_bin_flag.search(line)
                    if match:
                        space, binary, flags = match.groups()
                        if newflags:
                            line = '%s%s flags=(%s) {%s\n' % (space, binary, newflags, comment)
                        else:
                            line = '%s%s {%s\n' % (space, binary, comment)
                    else:
                        match = regex_hat_flag.search(line)
                        if match:
                            hat, flags = match.groups()
                            if newflags:
                                line = '%s flags=(%s) {%s\n' % (hat, newflags, comment)
                            else:
                                line = '%s {%s\n' % (hat, comment)
                    f_out.write(line)
        os.rename(tempfile.name, prof_filename)

def profile_exists(program):
    """Returns True if profile exists, False otherwise"""
    # Check cache of profiles
    if existing_profiles.get(program, False):
        return True
    # Check the disk for profile
    prof_path = get_profile_filename(program)
    if os.path.isfile(prof_path):
        # Add to cache of profile
        existing_profiles[program] = True
        return True
    return False

def sync_profile():
    user, passw = get_repo_user_pass()
    if not user or not passw:
        return None
    repo_profiles = []
    changed_profiles = []
    new_profiles = []
    serialize_opts = hasher()
    status_ok, ret = fetch_profiles_by_user(cfg['repository']['url'],
                                            cfg['repository']['distro'], user)
    if not status_ok:
        if not ret:
            ret = 'UNKNOWN ERROR'
        UI_Important('WARNING: Error synchronizing profiles with the repository:\n%s\n' % ret)
    else:
        users_repo_profiles = ret
        serialize_opts['NO_FLAGS'] = True
        for prof in sorted(aa.keys()):
            if is_repo_profile([aa[prof][prof]]):
                repo_profiles.append(prof)
            if prof in created:
                p_local = serialize_profile(aa[prof], prof, serialize_opts)
                if not users_repo_profiles.get(prof, False):
                    new_profiles.append(prof)
                    new_profiles.append(p_local)
                    new_profiles.append('')
                else:
                    p_repo = users_repo_profiles[prof]['profile']
                    if p_local != p_repo:
                        changed_profiles.append(prof)
                        changed_profiles.append(p_local)
                        changed_profiles.append(p_repo)
        if repo_profiles:
            for prof in repo_profiles:
                p_local = serialize_profile(aa[prof], prof, serialize_opts)
                if not users_repo_profiles.get(prof, False):
                    new_profiles.append(prof)
                    new_profiles.append(p_local)
                    new_profiles.append('')
                else:
                    p_repo = ''
                    if aa[prof][prof]['repo']['user'] == user:
                        p_repo = users_repo_profiles[prof]['profile']
                    else:
                        status_ok, ret = fetch_profile_by_id(cfg['repository']['url'],
                                                             aa[prof][prof]['repo']['id'])
                        if status_ok:
                            p_repo = ret['profile']
                        else:
                            if not ret:
                                ret = 'UNKNOWN ERROR'
                            UI_Important('WARNING: Error synchronizing profiles witht he repository\n%s\n' % ret)
                            continue
                    if p_repo != p_local:
                        changed_profiles.append(prof)
                        changed_profiles.append(p_local)
                        changed_profiles.append(p_repo)
        if changed_profiles:
            submit_changed_profiles(changed_profiles)
        if new_profiles:
            submit_created_profiles(new_profiles)
        
def submit_created_profiles(new_profiles):
    #url = cfg['repository']['url']
    if new_profiles:
        if UI_mode == 'yast':
            title = 'New Profiles'
            message = 'Please select the newly created profiles that you would like to store in the repository'
            yast_select_and_upload_profiles(title, message, new_profiles)
        else:
            title = 'Submit newly created profiles to the repository'
            message = 'Would you like to upload newly created profiles?'
            console_select_and_upload_profiles(title, message, new_profiles)

def submit_changed_profiles(changed_profiles):
    #url = cfg['repository']['url']
    if changed_profiles:
        if UI_mode == 'yast':
            title = 'Changed Profiles'
            message = 'Please select which of the changed profiles would you like to upload to the repository'
            yast_select_and_upload_profiles(title, message, changed_profiles)
        else:
            title = 'Submit changed profiles to the repository'
            message = 'The following profiles from the repository were changed.\nWould you like to upload your changes?'
            console_select_and_upload_profiles(title, message, changed_profiles)

def yast_select_and_upload_profiles(title, message, profiles_up):
    url = cfg['repository']['url']
    profile_changes = hasher()
    profs = profiles_up[:]
    for p in profs:
        profile_changes[p[0]] = get_profile_diff(p[2], p[1])
    SendDataToYast({
                    'type': 'dialog-select-profiles',
                    'title': title,
                    'explanation': message,
                    'default_select': 'false',
                    'disable_ask_upload': 'true',
                    'profiles': profile_changes
                    })
    ypath, yarg = GetDataFromYast()
    selected_profiles = []
    changelog = None
    changelogs = None
    single_changelog = False
    if yarg['STATUS'] == 'cancel':
        return
    else:
        selected_profiles = yarg['PROFILES']
        changelogs = yarg['CHANGELOG']
        if changelogs.get('SINGLE_CHANGELOG', False):
            changelog = changelogs['SINGLE_CHANGELOG']
            single_changelog = True
    user, passw = get_repo_user_pass()
    for p in selected_profiles:
        profile_string = serialize_profile(aa[p], p)
        if not single_changelog:
            changelog = changelogs[p]
        status_ok, ret = upload_profile(url, user, passw, cfg['repository']['distro'],
                                        p, profile_string, changelog)
        if status_ok:
            newprofile = ret
            newid = newprofile['id']
            set_repo_info(aa[p][p], url, user, newid)
            write_profile_ui_feedback(p)
        else:
            if not ret:
                ret = 'UNKNOWN ERROR'
            UI_Important('WARNING: An error occured while uploading the profile %s\n%s\n' % (p, ret))
    UI_Info('Uploaded changes to repository.')
    if yarg.get('NEVER_ASK_AGAIN'):
        unselected_profiles = []
        for p in profs:
            if p[0] not in selected_profiles:
                unselected_profiles.append(p[0])
        set_profiles_local_only(unselected_profiles)

def console_select_and_upload_profiles(title, message, profiles_up):
    url = cfg['repository']['url']
    profs = profiles_up[:]
    q = hasher()
    q['title'] = title
    q['headers'] = ['Repository', url]
    q['explanation'] = message
    q['functions'] = ['CMD_UPLOAD_CHANGES', 'CMD_VIEW_CHANGES', 'CMD_ASK_LATER',
                      'CMD_ASK_NEVER', 'CMD_ABORT']
    q['default'] = 'CMD_VIEW_CHANGES'
    q['options'] = [i[0] for i in profs]
    q['selected'] = 0
    ans = ''
    while 'CMD_UPLOAD_CHANGES' not in ans and 'CMD_ASK_NEVER' not in ans and 'CMD_ASK_LATER' not in ans:
        ans, arg = UI_PromptUser(q)
        if ans == 'CMD_VIEW_CHANGES':
            display_changes(profs[arg][2], profs[arg][1])
    if ans == 'CMD_NEVER_ASK':
        set_profiles_local_only([i[0] for i in profs])
    elif ans == 'CMD_UPLOAD_CHANGES':
        changelog = UI_GetString('Changelog Entry: ', '')
        user, passw = get_repo_user_pass()
        if user and passw:
            for p_data in profs:
                prof = p_data[0]
                prof_string = p_data[1]
                status_ok, ret = upload_profile(url, user, passw, 
                                                cfg['repository']['distro'],
                                                prof, prof_string, changelog )
                if status_ok:
                    newprof = ret
                    newid = newprof['id']
                    set_repo_info(aa[prof][prof], url, user, newid)
                    write_profile_ui_feedback(prof)
                    UI_Info('Uploaded %s to repository' % prof)
                else:
                    if not ret:
                        ret = 'UNKNOWN ERROR'
                    UI_Important('WARNING: An error occured while uploading the profile %s\n%s\n' % (prof, ret))
        else:
            UI_Important('Repository Error\nRegistration or Sigin was unsuccessful. User login\n' + 
                         'information is required to upload profiles to the repository.\n' +
                         'These changes could not be sent.\n')

def set_profile_local_only(profs):
    for p in profs:
        aa[profs][profs]['repo']['neversubmit'] = True
        writeback_ui_feedback(profs)

def confirm_and_abort():
    ans = UI_YesNo('Are you sure you want to abandon this set of profile changes and exit?', 'n')
    if ans == 'y':
        UI_Info('Abandoning all changes.')
        shutdown_yast()
        for prof in created:
            delete_profile(prof)
        sys.exit(0)

def confirm_and_finish():
    sys.stdout.write('Finishing\n')
    sys.exit(0)

def build_x_functions(default, options, exec_toggle):
    ret_list = []
    if exec_toggle:
        if 'i' in options:
            ret_list.append('CMD_ix')
            if 'p' in options:
                ret_list.append('CMD_pix')
                ret_list.append('CMD_EXEC_IX_OFF')
            elif 'c' in options:
                ret_list.append('CMD_cix')
                ret_list.append('CMD_EXEC_IX_OFF')
            elif 'n' in options:
                ret_list.append('CMD_nix')
                ret_list.append('CMD_EXEC_IX_OFF')
        elif 'u' in options:
            ret_list.append('CMD_ux')
    else:
        if 'i' in options:
            ret_list.append('CMD_ix')
        elif 'c' in options:
            ret_list.append('CMD_cx')
            ret_list.append('CMD_EXEC_IX_ON')
        elif 'p' in options:
            ret_list.append('CMD_px')
            ret_list.append('CMD_EXEC_IX_OFF')
        elif 'n' in options:
            ret_list.append('CMD_nx')
            ret_list.append('CMD_EXEC_IX_OFF')
        elif 'u' in options:
            ret_list.append('CMD_ux')
    ret_list += ['CMD_DENY', 'CMD_ABORT', 'CMD_FINISHED']
    return ret_list

def handle_children(profile, hat, root):
    entries = root[:]
    pid = None
    p = None
    h = None
    prog = None
    aamode = None
    mode = None
    detail = None
    to_name = None
    uhat = None
    capability = None
    family = None
    sock_type = None
    protocol = None
    regex_nullcomplain = re.compile('^null(-complain)*-profile$')
    
    for entry in entries:
        if type(entry[0]) != str:
            handle_children(profile, hat, entry)
        else:
            typ = entry.pop(0)
            if typ == 'fork':
                pid, p, h = entry[:3]
                if not regex_nullcomplain.search(p) and not regex_nullcomplain.search(h):
                    profile = p
                    hat = h
                if hat:
                    profile_changes[pid] = profile + '//' + hat
                else:
                    profile_changes[pid] = profile
            elif type == 'unknown_hat':
                pid, p, h, aamode, uhat = entry[:5]
                if not regex_nullcomplain.search(p):
                    profile = p
                if aa[profile].get(uhat, False):
                    hat = uhat
                    continue
                new_p = update_repo_profile(aa[profile][profile])
                if new_p and UI_SelectUpdatedRepoProfile(profile, new_p) and aa[profile].get(uhat, False):
                    hat = uhat
                    continue
                
                default_hat = None
                for hatglob in cfg.options('defaulthat'):
                    if re.search(hatglob, profile):
                        default_hat = cfg['defaulthat'][hatglob]
                
                context = profile
                context = context + ' -> ^%s' % uhat
                ans = transitions.get(context, 'XXXINVALIDXXX')
                
                while ans not in ['CMD_ADDHAT', 'CMD_USEDEFAULT', 'CMD_DENY']:
                    q = hasher()
                    q['headers'] = []
                    q['headers'] += [gettext('Profile'), profile]
                    
                    if default_hat:
                        q['headers'] += [gettext('Default Hat'), default_hat]
                    
                    q['headers'] += [gettext('Requested Hat'), uhat]
                    
                    q['functions'] = []
                    q['functions'].append('CMD_ADDHAT')
                    if default_hat:
                        q['functions'].append('CMD_USEDEFAULT')
                    q['functions'] += ['CMD_DENY', 'CMD_ABORT', 'CMD_FINISHED']
                    
                    q['default'] = 'CMD_DENY'
                    if aamode == 'PERMITTING':
                        q['default'] = 'CMD_ADDHAT'
                    
                    seen_events += 1
                    
                    ans = UI_PromptUser(q)
                
                transitions[context] = ans
                
                if ans == 'CMD_ADDHAT':
                    hat = uhat
                    aa[profile][hat]['flags'] = aa[profile][profile]['flags']
                elif ans == 'CMD_USEDEFAULT':
                    hat = default_hat
                elif ans == 'CMD_DENY':
                    return None
            
            elif type == 'capability':
                pid, p, h, prog, aamode, capability = entry[:6]
                if not regex_nullcomplain.search(p) and not regex_nullcomplain.search(h):
                    profile = p
                    hat = h
                if not profile or not hat:
                    continue
                prelog[aamode][profile][hat]['capability'][capability] = True
            
            elif type == 'path' or type == 'exec':
                pid, p, h, prog, aamode, mode, detail, to_name = entry[:8]
                
                if not mode:
                    mode = 0
                if not regex_nullcomplain.search(p) and not regex_nullcomplain.search(h):
                    profile = p
                    hat = h
                if not profile or not hat or not detail:
                    continue
                
                domainchange = 'nochange'
                if type == 'exec':
                    domainchange = 'change'

                # Escape special characters
                detail = detail.replace('[', '\[')
                detail = detail.replace(']', '\]')
                detail = detail.replace('+', '\+')
                detail = detail.replace('*', '\*')
                detail = detail.replace('{', '\{')
                detail = detail.replace('}', '\}')
                
                # Give Execute dialog if x access requested for something that's not a directory 
                # For directories force an 'ix' Path dialog
                do_execute = False
                exec_target = detail
                
                if mode & str_to_mode('x'):
                    if os.path.isdir(exec_target):
                        mode = mode & (~ALL_AA_EXEC_TYPE)
                        mode = mode | str_to_mode('ix')
                    else:
                        do_execute = True
                
                if mode & AA_MAY_LINK:
                    regex_link = re.compile('^from (.+) to (.+)$')
                    match = regex_link.search(detail)
                    if match:
                        path = match.groups()[0]
                        target = match.groups()[1]
                        
                        frommode = str_to_mode('lr')
                        if prelog[aamode][profile][hat]['path'].get(path, False):
                            frommode |= prelog[aamode][profile][hat]['path'][path]
                        prelog[aamode][profile][hat]['path'][path] = frommode
                        
                        tomode = str_to_mode('lr')
                        if prelog[aamode][profile][hat]['path'].get(target, False):
                            tomode |= prelog[aamode][profile][hat]['path'][target]
                        prelog[aamode][profile][hat]['path'][target] = tomode    
                    else:
                        continue
                elif mode:
                    path = detail
                    
                    if prelog[aamode][profile][hat]['path'].get(path, False):
                        mode |= prelog[aamode][profile][hat]['path'][path]
                    prelog[aamode][profile][hat]['path'][path] = mode
                
                if do_execute:
                    if profile_known_exec(aa[profile][hat], 'exec', exec_target):
                        continue
                    
                    p = update_repo_profile(aa[profile][profile])
                    if to_name:
                        if UI_SelectUpdatedRepoProfile(profile, p) and profile_known_exec(aa[profile][hat], 'exec', to_name):
                            continue
                    else:
                        if UI_SelectUpdatedRepoProfile(profile, p) and profile_known_exec(aa[profile][hat], 'exec', exec_target):
                            continue
                    
                    context_new = profile
                    if profile != hat:
                        context_new = context_new + '^%s' % hat
                    context_new = context + ' ->%s' % exec_target
                    
                    ans_new = transitions.get(context_new, '')
                    combinedmode = False
                    combinedaudit = False
                    ## Check return Value Consistency
                    # Check if path matches any existing regexps in profile
                    cm, am , m = rematchfrag(aa[profile][hat], 'allow', exec_target)
                    if cm:
                        combinedmode |= cm
                    if am:
                        combinedaudit |= am
                    
                    if combinedmode & str_to_mode('x'):
                        nt_name = None
                        for entr in m:
                            if aa[profile][hat]['allow']['path'].get(entr, False):
                                nt_name = aa[profile][hat]
                                break
                        if to_name and to_name != nt_name:
                            pass
                        elif nt_name:
                            to_name = nt_name
                    ## Check return value consistency
                    # Check if the includes from profile match
                    cm, am, m = match_prof_incs_to_path(aa[profile][hat], 'allow', exec_target)
                    if cm:
                        combinedmode |= cm
                    if am:
                        combinedaudit |= am
                    if combinedmode & str_to_mode('x'):
                        nt_name = None
                        for entr in m:
                            if aa[profile][hat]['allow']['path'][entry]['to']:
                                int_name = aa[profile][hat]['allow']['path'][entry]['to']
                                break
                        if to_name and to_name != nt_name:
                            pass
                        elif nt_name:
                            to_name = nt_name
                    
                    # nx is not used in profiles but in log files.
                    # Log parsing methods will convert it to its profile form
                    # nx is internally cx/px/cix/pix + to_name
                    exec_mode = False
                    if contains(combinedmode, 'pix'):
                        if to_name:
                            ans = 'CMD_nix'
                        else:
                            ans = 'CMD_pix'
                        exec_mode = str_to_mode('pixr')
                    elif contains(combinedmode, 'cix'):
                        if to_name:
                            ans = 'CMD_nix'
                        else:
                            ans = 'CMD_cix'
                        exec_mode = str_to_mode('cixr')
                    elif contains(combinedmode, 'Pix'):
                        if to_name:
                            ans = 'CMD_nix_safe'
                        else:
                            ans = 'CMD_pix_safe'
                        exec_mode = str_to_mode('Pixr')
                    elif contains(combinedmode, 'Cix'):
                        if to_name:
                            ans = 'CMD_nix_safe'
                        else:
                            ans = 'CMD_cix_safe'
                        exec_mode = str_to_mode('Cixr')
                    elif contains(combinedmode, 'ix'):
                        ans = 'CMD_ix'
                        exec_mode = str_to_mode('ixr')
                    elif contains(combinedmode, 'px'):
                        if to_name:
                            ans = 'CMD_nx'
                        else:
                            ans = 'CMD_px'
                        exec_mode = str_to_mode('px')
                    elif contains(combinedmode, 'cx'):
                        if to_name:
                            ans = 'CMD_nx'
                        else:
                            ans = 'CMD_cx'
                        exec_mode = str_to_mode('cx')
                    elif contains(combinedmode, 'ux'):
                        ans = 'CMD_ux'
                        exec_mode = str_to_mode('ux')
                    elif contains(combinedmode, 'Px'):
                        if to_name:
                            ans = 'CMD_nx_safe'
                        else:
                            ans = 'CMD_px_safe'
                        exec_mode = str_to_mode('Px')
                    elif contains(combinedmode, 'Cx'):
                        if to_name:
                            ans = 'CMD_nx_safe'
                        else:
                            ans = 'CMD_cx_safe'
                        exec_mode = str_to_mode('Cx')
                    elif contains(combinedmode, 'Ux'):
                        ans = 'CMD_ux_safe'
                        exec_mode = str_to_mode('Ux')
                    else:
                        options = cfg['qualifiers'].get(exec_target, 'ipcnu')
                        if to_name:
                            fatal_error('%s has transition name but not transition mode' % entry)
                        
                        ### If profiled program executes itself only 'ix' option
                        ##if exec_target == profile:
                            ##options = 'i'
                        
                        # Don't allow hats to cx?
                        options.replace('c', '')
                        # Add deny to options
                        options += 'd'
                        # Define the default option
                        default = None
                        if 'p' in options and os.path.exists(get_profile_filename(exec_target)):
                            default = 'CMD_px'
                        elif 'i' in options:
                            default = 'CMD_ix'
                        elif 'c' in options:
                            default = 'CMD_cx'
                        elif 'n' in options:
                            default = 'CMD_nx'
                        else:
                            default = 'DENY'
                        
                        # 
                        parent_uses_ld_xxx = check_for_LD_XXX(profile)
                        
                        sev_db.unload_variables()
                        sev_db.load_variables(profile)
                        severity = sev_db.rank(exec_target, 'x')
                        
                        # Prompt portion starts
                        q = hasher()
                        q['headers'] = []
                        q['headers'] += [gettext('Profile'), combine_name(profile, hat)]
                        if prog and prog != 'HINT':
                            q['headers'] += [gettext('Program'), prog]
                        
                        # to_name should not exist here since, transitioning is already handeled
                        q['headers'] += [gettext('Execute'), exec_target]
                        q['headers'] += [gettext('Severity'), severity]
                        
                        q['functions'] = []
                        prompt = '\n%s\n' % context
                        exec_toggle = False
                        q['functions'].append(build_x_functions(default, options, exec_toggle)) 
                        
                        options = '|'.join(options)
                        seen_events += 1
                        regex_options = re.compile('^CMD_(ix|px|cx|nx|pix|cix|nix|px_safe|cx_safe|nx_safe|pix_safe|cix_safe|nix_safe|ux|ux_safe|EXEC_TOGGLE|DENY)$')
                        
                        while regex_options.search(ans):
                            ans = UI_PromptUser(q).strip()
                            if ans.startswith('CMD_EXEC_IX_'):
                                exec_toggle = not exec_toggle
                                q['functions'] = []
                                q['functions'].append(build_x_functions(default, options, exec_toggle))
                                ans = ''
                                continue
                            if ans == 'CMD_nx' or ans == 'CMD_nix':
                                arg = exec_target
                                ynans = 'n'
                                if profile == hat:
                                    ynans = UI_YesNo(gettext('Are you specifying a transition to a local profile?'), 'n')
                                if ynans == 'y':
                                    if ans == 'CMD_nx':
                                        ans = 'CMD_cx'
                                    else:
                                        ans = 'CMD_cix'
                                else:
                                    if ans == 'CMD_nx':
                                        ans = 'CMD_px'
                                    else:
                                        ans = 'CMD_pix'
                                
                                to_name = UI_GetString(gettext('Enter profile name to transition to: '), arg)
                            
                            regex_optmode = re.compile('CMD_(px|cx|nx|pix|cix|nix)')
                            if ans == 'CMD_ix':
                                exec_mode = str_to_mode('ix')
                            elif regex_optmode.search(ans):
                                match = regex_optmode.search(ans).groups()[0]
                                exec_mode = str_to_match(match)
                                px_default = 'n'
                                px_msg = gettext('Should AppArmor sanitise the environment when\n' +
                                                 'switching profiles?\n\n' + 
                                                 'Sanitising environment is more secure,\n' +
                                                 'but some applications depend on the presence\n' +
                                                 'of LD_PRELOAD or LD_LIBRARY_PATH.')
                                if parent_uses_ld_xxx:
                                    px_msg = gettext('Should AppArmor sanitise the environment when\n' +
                                                 'switching profiles?\n\n' + 
                                                 'Sanitising environment is more secure,\n' +
                                                 'but this application appears to be using LD_PRELOAD\n' +
                                                 'or LD_LIBRARY_PATH and sanitising the environment\n' +
                                                 'could cause functionality problems.')
                                
                                ynans = UI_YesNo(px_msg, px_default)
                                if ynans == 'y':
                                    # Disable the unsafe mode
                                    exec_mode &= ~(AA_EXEC_UNSAFE | (AA_EXEC_UNSAFE << AA_OTHER_SHIFT))
                            elif ans == 'CMD_ux':
                                exec_mode = str_to_mode('ux')
                                ynans = UI_YesNo(gettext('Launching processes in an unconfined state is a very\n' +
                                                        'dangerous operation and can cause serious security holes.\n\n' +
                                                        'Are you absolutely certain you wish to remove all\n' +
                                                        'AppArmor protection when executing :') + '%s ?' % exec_target, 'n')
                                if ynans == 'y':
                                    ynans = UI_YesNo(gettext('Should AppArmor sanitise the environment when\n' +
                                                             'running this program unconfined?\n\n' +
                                                             'Not sanitising the environment when unconfining\n' +
                                                             'a program opens up significant security holes\n' +
                                                             'and should be avoided if at all possible.'), 'y')
                                    if ynans == 'y':
                                        # Disable the unsafe mode
                                        exec_mode &= ~(AA_EXEC_UNSAFE | (AA_EXEC_UNSAFE << AA_OTHER_SHIFT))
                                else:
                                    ans = 'INVALID'
                        transitions[context] = ans
                        
                        regex_options = re.compile('CMD_(ix|px|cx|nx|pix|cix|nix)')
                        if regex_options.search(ans):
                            # For inherit we need r
                            if exec_mode & str_to_mode('i'):
                                exec_mode |= str_to_mode('r')
                        else:
                            if ans == 'CMD_DENY':
                                aa[profile][hat]['deny']['path'][exec_target]['mode'] = aa[profile][hat]['deny']['path'][exec_target].get('mode', str_to_mode('x')) | str_to_mode('x')
                                aa[profile][hat]['deny']['path'][exec_target]['audit'] = aa[profile][hat]['deny']['path'][exec_target].get('audit', 0)
                                changed[profile] = True
                                # Skip remaining events if they ask to deny exec
                                if domainchange == 'change':
                                    return None
                        
                        if ans != 'CMD_DENY':
                            prelog['PERMITTING'][profile][hat]['path'][exec_target] = prelog['PERMITTING'][profile][hat]['path'].get(exec_target, exec_mode) | exec_mode
                            
                            log_dict['PERMITTING'][profile] = hasher()
                            
                            aa[profile][hat]['allow']['path'][exec_target]['mode'] = aa[profile][hat]['allow']['path'][exec_target].get('mode', exec_mode)
                            
                            aa[profile][hat]['allow']['path'][exec_target]['audit'] = aa[profile][hat]['allow']['path'][exec_target].get('audit', 0)
                            
                            if to_name:
                                aa[profile][hat]['allow']['path'][exec_target]['to'] = to_name
                            
                            changed[profile] = True
                            
                            if exec_mode & str_to_mode('i'):
                                if 'perl' in exec_target:
                                    aa[profile][hat]['include']['abstractions/perl'] = True
                                elif '/bin/bash' in exec_path or '/bin/sh' in exec_path:
                                    aa[profile][hat]['include']['abstractions/bash'] = True
                                hashbang = head(exec_target)
                                if hashbang.startswith('#!'):
                                    interpreter = hashbang[2:].strip()
                                    interpreter_path = get_full_path(interpreter)
                                    interpreter = re.sub('^(/usr)?/bin/[^/]', '', interpreter_path)
                                    
                                    aa[profile][hat]['path'][interpreter_path]['mode'] = aa[profile][hat]['path'][interpreter_path].get('mode', str_to_mode('ix')) | str_to_mode('ix')
                                    
                                    aa[profile][hat]['path'][interpreter_path]['audit'] = aa[profile][hat]['path'][interpreter_path].get('audit', 0)
                                    
                                    if interpreter == 'perl':
                                        aa[profile][hat]['include']['abstractions/perl'] = True
                                    elif interpreter in ['bash', 'dash', 'sh']:
                                        aa[profile][hat]['include']['abstractions/bash'] = True
                    
                    # Update tracking info based on kind of change
                    
                    if ans == 'CMD_ix':
                        if hat:
                            profile_changes[pid] = '%s//%s' %(profile, hat)
                        else:
                            profile_changes[pid] = '%s//' % profile
                    elif re.search('^CMD_(px|nx|pix|nix)', ans):
                        if to_name:
                            exec_target = to_name
                        if aamode == 'PERMITTING':
                            if domainchange == 'change':
                                profile = exec_target
                                hat = exec_target
                                profile_changes[pid] = '%s' % profile
                        
                        # Check profile exists for px
                        if not os.path.exists(get_profile_filename(exec_target)):
                            ynans = 'y'
                            if exec_mode & str_to_mode('i'):
                                ynans = UI_YesNo(gettext('A profile for ') + str(exec_target) + gettext(' doesnot exist.\nDo you want to create one?'), 'n')
                            if ynans == 'y':
                                helpers[exec_target] = 'enforce'
                                if to_name:
                                    autodep_base('', exec_target)
                                else:
                                    autodep_base(exec_target, '')
                                reload_base(exec_target)
                    elif ans.startswith('CMD_cx') or ans.startswith('CMD_cix'):
                        if to_name:
                            exec_target = to_name
                        if aamode == 'PERMITTING':
                            if domainchange == 'change':
                                profile_changes[pid] = '%s//%s' % (profile, exec_target)
                        
                        if not aa[profile].get(exec_target, False):
                            ynans = 'y'
                            if exec_mode & str_to_mode('i'):
                                ynans = UI_YesNo(gettext('A local profile for %s does not exit. Create one') % exec_target, 'n')
                            if ynans == 'y':
                                hat = exec_target
                                aa[profile][hat]['declared'] = False
                                aa[profile][hat]['profile'] = True
                                
                                if profile != hat:
                                    aa[profile][hat]['flags'] = aa[profile][profile]['flags']
                                
                                stub_profile = create_new_profile(hat)
                                
                                aa[profile][hat]['flags'] = 'complain'
                                
                                aa[profile][hat]['allow']['path'] = hasher()
                                if stub_profile[hat][hat]['allow'].get('path', False):
                                    aa[profile][hat]['allow']['path'] = stub_profile[hat][hat]['allow']['path']
                                
                                aa[profile][hat]['include'] = hasher()
                                if stub_profile[hat][hat].get('include', False):
                                    aa[profile][hat]['include'] = stub_profile[hat][hat]['include']
                                
                                aa[profile][hat]['allow']['netdomain'] = hasher()
                                
                                file_name = aa[profile][profile]['filename']
                                filelist[file_name]['profiles'][profile][hat] = True
                    
                    elif ans.startswith('CMD_ux'):
                        profile_changes[pid] = 'unconfined'
                        if domainchange == 'change':
                            return None
            
            elif type == 'netdomain':
                pid, p, h, prog, aamode, family, sock_type, protocol = entry[:8]
                
                if not regex_nullcomplain.search(p) and not regex_nullcomplain.search(h):
                    profile = p
                    hat = h
                if not hat or not profile:
                    continue
                if family and sock_type:
                    prelog[aamode][profile][hat]['netdomain'][family][sock_type] = True
                    
    return None

def add_to_tree(loc_pid, parent, type, event):
    if DEBUGGING:
        debug_logger.info('add_to_tree: pid [%s] type [%s] event [%s]' % (pid, type, event))
    
    if not pid.get(loc_pid, False):
        profile, hat = event[:1]
        if parent and pid.get(parent, False):
            if not hat:
                hat = 'null-complain-profile'
            array_ref = ['fork', loc_pid, profile, hat]
            pid[parent].append(array_ref)
            pid[loc_pid] = array_ref
        #else:
        #    array_ref = []
        #    log.append(array_ref)
        #    pid[pid] = array_ref
    pid[loc_pid] += [type, loc_pid, event]

# Variables used by logparsing routines
LOG = None
next_log_entry = None
logmark = None
seenmark = None
#RE_LOG_v2_0_syslog = re.compile('SubDomain')
#RE_LOG_v2_1_syslog = re.compile('kernel:\s+(\[[\d\.\s]+\]\s+)?(audit\([\d\.\:]+\):\s+)?type=150[1-6]')
RE_LOG_v2_6_syslog = re.compile('kernel:\s+(\[[\d\.\s]+\]\s+)?type=\d+\s+audit\([\d\.\:]+\):\s+apparmor=')
#RE_LOG_v2_0_audit  = re.compile('type=(APPARMOR|UNKNOWN\[1500\]) msg=audit\([\d\.\:]+\):')
#RE_LOG_v2_1_audit  = re.compile('type=(UNKNOWN\[150[1-6]\]|APPARMOR_(AUDIT|ALLOWED|DENIED|HINT|STATUS|ERROR))')
RE_LOG_v2_6_audit = re.compile('type=AVC\s+(msg=)?audit\([\d\.\:]+\):\s+apparmor=')

LOG_MODE_RE = re.compile('r|w|l|m|k|a|x|ix|ux|px|cx|nx|pix|cix|Ix|Ux|Px|PUx|Cx|Nx|Pix|Cix')

def prefetch_next_log_entry():
    if next_log_entry:
        sys.stderr.out('A log entry already present: %s' % next_log_entry)
    next_log_entry = LOG.readline()
    while RE_LOG_v2_6_syslog.search(next_log_entry) or RE_LOG_v2_6_audit.search(next_log_entry) or re.search(logmark, next_log_entry):
        next_log_entry = LOG.readline()
        if not next_log_entry:
            break

def get_next_log_entry():
    # If no next log entry fetch it
    if not next_log_entry:
        prefetch_next_log_entry()
    log_entry = next_log_entry
    next_log_entry = None
    return log_entry

def peek_at_next_log_entry():
    # Take a peek at the next log entry
    if not next_log_entry:
        prefetch_next_log_entry()
    return next_log_entry

def throw_away_next_log_entry():
    next_log_entry = None

def parse_log_record(record):
    if DEBUGGING:
        debug_logger.debug('parse_log_record: %s' % record)
    
    record_event = parse_event(record)
    return record_event

def add_event_to_tree(e):
    aamode = e.get('aamode', 'UNKNOWN')
    if e.get('type', False):
        if re.search('(UNKNOWN\[1501\]|APPARMOR_AUDIT|1501)', e['type']):
            aamode = 'AUDIT'
        elif re.search('(UNKNOWN\[1502\]|APPARMOR_ALLOWED|1502)', e['type']):
            aamode = 'PERMITTING'
        elif re.search('(UNKNOWN\[1503\]|APPARMOR_DENIED|1503)', e['type']):
            aamode = 'REJECTING'
        elif re.search('(UNKNOWN\[1504\]|APPARMOR_HINT|1504)', e['type']):
            aamode = 'HINT'
        elif re.search('(UNKNOWN\[1505\]|APPARMOR_STATUS|1505)', e['type']):
            aamode = 'STATUS'
        elif re.search('(UNKNOWN\[1506\]|APPARMOR_ERROR|1506)', e['type']):
            aamode = 'ERROR'
        else:
            aamode = 'UNKNOWN'
    
    if aamode in ['UNKNOWN', 'AUDIT', 'STATUS', 'ERROR']:
        return None
    
    if 'profile_set' in e['operation']:
        return None
    
    # Skip if AUDIT event was issued due to a change_hat in unconfined mode
    if not e.get('profile', False):
        return None 
    
    # Convert new null profiles to old single level null profile
    if '\\null-' in e['profile']:
        e['profile'] = 'null-complain-profile'
    
    profile = e['profile']
    hat = None
    
    if '\\' in e['profile']:
        profile, hat = e['profile'].split('\\')
    
    # Filter out change_hat events that aren't from learning
    if e['operation'] == 'change_hat':
        if aamode != 'HINT' and aamode != 'PERMITTING':
            return None
        profile = e['name']
        if '\\' in e['name']:
            profile, hat = e['name'].split('\\')
   
    # prog is no longer passed around consistently
    prog = 'HINT'
     
    if profile != 'null-complain-profile' and not profile_exists(profile):
        return None

    if e['operation'] == 'exec':
        if e.get('info', False) and e['info'] == 'mandatory profile missing':
            add_to_tree(e['pid'], e['parent'], 'exec', 
                        [profile, hat, aamode, 'PERMITTING', e['denied_mask'], e['name'], e['name2']])
        elif e.get('name2', False) and '\\null-/' in e['name2']:
            add_to_tree(e['pid'], e['parent'], 'exec',
                        [profile, hat, prog, aamode, e['denied_mask'], e['name'], ''])
        elif e.get('name', False):
            add_to_tree(e['pid'], e['parent'], 'exec',
                        [profile, hat, prog, aamode, e['denied_mask'], e['name'], ''])
        else:
            debug_logger.debug('add_event_to_tree: dropped exec event in %s' % e['profile'])
    
    elif 'file_' in e['operation']:
        add_to_tree(e['pid'], e['parent'], 'path',
                    [profile, hat, prog, aamode, e['denied_mask'], e['name'], ''])
    elif e['operation'] in ['open', 'truncate', 'mkdir', 'mknod', 'rename_src', 
                            'rename_dest', 'unlink', 'rmdir', 'symlink_create', 'link']:
        add_to_tree(e['pid'], e['parent'], 'path',
                    [profile, hat, prog, aamode, e['denied_mask'], e['name'], ''])
    elif e['operation'] == 'capable':
        add_to_tree(e['pid'], e['parent'], 'capability',
                    [profile, hat, prog, aamode, e['name'], ''])
    elif e['operation'] == 'setattr' or 'xattr' in e['operation']:
        add_to_tree(e['pid'], e['parent'], 'path',
                    [profile, hat, prog, aamode, e['denied_mask'], e['name'], ''])
    elif 'inode_' in e['operation']:
        is_domain_change = False
        if e['operation'] == 'inode_permission' and (e['denied_mask'] & AA_MAY_EXEC) and aamode == 'PERMITTING':
            following = peek_at_next_log_entry()
            if following:
                entry = parse_log_record(following)
                if entry and entry.get('info', False) == 'set profile':
                    is_domain_change = True
                    throw_away_next_log_entry()
        
        if is_domain_change:
            add_to_tree(e['pid'], e['parent'], 'exec',
                        [profile, hat, prog, aamode, e['denied_mask'], e['name'], e['name2']])
        else:
            add_to_tree(e['pid'], e['parent'], 'path',
                        [profile, hat, prog, aamode, e['denied_mask'], e['name'], ''])
        
    elif e['operation'] == 'sysctl':
        add_to_tree(e['pid'], e['parent'], 'path',
                    [profile, hat, prog, aamode, e['denied_mask'], e['name'], ''])
    
    elif e['operation'] == 'clone':
        parent , child = e['pid'], e['task']
        if not parent:
            parent = 'null-complain-profile'
        if not hat:
            hat = 'null-complain-profile'
        arrayref = ['fork', child, profile, hat]
        if pid.get(parent, False):
            pid[parent] += [arrayref]
        else:
            log += [arrayref]
        pid[child] = arrayref
    
    elif op_type(e['operation']) == 'net':
        add_to_tree(e['pid'], e['parent'], 'netdomain',
                    [profile, hat, prog, aamode, e['family'], e['sock_type'], e['protocol']])
    elif e['operation'] == 'change_hat':
        add_to_tree(e['pid'], e['parent'], 'unknown_hat',
                    [profile, hat, aamode, hat])
    else:
        debug_logger.debug('UNHANDLED: %s' % e)

def read_log(logmark):
    seenmark = True
    if logmark:
        seenmark = False
    #last = None
    #event_type = None
    try:
        log_open = open_file_read(filename)
    except IOError:
        raise AppArmorException('Can not read AppArmor logfile: ' + filename)
    
    with log_open as f_in:
        for line in f_in:
            line = line.strip()
            debug_logger.debug('read_log: %s' % line)
            if logmark in line:
                seenmark = True
            if not seenmark:
                debug_logger.debug('read_log: seenmark = %s' % seenmark)
            
            event = parse_log_record(line)
            if event:
                add_event_to_tree(event)
    logmark = ''

def parse_event(msg):
    """Parse the event from log into key value pairs"""
    msg = msg.strip()
    debug_logger.log('parse_event: %s' % msg)
    event = LibAppArmor.parse_record(msg)
    rmask = None
    dmask = None
    ev = dict()
    ev['resource'] = event.info
    ev['active_hat'] = event.active_hat
    ev['aamode'] = event.event
    ev['time'] = event.epoch
    ev['operation'] = event.operation
    ev['profile'] = event.profile
    ev['name'] = event.name
    ev['name2'] = event.name2
    ev['attr'] = event.attribute
    ev['parent'] = event.parent
    ev['pid'] = event.pid
    ev['task'] = event.task
    ev['info'] = event.info
    dmask = event.denied_mask
    rmask = event.requested_mask
    ev['magic_token'] = event.magic_token
    if ev['operation'] and op_type(ev['operation']) == 'net':
        ev['family'] = event.net_family
        ev['protocol'] = event.net_protocol
        ev['sock_type'] = event.net_sock_type
    LibAppArmor.free_record(event)
    # Map c (create) to a and d (delete) to w, logprof doesn't support c and d
    if rmask:
        rmask = rmask.replace('c', 'a')
        rmask = rmask.replace('d', 'w')
        if not validate_log_mode(hide_log_mode(rmask)):
            fatal_error(gettext('Log contains unknown mode %s') % rmask)
    if dmask:
        dmask = dmask.replace('c', 'a')
        dmask = dmask.replace('d', 'w')
        if not validate_log_mode(hide_log_mode(dmask)):
            fatal_error(gettext('Log contains unknown mode %s') % dmask)
    
    mask, name = log_str_to_mode(ev['profile'], dmask, ev['name2'])
    ev['denied_mask'] = mask
    ev['name2'] = name
    
    mask, name = log_str_to_mode(ev['profile'], rmask, ev['name2'])
    ev['request_mask'] = mask
    ev['name2'] = name
    
    if not ev['time']:
        ev['time'] = int(time.time)
    # Remove None keys
    #for key in ev.keys():
    #    if not ev[key] or not re.search('[\w]+', ev[key]):
    #        ev.pop(key)
    if ev['aamode']:
        # Convert aamode values to their counter-parts
        mode_convertor = {
                          0: 'UNKNOWN',
                          1: 'ERROR',
                          2: 'AUDITING',
                          3: 'PERMITTING',
                          4: 'REJECTING',
                          5: 'HINT',
                          6: 'STATUS'
                          }
        try:
            ev['aamode'] = mode_convertor(ev['aamode'])
        except KeyError:
            ev['aamode'] = None
    
    if ev['aamode']:
        debug_logger.debug(ev)
        return ev
    else:
        return None

def hide_log_mode(mode):
    mode = mode.replace('::', '')
    return mode

def validate_log_mode(mode):
    if LOG_MODE_RE.search(mode):
        return True
    else:
        return False
          
##### Repo related functions

def UI_SelectUpdatedRepoProfile(profile, p):
    # To-Do
    return False

def UI_repo_signup():
    # To-Do
    return None, None

def UI_ask_to_enable_repo():
    # To-Do
    pass

def UI_ask_to_upload_profiles():
    # To-Do
    pass

def UI_ask_mode_toggles(audit_toggle, owner_toggle, oldmode):
    # To-Do
    pass

def parse_repo_profile(fqdbin, repo_url, profile):
    # To-Do
    pass

def set_repo_info(profile_data, repo_url, username, iden):
    # To-Do
    pass

def is_repo_profile(profile_data):
    # To-Do
    pass

def get_repo_user_pass():
    # To-Do
    pass

def update_repo_profile(profile):
    # To-Do
    return None

def order_globs(globs, path):
    """Returns the globs in sorted order, more specific behind"""
    # To-Do
    # ATM its lexicographic, should be done to allow better matches later
    return sorted(globs)

def ask_the_question():
    found = None
    for aamode in sorted(log_dict.keys()):
        # Describe the type of changes
        if aamode == 'PERMITTING':
            UI_Info(gettext('Complain-mode changes:'))
        elif aamode == 'REJECTING':
            UI_Info(gettext('Enforce-mode changes:'))
        else:
            # oops something screwed up
            fatal_error(gettext('Invalid mode found: %s') % aamode)
        
        for profile in sorted(log_dict[aamode].keys()):
            # Update the repo profiles
            p = update_repo_profile(aa[profile][profile])
            if p:
                UI_SelectUpdatedRepoProfile(profile, p)
            
            found += 1
            # Sorted list of hats with the profile name coming first
            hats = filter(lambda key: key != profile, sorted(log_dict[aamode][profile].keys()))
            if log_dict[aamode][profile].get(profile, False):
                hats = [profile] + hats
            
            for hat in hats:
                for capability in sorted(log_dict[aamode][profile][hat]['capability'].keys()):
                    # skip if capability already in profile
                    if profile_known_capability(aa[profile][hat], capability):
                        continue
                    # Load variables? Don't think so.
                    severity = sev_db.rank('CAP_%s' % capability)
                    default_option = 1
                    options = []
                    newincludes = match_cap_includes(aa[profile][hat], capability)
                    q = hasher()
                    
                    if newincludes:
                        options += map(lambda inc: '#include <%s>' %inc, sorted(set(newincludes)))
                    
                    if options:
                        options.append('capability %s' % capability)
                        q['options'] = [options]
                        q['selected'] = default_option - 1
                    
                    q['headers'] = [gettext('Profile'), combine_name(profile, hat)]
                    q['headers'] += [gettext('Capability'), capability]
                    q['headers'] += [gettext('Severity'), severity]
                    
                    audit_toggle = 0
                    
                    q['functions'] = ['CMD_ALLOW', 'CMD_DENY', 'CMD_AUDIT_NEW',
                                      'CMD_ABORT', 'CMD_FINISHED']
                    
                    # In complain mode: events default to allow
                    # In enforce mode: events default to deny
                    q['default'] = 'CMD_DENY'
                    if aamode == 'PERMITTING':
                        q['default'] = 'CMD_ALLOW'
                    
                    seen_events += 1
                    
                    done = False
                    while not done:
                        ans, selected = UI_PromptUser(q)
                        if ans == 'CMD_AUDIT':
                            audit_toggle = not audit_toggle
                            audit = ''
                            if audit_toggle:
                                q['functions'] = ['CMD_ALLOW', 'CMD_DENY', 'CMD_AUDIT_OFF',
                                                  'CMD_ABORT', 'CMD_FINISHED']
                                audit = 'audit'
                            else:
                                q['functions'] = ['CMD_ALLOW', 'CMD_DENY', 'CMD_AUDIT_NEW',
                                                  'CMD_ABORT', 'CMD_FINISHED']
                            
                            q['headers'] = [gettext('Profile'), combine_name(profile, hat),
                                            gettext('Capability'), audit + capability,
                                            gettext('Severity'), severity]
                        
                        if ans == 'CMD_ALLOW':
                            selection = options[selected]
                            match = re.search('^#include\s+<(.+)>$', selection)
                            if match:
                                deleted = False
                                inc = match.groups()[0]
                                deleted = delete_duplicates(aa[profile][hat], inc)
                                aa[profile][hat]['include'][inc] = True
                                
                                UI_Info(gettext('Adding %s to profile.') % selection)
                                if deleted:
                                    UI_Info(gettext('Deleted %s previous matching profile entries.') % deleted)
                                
                            aa[profile][hat]['allow']['capability'][capability]['set'] = True
                            aa[profile][hat]['allow']['capability'][capability]['audit'] = audit_toggle
                            
                            changed[profile] = True
                            
                            UI_Info(gettext('Adding capability %s to profile.'), capability)
                            done = True
                        
                        elif ans == 'CMD_DENY':
                            aa[profile][hat]['deny']['capability'][capability]['set'] = True
                            changed[profile] = True
                            
                            UI_Info(gettext('Denying capability %s to profile.') % capability)
                            done = True
                        else:
                            done = False
                
                # Process all the path entries.
                for path in sorted(log_dict[aamode][profile][hat]['path'].keys()):
                    mode = log_dict[aamode][profile][hat]['path'][path]
                    # Lookup modes from profile
                    allow_mode = 0
                    allow_audit = 0
                    deny_mode = 0
                    deny_audit = 0
                    
                    fmode, famode, fm = rematch_frag(aa[profile][hat], 'allow', path)
                    if fmode:
                        allow_mode |= fmode
                    if famode:
                        allow_audit |= famode
                    
                    cm, cam, m = rematch_frag(aa[profile][hat], 'deny', path)
                    if cm:
                        deny_mode |= cm
                    if cam:
                        deny_audit |= cam
                    
                    imode, iamode, im = match_prof_incs_to_path(aa[profile][hat], 'allow', path)
                    if imode:
                        allow_mode |= imode
                    if iamode:
                        allow_audit |= iamode
                    
                    cm, cam, m = match_prof_incs_to_path(aa[profile][hat], 'deny', path)
                    if cm:
                        deny_mode |= cm
                    if cam:
                        deny_audit |= cam
                    
                    if deny_mode & AA_MAY_EXEC:
                        deny_mode |= ALL_AA_EXEC_TYPE
                    
                    # Mask off the denied modes
                    mode = mode & ~deny_mode
                    
                    # If we get an exec request from some kindof event that generates 'PERMITTING X'
                    # check if its already in allow_mode
                    # if not add ix permission
                    if mode & AA_MAY_EXEC:
                        # Remove all type access permission
                        mode = mode & ~ALL_AA_EXEC_TYPE
                        if not allow_mode & AA_MAY_EXEC:
                            mode |= str_to_mode('ix')
                    
                    # If we get an mmap request, check if we already have it in allow_mode
                    if mode & AA_EXEC_MMAP:
                        # ix implies m, so we don't need to add m if ix is present
                        if contains(allow_mode, 'ix'):
                            mode = mode & ~AA_EXEC_MMAP
                        
                    if not mode:
                        continue
                    
                    matches = []
                    
                    if fmode:
                        matches.append(fm)
                        
                    if imode:
                        matches.append(im)
                    
                    if not mode_contains(allow_mode, mode):
                        default_option = 1
                        options = []
                        newincludes = []
                        include_valid = False
                        
                        for incname in include.keys():
                            include_valid = False
                            # If already present skip
                            if aa[profile][hat][incname]:
                                continue
                            
                            if cfg['settings']['custom_includes']:
                                for incn in cfg['settings']['custom_includes'].split():
                                    if incn in incname:
                                        include_valid = True
                            
                            if 'abstraction' in incname:
                                include_valid = True
                            
                            if not include_valid:
                                continue
                            
                            cm, am, m = match_include_to_path(incname, 'allow', path)
                            
                            if cm and mode_contains(cm, mode):
                                dm = match_include_to_path(incname, 'deny', path)
                                # If the mode is denied
                                if not mode & dm:
                                    if not filter(lambda s: '/**' not in s, m):
                                        newincludes.append(incname)
                        # Add new includes to the options
                        if newincludes:
                            options += map(lambda s: '#include <%s>' % s, sorted(set(newincludes)))
                        # We should have literal the path in options list too
                        options.append(path)
                        # Add any the globs matching path from logprof
                        globs = globcommon(path)
                        if globs:
                            matches += globs
                        # Add any user entered matching globs
                        for user_glob in user_globs:
                            if matchliteral(user_glob, path):
                                matches.append(user_glob)
                        
                        matches = list(set(matches))
                        if path in matches:
                            matches.remove(path)
                        
                        options += order_globs(matches, path)
                        default_option = len(options)
                        
                        sev_db.unload_variables()
                        sev_db.load_variables(profile)
                        severity = sev_db.rank(path, mode_to_str(mode))
                        sev_db.unload_variables()
                        
                        audit_toggle = 0
                        owner_toggle = cfg['settings']['default_owner_prompt']
                        done = False
                        while not done:
                            q =  hasher()
                            q['headers'] = [gettext('Profile'), combine_name(profile, hat),
                                            gettext('Path'), path]
                            
                            if allow_mode:
                                mode |= allow_mode
                                tail = ''
                                s = ''
                                prompt_mode = None
                                if owner_toggle == 0:
                                    prompt_mode = flatten_mode(mode)
                                    tail = '     ' + gettext('(owner permissions off)')
                                elif owner_toggle == 1:
                                    prompt_mode = mode
                                elif owner_toggle == 2:
                                    prompt_mode = allow_mode | owner_flatten_mode(mode & ~allow_mode)
                                    tail = '     ' + gettext('(force new perms to owner)')
                                else:
                                    prompt_mode = owner_flatten_mode(mode)
                                    tail = '     ' + gettext('(force all rule perms to owner)')
                                
                                if audit_toggle == 1:
                                    s = mode_to_str_user(allow_mode)
                                    if allow_mode:
                                        s += ', '
                                    s += 'audit ' + mode_to_str_user(prompt_mode & ~allow_mode) + tail
                                elif audit_toggle == 2:
                                    s = 'audit ' + mode_to_str_user(prompt_mode) + tail
                                else:
                                    s = mode_to_str_user(prompt_mode) + tail
                                
                                q['headers'] += [gettext('Old Mode'), mode_to_str_user(allow_mode), 
                                                 gettext('New Mode'), s]
                            
                            else:
                                s = ''
                                tail = ''
                                prompt_mode = None
                                if audit_toggle:
                                    s = 'audit'
                                if owner_toggle == 0:
                                    prompt_mode = flatten_mode(mode)
                                    tail = '     ' + gettext('(owner permissions off)')
                                elif owner_toggle == 1:
                                    prompt_mode = mode
                                else:
                                    prompt_mode = owner_flatten_mode(mode)
                                    tail = '     ' + gettext('(force perms to owner)')
                                
                                s = mode_to_str_user(prompt_mode)
                                q['headers'] += [gettext('Mode'), s]
                            
                            q['headers'] += [gettext('Severity'), severity]
                            q['options'] = options
                            q['selected'] = default_option - 1
                            q['functions'] = ['CMD_ALLOW', 'CMD_DENY', 'CMD_GLOB',
                                              'CMD_GLOBTEXT', 'CMD_NEW', 'CMD_ABORT',
                                              'CMD_FINISHED', 'CMD_OTHER']
                            q['default'] = 'CMD_DENY'
                            if aamode == 'PERMITTING':
                                q['default'] = 'CMD_ALLOW'
                            
                            seen_events += 1
                            
                            ans, selected = UI_PromptUser(q)
                            
                            if ans == 'CMD_OTHER':
                                audit_toggle, owner_toggle = UI_ask_mode_toggles(audit_toggle, owner_toggle, allow_mode)
                            elif ans == 'CMD_USER_TOGGLE':
                                owner_toggle += 1
                                if not allow_mode and owner_toggle == 2:
                                    owner_toggle += 1
                                if owner_toggle > 3:
                                    owner_toggle = 0
                            elif ans == 'CMD_ALLOW':
                                path = options[selected]
                                done = True
                                match = re.search('^#include\s+<(.+)>$', path)
                                if match:
                                    inc = match.gropus()[0]
                                    deleted = 0
                                    deleted = delete_duplicates(aa[profile][hat], inc)
                                    aa[profile][hat]['include'][inc] =  True
                                    changed[profile] =  True
                                    UI_Info(gettext('Adding %s to profile.') % path)
                                    if deleted:
                                        UI_Info(gettext('Deleted %s previous matching profile entries.') % deleted)
                                
                                else:
                                    if aa[profile][hat]['allow']['path'][path].get('mode', False):
                                        mode |= aa[profile][hat]['allow']['path'][path]['mode']
                                    deleted = 0
                                    for entry in aa[profile][hat]['allow']['path'].keys():
                                        if path == entry:
                                            continue
                                        
                                        if matchregexp(path, entry):
                                            if mode_contains(mode, aa[profile][hat]['allow']['path'][entry]['mode']):
                                                aa[profile][hat]['allow']['path'].pop(entry)
                                                deleted += 1
                                    
                                    if owner_toggle == 0:
                                        mode = flatten_mode(mode)
                                    #elif owner_toggle == 1:
                                    #    mode = mode
                                    elif owner_toggle == 2:
                                        mode = allow_mode | owner_flatten_mode(mode & ~allow_mode)
                                    elif owner_toggle == 3:
                                        mode = owner_flatten_mode(mode)
                                    
                                    aa[profile][hat]['allow']['path'][path]['mode'] = aa[profile][hat]['allow']['path'][path].get('mode', 0) | mode
                                    
                                    tmpmode = 0
                                    if audit_toggle == 1:
                                        tmpmode = mode & ~allow_mode
                                    elif audit_toggle == 2:
                                        tmpmode = mode 
                                    
                                    aa[profile][hat]['allow']['path'][path]['audit'] = aa[profile][hat]['allow']['path'][path].get('audit', 0) | tmpmode
                                    
                                    changed[profile] = True
                                    
                                    UI_Info(gettext('Adding %s %s to profile') % (path, mode_to_str_user(mode)))
                                    if deleted:
                                        UI_Info(gettext('Deleted %s previous matching profile entries.') % deleted)
                                    
                            elif ans == 'CMD_DENY':
                                # Add new entry?
                                aa[profile][hat]['deny']['path'][path]['mode'] = aa[profile][hat]['deny']['path'][path].get('mode', 0) | (mode & ~allow_mode)
                                
                                aa[profile][hat]['deny']['path'][path]['audit'] = aa[profile][hat]['deny']['path'][path].get('audit', 0)
                                
                                changed[profile] = True
                                
                                done = True
                            
                            elif ans == 'CMD_NEW':
                                arg = options[selected]
                                if not arg.startswith('#include'):
                                    ans = UI_GetString(gettext('Enter new path:'), arg)
                                    if ans:
                                        if not matchliteral(ans, path):
                                            ynprompt = gettext('The specified path does not match this log entry:')
                                            ynprompt += '\n\n  ' + gettext('Log Entry') + ':  %s' % path
                                            ynprompt += '\n  ' + gettext('Entered Path') + ':  %s' % ans
                                            ynprompt += gettext('Do you really want to use this path?') + '\n'
                                            key = UI_YesNo(ynprompt, 'n')
                                            if key == 'n':
                                                continue
                                        
                                        user_globs.append(ans)
                                        options.append(ans)
                                        default_option = len(options)
                            
                            elif ans == 'CMD_GLOB':
                                newpath = options[selected].strip()
                                if not newpath.startswith('#include'):
                                    if newpath[-1] == '/':
                                        if newpath[-4:] == '/**/' or newpath[-3:] == '/*/':
                                            # collapse one level to /**/
                                            newpath = re.sub('/[^/]+/\*{1,2}$/', '/\*\*/', newpath)
                                        else:
                                            newpath = re.sub('/[^/]+/$', '/\*/', newpath)
                                    else:
                                        if newpath[-3:] == '/**' or newpath[-2:] == '/*':
                                            newpath = re.sub('/[^/]+/\*{1,2}$', '/\*\*', newpath)
                                        elif re.search('/\*\*[^/]+$', newpath):
                                            newpath = re.sub('/\*\*[^/]+$', '/\*\*', newpath)
                                        else:
                                            newpath = re.sub('/[^/]+$', '/\*', newpath)
                                    
                                    if newpath not in options:
                                        options.append(newpath)
                                        default_option = len(options)
                            
                            elif ans == 'CMD_GLOBEXT':
                                newpath = options[selected].strip()
                                if not newpath.startswith('#include'):
                                    match = re.search('/\*{1,2}(\.[^/]+)$', newpath)
                                    if match:
                                        newpath = re.sub('/[^/]+/\*{1,2}\.[^/]+$', '/\*\*'+match.group()[0], newpath)
                                    else:
                                        match = re.search('(\.[^/]+)$')
                                        newpath = re.sub('/[^/]+(\.[^/]+)$', '/\*'+match.groups()[0], newpath)
                                    if newpath not in options:
                                        options.append(newpath)
                                        default_option = len(options)
                            
                            elif re.search('\d', ans):
                                default_option = ans
                
                #
                for family in sorted(log_dict[aamode][profile][hat]['netdomain'].keys()):
                    # severity handling for net toggles goes here
                    for sock_type in sorted(log_dict[aaprofile][profile][hat]['netdomain'][family].keys()):
                        if profile_known_network(aa[profile][hat], family, sock_type):
                            continue
                        default_option = 1
                        options = []
                        newincludes = matchnetincludes(aa[profile][hat], family, sock_type)
                        q = hasher()
                        if newincludes:
                            options += map(lambda s: '#include <%s>'%s, sorted(set(newincludes)))
                        if options:
                            options.append('network %s %s' % (family, sock_type))
                            q['options'] = options
                            q['selected'] = default_option - 1
                        
                        q['headers'] = [gettext('Profile'), combine_name(profile, hat)]
                        q['headers'] += [gettext('Network Family'), family]
                        q['headers'] += [gettext('Socket Type'), sock_type]
                        
                        audit_toggle = 0
                        q['functions'] = ['CMD_ALLOW', 'CMD_DENY', 'CMD_AUDIT_NEW',
                                          'CMD_ABORT', 'CMD_FINISHED']
                        q['default'] = 'CMD_DENY'
                        
                        if aamode == 'PERMITTING':
                            q['default'] = 'CMD_ALLOW'
                        
                        seen_events += 1
                                
                        done = False
                        while not done:
                            ans, selected = UI_PromptUser(q)
                            if ans.startswith('CMD_AUDIT'):
                                audit_toggle = not audit_toggle
                                audit = ''
                                if audit_toggle:
                                    audit = 'audit'
                                    q['functions'] = ['CMD_ALLOW', 'CMD_DENY', 'CMD_AUDIT_OFF',
                                                      'CMD_ABORT', 'CMD_FINISHED']
                                else:
                                    q['functions'] = ['CMD_ALLOW', 'CMD_DENY', 'CMD_AUDIT_NEW',
                                                      'CMD_ABORT', 'CMD_FINISHED']
                                q['headers'] = [gettext('Profile'), combine_name(profile, hat)]
                                q['headers'] += [gettext('Network Family'), audit + family]
                                q['headers'] += [gettext('Socket Type'), sock_type]
                            
                            elif ans == 'CMD_ALLOW':
                                selection = options[selected]
                                done = True
                                if re.search('#include\s+<.+>$', selection):
                                    inc =  re.search('#include\s+<(.+)>$', selection).groups()[0]
                                    deleted =  0
                                    deleted = delete_duplicates(aa[profile][hat], inc)
                                    
                                    aa[profile][hat]['include'][inc] = True
                                    
                                    changed[profile] = True
                                    
                                    UI_Info(gettext('Adding %s to profile') % selection)
                                    if deleted:
                                        UI_Info(gettext('Deleted %s previous matching profile entries.') % deleted)
                                
                                else:
                                    aa[profile][hat]['allow']['netdomain']['audit'][family][sock_type] = audit_toggle
                                    aa[profile][hat]['allow']['netdomain']['rule'][family][sock_type] = True
                                    
                                    changed[profile] = True
                                    
                                    UI_Info(gettext('Adding network access %s %s to profile.' % (family, sock_type)))
                            
                            elif ans == 'CMD_DENY':
                                done = True
                                aa[profile][hat]['deny']['netdomain']['rule'][family][sock_type] = True
                                changed[profile] = True
                                UI_Info(gettext('Denying network access %s %s to profile') % (family, sock_type))
                            
                            else:
                                done = False

