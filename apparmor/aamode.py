import re

AA_MAY_EXEC = set('x')
AA_MAY_WRITE = set('w')
AA_MAY_READ = set('r')
AA_MAY_APPEND = set('a')
AA_MAY_LINK = set('l')
AA_MAY_LOCK = set('k')
AA_EXEC_MMAP = set('m')
AA_EXEC_UNSAFE = set('unsafe')
AA_EXEC_INHERIT = set('i')
AA_EXEC_UNCONFINED = set('U')
AA_EXEC_PROFILE = set('P')
AA_EXEC_CHILD = set('C')
AA_EXEC_NT = set('N')
AA_LINK_SUBSET = set('ls')
AA_OTHER_SHIFT = 14
AA_USER_MASK = 16384 - 1

AA_EXEC_TYPE = (AA_MAY_EXEC | AA_EXEC_UNSAFE | AA_EXEC_INHERIT |
                AA_EXEC_UNCONFINED | AA_EXEC_PROFILE | AA_EXEC_CHILD | AA_EXEC_NT)

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

LOG_MODE_RE = re.compile('r|w|l|m|k|a|x|ix|ux|px|cx|nx|pix|cix|Ix|Ux|Px|PUx|Cx|Nx|Pix|Cix')
MODE_MAP_RE = re.compile('r|w|l|m|k|a|x|i|u|p|c|n|I|U|P|C|N')

def str_to_mode(string):
    if not string:
        return set()
    user, other = split_log_mode(string)
    
    if not user:
        user = other

    mode = sub_str_to_mode(user)
    #print(string, mode)
    #print(string, 'other', sub_str_to_mode(other))
    mode |= (sub_str_to_mode(other) << AA_OTHER_SHIFT)
    #print (string, mode)
    #print('str_to_mode:', mode)
    return mode

def sub_str_to_mode(string):
    mode = set()
    if not string:
        return mode
    while string:
        pattern = '(%s)' % MODE_MAP_RE.pattern
        tmp = re.search(pattern, string)
        if tmp:
            tmp = tmp.groups()[0]
        string = re.sub(pattern, '', string)
        if tmp and MODE_HASH.get(tmp, False):
            mode |= MODE_HASH[tmp]
        else:
            pass
    
    return mode

def split_log_mode(mode):
    user = ''
    other = ''
    match = re.search('(.*?)::(.*)', mode)
    if match:
        user, other = match.groups()
    else:
        user = mode
        other = mode
    #print ('split_logmode:', user, mode)
    return user, other

def mode_contains(mode, subset):
    # w implies a
    if mode & AA_MAY_WRITE:
        mode |= AA_MAY_APPEND   
    if mode & (AA_MAY_WRITE << AA_OTHER_SHIFT):
        mode |= (AA_MAY_APPEND << AA_OTHER_SHIFT)
    
    return (mode & subset) == subset

def contains(mode, string):
    return mode_contains(mode, str_to_mode(string))

def validate_log_mode(mode):
    pattern = '^(%s)+$' % LOG_MODE_RE.pattern
    if re.search(pattern, mode):
    #if LOG_MODE_RE.search(mode):
        return True
    else:
        return False

def hide_log_mode(mode):
    mode = mode.replace('::', '')
    return mode
    
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

def log_str_to_mode(profile, string, nt_name):
    mode = str_to_mode(string)
    # If contains nx and nix
    #print (profile, string, nt_name)
    if contains(mode, 'Nx'):
        # Transform to px, cx
        match = re.search('(.+?)//(.+?)', nt_name)
        if match:
            lprofile, lhat = match.groups()
            tmode = 0
            
            if lprofile == profile:
                if mode & AA_MAY_EXEC:
                    tmode = str_to_mode('Cx::')
                if mode & (AA_MAY_EXEC << AA_OTHER_SHIFT):
                    tmode |= str_to_mode('Cx')
                nt_name = lhat
            else:
                if mode & AA_MAY_EXEC:
                    tmode = str_to_mode('Px::')
                if mode & (AA_MAY_EXEC << AA_OTHER_SHIFT):
                    tmode |= str_to_mode('Px')
                nt_name = lhat
            
            mode = mode & ~str_to_mode('Nx')
            mode |= tmode
    
    return mode, nt_name

def hide_log_mode(mode):
    mode = mode.replace('::', '')
    return mode

def validate_log_mode(mode):
    pattern = '^(%s)+$' % LOG_MODE_RE.pattern
    if re.search(pattern, mode):
    #if LOG_MODE_RE.search(mode):
        return True
    else:
        return False
    
def str_to_mode(string):
    if not string:
        return 0
    user, other = split_log_mode(string)
    
    if not user:
        user = other

    mode = sub_str_to_mode(user)
    #print(string, mode)
    #print(string, 'other', sub_str_to_mode(other))
    mode |= (sub_str_to_mode(other) << AA_OTHER_SHIFT)
    #print (string, mode)
    #print('str_to_mode:', mode)
    return mode

def mode_contains(mode, subset):
    # w implies a
    if mode & AA_MAY_WRITE:
        mode |= AA_MAY_APPEND   
    if mode & (AA_MAY_WRITE << AA_OTHER_SHIFT):
        mode |= (AA_MAY_APPEND << AA_OTHER_SHIFT)
    
    # ix does not imply m
    
    ### ix implies m
    ##if mode & AA_EXEC_INHERIT:
    ##    mode |= AA_EXEC_MMAP
    ##if mode & (AA_EXEC_INHERIT << AA_OTHER_SHIFT):
    ##    mode |= (AA_EXEC_MMAP << AA_OTHER_SHIFT)
    
    return (mode & subset) == subset

def contains(mode, string):
    return mode_contains(mode, str_to_mode(string))

def sub_str_to_mode(string):
    mode = 0
    if not string:
        return mode
    while string:
        pattern = '(%s)' % MODE_MAP_RE.pattern
        tmp = re.search(pattern, string)
        if tmp:
            tmp = tmp.groups()[0]
        string = re.sub(pattern, '', string)
        if tmp and MODE_HASH.get(tmp, False):
            mode |= MODE_HASH[tmp]
        else:
            pass
    
    return mode

def split_log_mode(mode):
    user = ''
    other = ''
    match = re.search('(.*?)::(.*)', mode)
    if match:
        user, other = match.groups()
    else:
        user = mode
        other = mode
    #print ('split_logmode:', user, mode)
    return user, other