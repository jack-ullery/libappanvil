

            
    
def serialize_profile(profile_data, name, options):
    string = ''
    include_metadata = False
    include_flags = True
    data= []
    
    if options:# and type(options) == dict:
        if options.get('METADATA', False):
            include_metadata = True
        if options.get('NO_FLAGS', False):
            include_flags = False
    
    if include_metadata:
        string = '# Last Modified: %s\n' %time.time()
        
        if (profile_data[name].get('repo', False) and profile_data[name]['repo']['url']
            and profile_data[name]['repo']['user'] and profile_data[name]['repo']['id']):
            repo = profile_data[name]['repo']
            string += '# REPOSITORY: %s %s %s\n' %(repo['url'], repo['user'], repo['id'])
        elif profile_data[name]['repo']['neversubmit']:
            string += '# REPOSITORY: NEVERSUBMIT\n'
    
    if profile_data[name].get('initial_comment', False):
        comment = profile_data[name]['initial_comment']
        comment.replace('\\n', '\n')
        string += comment + '\n'
    
    prof_filename = get_profile_filename(name)
    if filelist.get(prof_filename, False):
        data += write_alias(filelist[prof_filename], 0)
        data += write_list_vars(filelist[prof_filename], 0)
        data += write_includes(filelist[prof_filename], 0)
    
    data += write_piece(profile_data, 0, name, name, include_flags)
    
    string += '\n'.join(data)
    
    return string+'\n'
