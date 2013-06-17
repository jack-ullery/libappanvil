import os
import re

class Severity:
    def __init__(self, dbname=None, default_rank=10):
        self.severity = dict()
        self.severity['DATABASENAME'] = dbname
        self.severity['CAPABILITIES'] = {}
        self.severity['FILES'] = {}
        self.severity['REGEXPS'] = {}
        self.severity['DEFAULT_RANK'] = default_rank
        if not dbname:
            return self.severity
        try:
            database = open(dbname, 'r')
        except IOError:
            raise("Could not open severity database %s"%dbname)
        for line in database:
            line = line.strip() # or only rstrip and lstrip?
            if line == '' or line.startswith('#') :
                continue
            if line.startswith('/'):
                try:
                    path, read, write, execute = line.split()
                except ValueError:
                    raise("Insufficient values for permissions")
                else:
                    path = path.lstrip('/')
                    if '*' not in path:
                        self.severity['FILES'][path] = {'r': read, 'w': write, 'x': execute}
                    else:
                        ptr = self.severity['REGEXPS']
                        pieces = path.split('/')
                        for index, piece in enumerate(pieces):
                            if '*' in piece:
                                path = '/'.join(pieces[index:])
                                regexp = self.convert_regexp(path)
                                ptr[regexp] = {'SD_RANK': {'r': read, 'w': write, 'x': execute}}
                                break
                            else:
                                ptr[piece] = ptr.get(piece, {})
                                ptr = ptr[piece]
            elif line.startswith('CAP'):
                resource, severity = line.split()
                self.severity['CAPABILITIES'][resource] = severity
            else:
                print("unexpected database line: %s"%line)   
        database.close()
        
    def convert_regexp(self, path):
        pattern_or = re.compile('{.*\,.*}')    # The regex pattern for {a,b}
        regex = path
        for character in ['.', '+', '[', ']']:    # Escape the regex symbols
            regex = regex.replace(character, "\%s"%character)
        # Convert the ** to regex
        regex = regex.replace('**', '.SDPROF_INTERNAL_GLOB')
        # Convert the * to regex
        regex = regex.replace('*', '[^/]SDPROF_INTERNAL_GLOB')
        # Convert {a,b} to (a|b) form
        if pattern_or.match(regex):
            for character, replacement in zip('{},', '()|'):
                regex = regex.replace(character, replacement)
        # Restore the * in the final regex
        regex = regex.replace('SDPROF_INTERNAL_GLOB', '*')
        return regex
    
    