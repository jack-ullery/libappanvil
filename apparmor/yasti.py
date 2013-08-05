import re
#import ycp
import os
import sys
import logging

from apparmor.common import error
DEBUGGING = False
debug_logger = None
# Set up UI logger for separate messages from YaST module
if os.getenv('LOGPROF_DEBUG', False):
    DEBUGGING = True
    logprof_debug = '/var/log/apparmor/logprof.log'
    logging.basicConfig(filename=logprof_debug, level=logging.DEBUG)
    debug_logger = logging.getLogger('YaST')

def setup_yast():
    # To-Do
    pass   

def shutdown_yast():
    # To-Do
    pass

def yastLog(text):
    ycp.y2milestone(text)

def SendDataToYast(data):
    if DEBUGGING:
        debug_logger.info('SendDataToYast: Waiting for YCP command')
    for line in sys.stdin:
        ycommand, ypath, yargument = ParseCommand(line)
        if ycommand and ycommand == 'Read':
            if DEBUGGING:
                debug_logger.info('SendDataToYast: Sending--%s' % data)
            Return(data)
            return True
        else:
            if DEBUGGING:
                debug_logger.info('SendDataToYast: Expected \'Read\' but got-- %s' % line)
    error('SendDataToYast: didn\'t receive YCP command before connection died')   

def GetDataFromYast():
    if DEBUGGING:
        debug_logger.inf('GetDataFromYast: Waiting for YCP command')
    for line in sys.stdin:
        if DEBUGGING:
            debug_logger.info('GetDataFromYast: YCP: %s' % line)
        ycommand, ypath, yarg = ParseCommand(line)
        if DEBUGGING:
            debug_logger.info('GetDataFromYast: Recieved--\n%s' % yarg)
        if ycommand and ycommand == 'Write':
            Return('true')
            return ypath, yarg
        else:
            if DEBUGGING:
                debug_logger.info('GetDataFromYast: Expected Write but got-- %s' % line)
    error('GetDataFromYast: didn\'t receive YCP command before connection died')

def ParseCommand(commands):
    term = ParseTerm(commands)
    if term:
        command = term[0]
        term = term[1:]
    else:
        command = ''
    path = ''
    pathref = None
    if term:
        pathref = term[0]
        term = term[1:]
    if pathref:
        if pathref.strip():
            path = pathref.strip()
        elif command != 'result':
            ycp.y2error('The first arguement is not a path. (%s)' % pathref)
    argument = None
    if term:
        argument = term[0]
    if len(term) > 1:
        ycp.y2warning('Superfluous command arguments ignored')
    return (command, path, argument)

def ParseTerm(inp):
    regex_term = re.compile('^\s*`?(\w*)\s*')
    term = regex_term.search(inp)
    ret = []
    symbol = None
    if term:
        symbol = term.groups()[0]
    else:
        ycp.y2error('No term symbol')
    ret.append(symbol)
    inp = regex_term.sub('', inp)
    if not inp.startswith('('):
        ycp.y2error('No term parantheses')
    argref, err, rest = ParseYcpTermBody(inp)
    if err:
        ycp.y2error('%s (%s)' % (err, rest))
    else:
        ret += argref
    return ret

