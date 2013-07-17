# 1728
import sys
import gettext
import locale
import logging
import os
from yasti import yastLog, SendDataToYast, GetDataFromYast

from apparmor.common import readkey

DEBUGGING = False
debug_logger = None
# Set up UI logger for separate messages from UI module
if os.getenv('LOGPROF_DEBUG', False):
    DEBUGGING = True
    logprof_debug = '/var/log/apparmor/logprof.log'
    logging.basicConfig(filename=logprof_debug, level=logging.DEBUG)
    debug_logger = logging.getLogger('UI')

# The operating mode: yast or text, text by default
UI_mode = 'text'

def init_localisation():
    locale.setlocale(locale.LC_ALL, '')
    #cur_locale = locale.getlocale()
    filename = 'res/messages_%s.mo' % locale.getlocale()[0][0:2]
    try:
        trans = gettext.GNUTranslations(open( filename, 'rb'))
    except IOError:
        trans = gettext.NullTranslations()
    trans.install()

def UI_Info(text):
    if DEBUGGING:
        debug_logger.info(text)
    if UI_mode == 'text':
        sys.stdout.write(text + '\n')
    else:
        yastLog(text)

def UI_Important(text):
    if DEBUGGING:
        debug_logger.debug(text)
    if UI_mode == 'text':
        sys.stdout.write('\n' + text + '\n')
    else:
        SendDataToYast({
                        'type': 'dialog-error',
                        'message': text
                        })
        path, yarg = GetDataFromYast()

def UI_YesNo(text, default):
    if DEBUGGING:
        debug_logger.debug('UI_YesNo: %s: %s %s' %(UI_mode, text, default))
    ans = default
    if UI_mode == 'text':
        yes = '(Y)es'
        no = '(N)o'
        usrmsg = 'PromptUser: Invalid hotkey for'
        yeskey = 'y'
        nokey = 'n'
        sys.stdout.write('\n' + text + '\n')
        if default == 'y':
            sys.stdout.write('\n[%s] / %s\n' % (yes, no))
        else:
            sys.stdout.write('\n%s / [%s]\n' % (yes, no))
        ans = readkey()
        if ans:
            ans = ans.lower()
        else:
            ans = default
    else:
        SendDataTooYast({
                         'type': 'dialog-yesno',
                         'question': text
                         })
        ypath, yarg = GetDataFromYast()
        ans = yarg['answer']
        if not ans:
            ans = default
    return ans

def UI_YesNoCancel(text, default):
    if DEBUGGING:
        debug_logger.debug('UI_YesNoCancel: %s: %s %s' % (UI_mode, text, default))

    if UI_mode == 'text':
        yes = '(Y)es'
        no = '(N)o'
        cancel = '(C)ancel'
        yeskey = 'y'
        nokey = 'n'
        cancelkey = 'c'
        ans = 'XXXINVALIDXXX'
        while ans != 'c' and ans != 'n' and ans != 'y':
            sys.stdout.write('\n' + text + '\n')
            if default == 'y':
                sys.stdout.write('\n[%s] / %s / %s\n' % (yes, no, cancel))
            elif default == 'n':
                sys.stdout.write('\n%s / [%s] / %s\n' % (yes, no, cancel))
            else:
                sys.stdout.write('\n%s / %s / [%s]\n' % (yes, no, cancel))
            ans = readkey()
            if ans:
                ans = ans.lower()
            else:
                ans = default
    else:
        SendDataToYast({
                        'type': 'dialog-yesnocancel',
                        'question': text
                        })
        ypath, yarg = GetDataFromYast()
        ans = yarg['answer']
        if not ans:
            ans = default
    return ans

def UI_GetString(text, default):
    if DEBUGGING:
        debug_logger.debug('UI_GetString: %s: %s %s' % (UI_mode, text, default))
    string = default
    if UI_mode == 'text':
        sys.stdout.write('\n' + text + '\n')
        string = sys.stdin.readline()
    else:
        SendDataToYast({
                        'type': 'dialog-getstring',
                        'label': text,
                        'default': default
                        })
        ypath, yarg = GetDatFromYast()
        string = yarg['string']
    return string

def UI_GetFile(file):
    if DEBUGGING:
        debug_logger.debug('UI_GetFile: %s' % UI_mode)
    filename = None
    if UI_mode == 'text':
        sys.stdout.write(file['description'] + '\n')
        filename = sys.stdin.read()
    else:
        file['type'] = 'dialog-getfile'
        SendDataToYast(file)
        ypath, yarg = GetDataFromYast()
        if yarg['answer'] == 'okay':
            filename = yarg['filename']
    return filename

def UI_BusyStart(message):
    if DEBUGGING:
        debug_logger.debug('UI_BusyStart: %s' % UI_mode)
    if UI_mode == 'text':
        UI_Info(message)
    else:
        SendDataToYast({
                        'type': 'dialog-busy-start',
                        'message': message
                        })
        ypath, yarg = GetDataFromYast()

def UI_BusyStop():
    if DEBUGGING:
        debug_logger.debug('UI_BusyStop: %s' % UI_mode)
    if UI_mode != 'text':
        SendDataToYast({'type': 'dialog-busy-stop'})
        ypath, yarg = GetDataFromYast()

CMDS = {
        'CMD_ALLOW': '(A)llow',
        'CMD_OTHER': '(M)ore',
        'CMD_AUDIT_NEW': 'Audi(t)',
        'CMD_AUDIT_OFF': 'Audi(t) off',
        'CMD_AUDIT_FULL': 'Audit (A)ll',
        #'CMD_OTHER': '(O)pts',
        'CMD_USER_ON': '(O)wner permissions on',
        'CMD_USER_OFF': '(O)wner permissions off',
        'CMD_DENY': '(D)eny',
        'CMD_ABORT': 'Abo(r)t',
        'CMD_FINISHED': '(F)inish',
        'CMD_ix': '(I)nherit',
        'CMD_px': '(P)rofile',
        'CMD_px_safe': '(P)rofile Clean Exec',
        'CMD_cx': '(C)hild',
        'CMD_cx_safe': '(C)hild Clean Exec',
        'CMD_nx': 'Named',
        'CMD_nx_safe': 'Named Clean Exec',
        'CMD_ux': '(U)nconfined',
        'CMD_ux_safe': '(U)nconfined Clean Exec',
        'CMD_pix': '(P)rofile Inherit',
        'CMD_pix_safe': '(P)rofile Inherit Clean Exec',
        'CMD_cix': '(C)hild Inherit',
        'CMD_cix_safe': '(C)hild Inherit Clean Exec',
        'CMD_nix': '(N)amed Inherit',
        'CMD_nix_safe': '(N)amed Inherit Clean Exec',
        'CMD_EXEC_IX_ON': '(X) ix On',
        'CMD_EXEC_IX_OFF': '(X) ix Off',
        'CMD_SAVE': '(S)ave Changes',
        'CMD_CONTINUE': '(C)ontinue Profiling',
        'CMD_NEW': '(N)ew',
        'CMD_GLOB': '(G)lob',
        'CMD_GLOBEXT': 'Glob with (E)xtension',
        'CMD_ADDHAT': '(A)dd Requested Hat',
        'CMD_USEDEFAULT': '(U)se Default Hat',
        'CMD_SCAN': '(S)can system log for AppArmor events',
        'CMD_HELP': '(H)elp',
        'CMD_VIEW_PROFILE': '(V)iew Profile',
        'CMD_USE_PROFILE': '(U)se Profile',
        'CMD_CREATE_PROFILE': '(C)reate New Profile',
        'CMD_UPDATE_PROFILE': '(U)pdate Profile',
        'CMD_IGNORE_UPDATE': '(I)gnore Update',
        'CMD_SAVE_CHANGES': '(S)ave Changes',
        'CMD_UPLOAD_CHANGES': '(U)pload Changes',
        'CMD_VIEW_CHANGES': '(V)iew Changes',
        'CMD_VIEW': '(V)iew',
        'CMD_ENABLE_REPO': '(E)nable Repository',
        'CMD_DISABLE_REPO': '(D)isable Repository',
        'CMD_ASK_NEVER': '(N)ever Ask Again',
        'CMD_ASK_LATER': 'Ask Me (L)ater',
        'CMD_YES': '(Y)es',
        'CMD_NO': '(N)o',
        'CMD_ALL_NET': 'Allow All (N)etwork',
        'CMD_NET_FAMILY': 'Allow Network Fa(m)ily',
        'CMD_OVERWRITE': '(O)verwrite Profile',
        'CMD_KEEP': '(K)eep Profile',
        'CMD_CONTINUE': '(C)ontinue'
        }

def UI_PromptUser(q):
    cmd = None
    arg = None
    if UI_mode == 'text':
        cmd, arg = Text_PromptUser(q)
    else:
        q['type'] = 'wizard'
        SendDataToYast(q)
        ypath, yarg = GetDataFromYast()
        if not cmd:
            cmd = 'CMD_ABORT'
        arg = yarg['selected']
    if cmd == 'CMD_ABORT':
        confirm_and_abort()
        cmd == 'XXXINVALIDXXX'
    elif cmd == 'CMD_FINISHED':
        confirm_and_finish()
        cmd == 'XXXINVALIDXXX'
    return (cmd, arg)

def UI_ShortMessage(title, message):
    SendDataToYast({
                    'type': 'short-dialog-message',
                    'headline': title,
                    'message': message
                    })
    ypath, yarg = GetDataFromYast()

def UI_longMessage(title, message):
    SendDataToYast({
                    'type': 'long-dialog-message',
                    'headline': title,
                    'message': message
                    })
    ypath, yarg = GetDataFromYast()
