import gettext
import locale

def init_localisation():
    locale.setlocale(locale.LC_ALL, '')
    cur_locale = locale.getlocale()
    filename = ''
    #If a correct locale has been provided set filename else let a IOError be raised by '' path
    if cur_locale[0]:
        filename = '/usr/share/locale/%s/LC_MESSAGES/apparmor-utils.mo' % locale.getlocale()[0][0:2]
    try:
        trans = gettext.GNUTranslations(open(filename, 'rb'))
    except IOError:
        trans = gettext.NullTranslations()
    trans.install()
    
init_localisation()