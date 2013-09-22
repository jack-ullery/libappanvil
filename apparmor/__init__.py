import gettext
import locale

def init_localisation():
    locale.setlocale(locale.LC_ALL, '')
    #If a correct locale has been provided set filename else let an IOError be raised
    filename = '/usr/share/locale/%s/LC_MESSAGES/apparmor-utils.mo' % locale.getlocale()[0]
    try:
        trans = gettext.GNUTranslations(open(filename, 'rb'))
    except IOError:
        trans = gettext.NullTranslations()
    trans.install()

init_localisation()