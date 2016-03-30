__author__ = 'liebesu'
import os
import ConfigParser
from lib.core.constants import CONFPATH
def read_conf():
    """read ida.conf
    """
    config = ConfigParser.ConfigParser()
    config.read(os.path.join(CONFPATH,"conf.conf"))

    datebaseip=config.get("Datebase","ip")
    datebaseuser=config.get("Datebase","user")
    datebasepsw=config.get("Datebase","password")
    datebasename=config.get("Datebase","databasename")
    datebasetable=config.get("Datebase","tablename")
    sha256filename=config.get("sha256 file","sha256filename")


    return datebaseip,datebaseuser,datebasepsw,datebasename,datebasetable,sha256filename

def check_config():
    '''check ida.config is exist or not
    '''
    configfile = os.path.join(CONFPATH , 'scan.conf')
    if not os.path.exists(configfile):
        print ("ida.conf file does not exist")
    else:
        print("ida.conf file is exist")
    return True
