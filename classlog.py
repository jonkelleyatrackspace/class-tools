import logging

class instance(object):
    def __init__(self,LOG_APPNAME='raxstat',LOG_FILE='/tmp/app.log',
                 LOG_LEVEL_FILEHANDLE=logging.DEBUG,
                 LOG_LEVEL_CONSOLE=logging.INFO):
        # Logger.
        self.logger = logging.getLogger(LOG_APPNAME)
        self.logger.setLevel(logging.DEBUG)
        # File handle.
        fh = logging.FileHandler(LOG_FILE)
        fh.setLevel(LOG_LEVEL_FILEHANDLE) # Eveeryyyyything.
        # Console handle.
        ch = logging.StreamHandler()
        ch.setLevel(LOG_LEVEL_CONSOLE) # Errors only.
        # Apply logformat.
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(filename)s:%(lineno)d - %(levelname)s - %(message)s - PID: %(process)d  ' )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        # Add handdler to logger instance.
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)


if __name__ == '__main__':
    """ Pretty much how to use this from a module """
    log = instance('lol','/var/log/lol.log')
    print("You found the secret cow level.")
    log.logger.debug('DEBUG.TEST.MESSAGE')
    log.logger.info('INFO.TEST.MESSAGE')
    log.logger.warn('WARN.TEST.MESSAGE')
    log.logger.error('ERROR.TEST.MESSAGE')
    log.logger.critical('CRITICAL.TEST.MESSAGE')
    
""" How to use in the wild:
  From your main application.py you must instanciate it first, doing something like:

  application.py
    import logclass; ohi = logclass.instance('project','/tmp/project.log',logging.DEBUG,logging.DEBUG)
    logger = logging.getLogger("project") 
    logger.debug('first message!')

  sub-module.py
    import logging; logger = logging.getLogger("raxstat") 
    logger.debug('first message!')

"""
