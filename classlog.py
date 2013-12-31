import logging

class logObject(object):
    def setLogFormat(self,format=None):
        """ Set this before you run buildlogger if you want to overwrite the default log formatting params"""
            self.format = format
    def getLogFormat(self):
        """ Used internally to return a default log string if you don't override it"""
        if not hasattr(self, 'format'):
            return '%(asctime)s - %(name)s - %(filename)s:%(lineno)d - %(levelname)s - %(message)s - PID: %(process)d '
        else:
            return self.format
    def buildLogger(self,
                    LOG_APPNAME='myapp',
                    LOG_FILE='/tmp/myapp.log',
                    LOG_LEVEL_FILEHANDLE=logging.NOTSET,
                    LOG_LEVEL_CONSOLE=logging.NOTSET):
        """ Sets up the logger """
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
        format = self.getLogFormat()
        formatter = logging.Formatter(format)


        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        # Add handdler to logger instance.
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

if __name__ == '__main__':
    """ Pretty much how to use this from a module """
    log = logObject()
    log.setLogFormat('Custom format... %(asctime)s - %(name)s - %(filename)s:%(lineno)d - %(levelname)s - %(message)s - PID: %(process)d')
    log.buildLogger('lol','/tmp/lol.log',LOG_LEVEL_CONSOLE=logging.DEBUG)
    print("You found the secret cow level.")
    log.logger.debug('DEBUG.TEST.MESSAGE')
    log.logger.info('INFO.TEST.MESSAGE')
    log.logger.warn('WARN.TEST.MESSAGE')
    log.logger.error('ERROR.TEST.MESSAGE')
    log.logger.critical('CRITICAL.TEST.MESSAGE')
    


