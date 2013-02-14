# Jon Kelley Feb 13 2013
import os, subprocess, tempfile
class strfromvim():
    """ Will open up vim, and capture your string input as variable.
        Supports optional welcome screen arguement to set initial text.
        Requires: import os, subprocess, tempfile
        Example:
            vim = strfromvim()
            vim.getinput('Welcome to vim!')
            print vim.output            """
    def __init__(self):
        (self.fd, self.path)  = tempfile.mkstemp()   # Makes in /tmp
    def getinput(self,welcomescreen=''):
        self.fp = os.fdopen(self.fd, 'w')       # This builds the vim startup text.
        self.fp.write(welcomescreen)            #     This builds the vim startup text.
        self.fp.close()                         #          This builds the vim startup text.

        OS_EDITOR = os.getenv('EDITOR', 'vi')
        #print(OS_EDITOR, self.path)
        subprocess.call('%s %s' % (OS_EDITOR, self.path), shell=True)

        with open(self.path, 'r') as f:
            self.output = f.read()
        
        os.unlink(self.path)

vim = strfromvim()
vim.getinput('Welcome to vim!')
print vim.output
