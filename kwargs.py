class ExampleClass( object ):
    def __init__(self, **kwargs):
        self.val = "default1"
        self.val2 = "default2"
        if "val" in kwargs:
            self.val = kwargs["val"]
            self.val2 = 2*self.val
        elif "val2" in kwargs:
            self.val2 = kwargs["val2"]
            self.val = self.val2 / 2
        else:
            raise TypeError( "must provide val= or val2= parameter values" )
