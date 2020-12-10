class Trace:
    def __init__(self):
        self.uuid = None
        self.link = None
        self.agent_version = None
        self.application_name = None
        self.rule_id = None

        #self.query_string = None
        self.request = Request()

        self.events = []

        # self.stack_graph = None
        # self.object_graph = None


class Request:
    def __init__(self):
        self.method = None
        self.uri = None
        self.port = None
        self.query_string = None
        self.body = None
        self.headers = []
        self.params = []

class RequestParam:
    def __init__(self, name=None, value=None):
        self.name = name
        self.value = value
    
    def __str__(self):
        return "{name}={value}".format(name=self.name, value=self.value)

class RequestHeader:
    def __init__(self, name=None, value=None):
        self.name = name
        self.value = value
    
    def __str__(self):
        return "{name}: {value}".format(name=self.name, value=self.value)

class Event:
    def __init__(self):
        self.signature = None
        self.event_type = None
        self.thread = None
        self.sources = []
        self.target = None
        self.object_id = None
        self.obj = None # EventObj
        self.ret = None # EventObj
        self.taint_ranges = [] 
        self.args = [] # EventObj[]
        self.stack = []

class EventObj:
    def __init__(self):
        self.tracked = False
        self.value = None
        self.hashCode = None

class StackFrame:
    def __init__(self, value=None):
        self.value = value

    def __str__(self):
        return self.value

class TaintRange:
    def __init__(self, tag=None):
        self.tag = tag
        self.ranges = []

    def add_range(self, start, end):
        self.ranges.append( (start, end) )
        self.ranges.sort()

    # extract ranges from string
    def extract(self, text):
        matches = []
        for r in self.ranges:
            matches.append( text[r[0]:r[1]])
        return matches
    
    # split provided text up based on taint ranges
    def split(self, text, wrap_taint=("", ""), wrap_non_taint=("", "")):
        #  TODO - taint ranges shouldnt overlap
        ptr_last = 0
        matches = []
        for r in self.ranges:
            trailing = text[ptr_last:r[0]]
            if trailing != '':
                matches.append( "{wrap[0]}{value}{wrap[1]}".format( wrap=wrap_non_taint, value=trailing) )
            matches.append( "{wrap[0]}{value}{wrap[1]}".format( wrap=wrap_taint, value=text[r[0]:r[1]]) )
            ptr_last = r[1]
        if ptr_last < len(text):
            matches.append( "{wrap[0]}{value}{wrap[1]}".format( wrap=wrap_non_taint, value=text[ptr_last:]) )
        return matches

    # wrap the taint ranges in a string with provided prefix and suffix
    def decorate(self, text, taint, non_taint=("", "")):
        return "".join( self.split(text, taint, non_taint ))

    def __str__(self):
        return "{tag}: {ranges}".format(tag=self.tag, ranges=",".join( ["{}:{}".format(r[0],r[1]) for r in self.ranges] ))