from vizt.model import *

import xml.etree.ElementTree as ET
from base64 import b64decode

class TraceParser:
    def __init__(self, xmlInput):
        self.root = None
        if hasattr(xmlInput, 'read'):
            # probably a file like object
            tree = ET.parse( xmlInput )
            self.root = tree.getroot()
        elif isinstance(xmlInput, str):
            self.root = ET.fromstring( xmlInput )
        else:
            raise Exception('Parser expects string or file like object, not:', type(xmlInput) )

    def _parse_finding_node(self, trace, finding):
        # parse finding details
        trace.uuid = finding.get('uuid')
        trace.link = finding.get('link')
        trace.agent_version = finding.get('agent-version')
        trace.application_name = finding.get('application-name')
        trace.rule_id = finding.get('ruleId')

    def _parse_request_node(self, trace, req):
        if req is not None: 
            trace.request.method = req.get('method')
            trace.request.uri = req.get('uri')
            trace.request.port = req.get('port')
            if req.get('qs'): # is there a query string?
                trace.request.query_string = req.get('qs')
            
            for header in req.findall('./headers/'):
                trace.request.headers.append( RequestHeader(name=header.get('name'), value=header.get('value')) )

            for param in req.findall('./parameters/'):
                trace.request.params.append( RequestParam(name=param.get('name'), value=param.get('value')) )

            body = req.find('./body')
            if body is not None and body.text is not None:
                trace.request.body = body.text

    def _parse_event_node(self, e):
        event = Event()
        event.signature = e.find('signature').text
        event.event_type = e.get('type')

        if e.get('source'): # source can be None
            event.sources = e.get('source').split(',')
        event.target = e.get('target')
        event.thread = e.get('thread')
        event.object_id = e.get('objectId')

        # get event source object
        event.obj = EventObj()
        obj = e.find('object')
        event.obj.hashCode = obj.get('hashCode')
        event.obj.tracked = obj.get('tracked') == "true"
        if obj.text is not None: # can be None
            event.obj.value = b64decode( obj.text )

        # get event return object
        event.ret = EventObj()
        ret = e.find('object')
        event.ret.hashCode = ret.get('hashCode')
        event.ret.tracked = ret.get('tracked') == "true"
        if ret.text is not None:
            event.ret.value = b64decode( ret.text ).decode()

        # get taint ranges
        for tr in e.findall('./taint-ranges/taint-range'):
            event.taint_ranges.append( self._parse_taint_range(tr) )
        
        # get event arg objects
        for arg in e.findall('./args/arg'):
            event_arg = EventObj()
            event_arg.hashCode = arg.get('hashCode')
            event_arg.tracked = arg.get('tracked') == "true"
            if arg.text:
                event_arg.value = b64decode(arg.text).decode()
            event.args.append( event_arg )

        # get stack frames
        for frame in e.findall('./stack/frame'):
            event.stack.append( StackFrame( frame.text ) )

        return event

    def _parse_taint_range(self, tr):
        #taint_ranges = []
        taint_range = TaintRange()
        raw_range = tr.find('range').text
        taint_range.tag = tr.find('tag').text
        if raw_range: # can be None
            for raw_ranges in raw_range.split(','):# 22:54,42:67
                split_range = raw_ranges.split(':') 
                if( len( split_range) == 2):
                    start_range = int( split_range[0] )
                    end_range = int( split_range[1] )
                    taint_range.add_range( start=start_range, end=end_range )
                    #taint_ranges.append( TaintRange(start=start_range, end=end_range, tag=tag) )
        return taint_range



    def get_all_traces(self):
        traces = []
        for finding in self.root.findall('./finding'):
            trace = Trace()
            
            self._parse_finding_node(trace, finding)
            
            # parse HTTP request information
            req = finding.find('./request')
            self._parse_request_node(trace, req)

            # parse all events
            for e in finding.findall('./events/'): 
                event = self._parse_event_node(e)
                trace.events.append( event )

            traces.append( trace )
        return traces


    