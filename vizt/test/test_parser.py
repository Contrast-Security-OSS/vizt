import unittest

import vizt
from vizt.model import *
from vizt.parser import *

import xml.etree.ElementTree as ET

class TestXmlParser(unittest.TestCase):

    def test_xml_file(self):
        traces = None
        with open('vizt/test/confluence.xml','r') as xml:
            traces = vizt.parse_traces(xml)
        #print( traces )
        self.assertIsNotNone( traces )
        self.assertEqual(len(traces), 1)
        trace = traces[0]
        self.assertEqual(trace.uuid, "NBGK-IUPQ-SLL5-X86V")
        self.assertEqual(len(trace.request.headers), 16)
        self.assertEqual(trace.request.headers[0].name, "Sec-fetch-mode")
        self.assertEqual(trace.request.headers[0].value, "navigate")

        self.assertEqual(len(trace.request.params), 3)
        self.assertEqual(trace.request.params[2].name, "setupType")
        self.assertEqual(trace.request.params[2].value, "install")

        self.assertEqual( len(trace.events), 5 )
        creation = trace.events[0]
        self.assertEqual(creation.event_type, "Creation")
        self.assertEqual(creation.signature, "java.util.Map javax.servlet.ServletRequestWrapper.getParameterMap()")
        self.assertEqual(creation.stack[0].value, "javax.servlet.ServletRequestWrapper.getParameterMap(ServletRequestWrapper.java:167)")
        self.assertEqual(len(creation.sources), 0)
        self.assertEqual(creation.target, "R")
        self.assertEqual(creation.thread, "http-nio-8090-exec-2 (id 89)")

        self.assertEqual(len(creation.taint_ranges),4)
        self.assertEqual(creation.taint_ranges[0].ranges[0][1], 9)
        self.assertEqual(creation.taint_ranges[0].tag, "untrusted")

        trigger = trace.events[-1]
        self.assertEqual(len(trigger.sources),1)

    def test_taint_range_class(self):
        # taint ranges should be ordered
        tr = TaintRange(tag="test")
        tr.add_range(9,10)
        tr.add_range(1,2)
        self.assertEqual(tr.ranges[0][0],1)

    def test_taint_range_split_basic(self):
        tr = TaintRange(tag="test")
        tr.add_range(3,6)
        s = tr.split("abcdefghijklmnop")
        self.assertEqual( s[0], "abc" )
        self.assertEqual( s[1], "def" )
        self.assertEqual( s[2], "ghijklmnop" )
    
    def test_taint_range_split_multi_gap(self):
        tr = TaintRange(tag="test")
        tr.add_range(18,21)
        tr.add_range(22,29)
        tr.add_range(30,37)
        self.assertEqual( tr.extract("/WEB-INF/classes//org/kohsuke/stapler/.adjunct"), ['org', 'kohsuke', 'stapler'] )
        self.assertEqual( tr.split("/WEB-INF/classes//org/kohsuke/stapler/.adjunct"), ['/WEB-INF/classes//', 'org', '/', 'kohsuke', '/', 'stapler','/.adjunct'])

    def test_taint_range_split_multi_back_to_back(self):
        tr = TaintRange(tag="test")
        tr.add_range(17,21)
        tr.add_range(21,29)
        tr.add_range(29,37)
        self.assertEqual( tr.extract("/WEB-INF/classes//org/kohsuke/stapler/.adjunct"), ['/org', '/kohsuke', '/stapler'] )
        self.assertEqual( tr.split("/WEB-INF/classes//org/kohsuke/stapler/.adjunct"), ['/WEB-INF/classes/', '/org', '/kohsuke', '/stapler','/.adjunct'])

    def test_taint_range_decorate(self):
        tr = TaintRange(tag="test")
        tr.add_range(17,21)
        tr.add_range(21,29)
        tr.add_range(29,37)
        self.assertEqual( tr.split("/WEB-INF/classes//org/kohsuke/stapler/.adjunct", wrap_taint=("<b>", "</b>") ), ['/WEB-INF/classes/', '<b>/org</b>', '<b>/kohsuke</b>', '<b>/stapler</b>','/.adjunct'])
        self.assertEqual( tr.decorate("/WEB-INF/classes//org/kohsuke/stapler/.adjunct", taint=("<b>", "</b>") ), '/WEB-INF/classes/<b>/org</b><b>/kohsuke</b><b>/stapler</b>/.adjunct' )

    def test_taint_range_decorate_multi(self):
        tr = TaintRange(tag="test")
        tr.add_range(3,6)
        self.assertEqual( tr.decorate("abcdefghijklmnop", taint=("*", "*"), non_taint=("!", "!") ) , "!abc!*def*!ghijklmnop!" )

    def test_taint_range_xml(self):
        tp = TraceParser("<foo/>")
        tr_xml = ET.fromstring( "<taint-range><tag>no-newlines</tag><range>0:12,15:32</range></taint-range>" )
        tr = tp._parse_taint_range( tr_xml )
        self.assertEqual( len(tr.ranges), 2)
        self.assertEqual( tr.ranges[0][1], 12)
        self.assertEqual( tr.extract("1234567890123456789012345678901234567890")[1], "67890123456789012")






if __name__ == '__main__':
    unittest.main()