from vizt.parser import TraceParser

"""
returns a list of Trace objects
"""
def parse_traces( xmlInput, **kwargs ):
    return TraceParser(xmlInput).get_all_traces()

# def dump_trace( trace ):

# def get_stack_graph( trace, pruned=False ):
# def get_object_graph( trace ):

# graph.to_dot()
# graph.to_json()
