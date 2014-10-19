__author__ = 'shahbaz'

from pydatapath.core import *

# ###############################################################################
# Main policy
# ###############################################################################
def main():
    policy = ((match(inport=1) >> modify(outport=2)) +
              (match(inport=2) >> modify(outport=1)))

    return policy