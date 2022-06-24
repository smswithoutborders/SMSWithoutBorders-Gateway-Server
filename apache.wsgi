import sys, os, logging
from inspect import getsourcefile
from os.path import abspath

sys.stdout = sys.stderr
logging.basicConfig(level='DEBUG', stream=sys.stderr)
# logging.basicConfig(stream=sys.stderr)
dir_path = os.path.dirname(abspath(getsourcefile(lambda:0)))
sys.path.insert(0, dir_path)

from main import app as application
