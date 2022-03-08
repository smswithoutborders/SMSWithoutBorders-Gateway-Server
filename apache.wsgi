import sys, os, logging
sys.stdout = sys.stderr
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, '/var/www/Deku-Router')

from main import app as application
