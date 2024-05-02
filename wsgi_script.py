"""WSGI script for running the application."""

import logging

logging.basicConfig(level=logging.DEBUG)

from src.main import app as application
