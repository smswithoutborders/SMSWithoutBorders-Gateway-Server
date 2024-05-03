"""API V3 Blueprint"""

import logging

from flask import Blueprint, request, jsonify
from flask_cors import CORS
from werkzeug.exceptions import BadRequest

from src.controllers import query_gateway_clients, check_reliability_tests
from src.db import connect

v3_blueprint = Blueprint("v3", __name__, url_prefix="/v3")
CORS(v3_blueprint)

database = connect()

logger = logging.getLogger(__name__)


def set_security_headers(response):
    """Set security headers for each response."""
    security_headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubdomains",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "script-src 'self'; object-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Cache-Control": "no-cache",
        "Permissions-Policy": (
            "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), "
            "clipboard-read=(), clipboard-write=(), cross-origin-isolated=(), display-capture=(), "
            "document-domain=(), encrypted-media=(), execution-while-not-rendered=(), "
            "execution-while-out-of-viewport=(), fullscreen=(), gamepad=(), geolocation=(), "
            "gyroscope=(), magnetometer=(), microphone=(), midi=(), navigation-override=(), "
            "payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), "
            "speaker=(), speaker-selection=(), sync-xhr=(), usb=(), web-share=(), "
            "xr-spatial-tracking=()"
        ),
    }

    for header, value in security_headers.items():
        response.headers[header] = value

    return response


@v3_blueprint.before_request
def _db_connect():
    """Connect to the database before processing the request."""
    database.connect()


@v3_blueprint.teardown_request
def _db_close(response):
    """Close the database connection after processing the request."""
    database.close()
    return response


@v3_blueprint.after_request
def after_request(response):
    """Set security headers after each request."""
    response = set_security_headers(response)
    return response


@v3_blueprint.route("/clients", methods=["GET"])
def get_gateway_clients():
    """Get gateway clients with optional filters"""

    filters = {
        "country": request.args.get("country") or None,
        "operator": request.args.get("operator") or None,
        "protocol": request.args.get("protocol") or None,
    }

    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 10))

    check_reliability_tests()
    results = query_gateway_clients(filters, page, per_page)

    return jsonify(results)


@v3_blueprint.errorhandler(BadRequest)
def handle_bad_request_error(error):
    """Handle BadRequest errors."""
    logger.error(error.description)
    return jsonify({"error": error.description}), error.code


@v3_blueprint.errorhandler(Exception)
def handle_generic_error(error):
    """Handle generic errors."""
    logger.exception(error)
    return jsonify({"error": "An unexpected error occurred"}), 500
