"""API V3 Blueprint"""

import logging

from flask import Blueprint, request, jsonify
from playhouse.shortcuts import model_to_dict
from peewee import fn
from werkzeug.exceptions import BadRequest

from src.models.db_connector import connect
from src.models.gateway_clients import GatewayClients

v3_blueprint = Blueprint("v3", __name__, url_prefix="/v3")

logger = logging.getLogger(__name__)

database = connect()


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
def before_request():
    """Connect to the database before each request."""
    if not database.is_closed():
        database.close()
    database.connect()


@v3_blueprint.after_request
def after_request(response):
    """Close the database connection and set security headers after each request."""
    if not database.is_closed():
        database.close()
    response = set_security_headers(response)
    return response


@v3_blueprint.route("/gateway-clients", methods=["GET"])
def get_gateway_clients():
    """Get gateway clients with optional filters"""

    filters = {
        "country": request.args.get("country") or None,
        "operator": request.args.get("operator") or None,
        "protocol": request.args.get("protocol") or None,
        "published": request.args.get("published"),
    }

    published_value = filters["published"]
    if published_value is not None and published_value != "":
        published = published_value.lower()
        if published in ("true", "1", "yes"):
            filters["published"] = True
        elif published in ("false", "0", "no"):
            filters["published"] = False
        else:
            raise BadRequest("Published must be boolean (True or False, 1 or 0)")
    else:
        filters["published"] = None

    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 10))

    query = GatewayClients.select().paginate(page, per_page)

    for key, value in filters.items():
        if value is not None:
            if key in ("country", "operator", "protocol"):
                query = query.where(
                    fn.lower(getattr(GatewayClients, key)) == value.lower()
                )
            else:
                query = query.where(getattr(GatewayClients, key) == value)

    results = [model_to_dict(client) for client in query]

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
