import socket

def get_private_ip() -> str:
    """
    """
    # This method was extracted from pallet/flask (flask)
    # https://github.com/pallets/werkzeug/blob/a44c1d76689ae6608d1783ac628127150826c809/src/werkzeug/serving.py#L925
    """Get the IP address of an external interface. Used when binding to
    0.0.0.0 or ::1 to show a more useful URL.
    :meta private:
    """
    # arbitrary private address
    family = socket.AF_INET

    host = "10.253.155.219"
    # host = "fd31:f903:5ab5:1::1" if family == socket.AF_INET6 else "10.253.155.219"

    with socket.socket(family, socket.SOCK_DGRAM) as s:
        try:
            s.connect((host, 58162))
        except OSError:
            return "::1" if family == socket.AF_INET6 else "127.0.0.1"

        return s.getsockname()[0]  # type: ignore
