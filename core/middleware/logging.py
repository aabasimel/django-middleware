import logging

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter(fmt="%(asctime)s %(levelname)s; %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

class LoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Before view (pre-processing)

        request_data = {
            "method": request.method,
            "ip_address": request.META.get("REMOTE_ADDR"),
            "path": request.path
        }

        logger.info(request_data)

        response = self.get_response(request)
        logger.info(f"Outgoing response: {response.status_code}")  # <-- also module-level

       

        return response
