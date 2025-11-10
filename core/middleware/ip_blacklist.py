from django.core.exceptions import PermissionDenied
from django.conf import settings


class IPBlacklistMiddleware:
        def __init__(self,get_response):
             self.get_reponse = get_response

        
        def __call__(self,request):
               
            if hasattr(settings, 'BANNED_IPS') and settings.BANNED_IPS is not None:
                  ip = request.META.get("REMOTE_ADDR")
                  if ip in settings.BANNED_IPS:
                       raise PermissionDenied()

            response = self.get_reponse(request)
            return response


             
