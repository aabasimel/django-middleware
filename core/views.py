import os
from django.http import HttpResponse, JsonResponse
from django.contrib.auth import authenticate, login 
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
from django_ratelimit.decorators import ratelimit
from .tasks import detect_suspicious_ips
from .models import RequestLog

def home(request):
    return HttpResponse("Home page")

def test_logging(request):
    """Test endpoint to verify logging is working"""
    log_exists = os.path.exists('result.txt')
    log_contents = ""
    
    if log_exists:
        with open('result.txt', 'r') as f:
            log_contents = f.read()
    
    return JsonResponse({
        'message': 'Test logging endpoint',
        'log_file_exists': log_exists,
        'log_file_contents': log_contents,
        'your_ip': request.META.get('REMOTE_ADDR'),
        'all_meta_keys': list(request.META.keys())
    })

@ratelimit(key='ip', rate='5/m', block=True)
@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        task = detect_suspicious_ips.delay()

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return JsonResponse({
                'status': 'success',
                'message': 'Login successful',
                'user': user.username,
                'celery_task_id': task.id
            })
        else:
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid credentials'
            }, status=400)
    else:
        return JsonResponse({
            'status': 'error',
            'message': 'Only POST method is allowed'
        }, status=405)

# API view with different rate limits based on authentication
@ratelimit(key='user_or_ip', rate='10/m', method=['GET', 'POST'], block=True)
def api_view(request):
    """
    API view with different rate limits for authenticated vs anonymous users
    """
    if request.user.is_authenticated:
        limit_info = '10 requests/minute (authenticated)'
    else:
        limit_info = '5 requests/minute (anonymous)'
    
    return JsonResponse({
        'message': 'API response',
        'user_authenticated': request.user.is_authenticated,
        'rate_limit': limit_info,
        'user': request.user.username if request.user.is_authenticated else 'Anonymous'
    })

# Public view without rate limiting for comparison
def public_view(request):
    """
    Public view without rate limiting
    """
    return JsonResponse({
        'message': 'This is a public view without rate limiting',
        'ip_address': request.META.get('REMOTE_ADDR')
    })

# View to check current rate limit status
@ratelimit(key='ip', rate='5/m', method='GET')
def rate_limit_status(request):
    """
    View to check rate limit status without blocking
    """
    was_limited = getattr(request, 'limited', False)
    
    return JsonResponse({
        'ip_address': request.META.get('REMOTE_ADDR'),
        'rate_limited': was_limited,
        'message': 'Rate limit check - this endpoint has rate limiting but wont block'
    })

@method_decorator(ratelimit(key='user_or_ip', rate='10/m', method='POST', block=True), name='dispatch')
class SensitiveActionView(View):
    """
    A sensitive action that requires different rate limits for authenticated vs anonymous users
    """
    
    def post(self, request):
        if request.user.is_authenticated:
            return JsonResponse({
                'status': 'success',
                'message': 'Sensitive action performed',
                'user': request.user.username,
                'rate_limit': '10/minute (authenticated)'
            })
        else:
            return JsonResponse({
                'status': 'success', 
                'message': 'Sensitive action performed',
                'rate_limit': '5/minute (anonymous)'
            })

def rate_limit_exceeded(request, exception=None):
    return JsonResponse({
        'error': 'Too many requests',
        'message': 'You have exceeded the allowed number of requests.'
    }, status=429)

class LoginView(View):
    """
    Login view that triggers anomaly detection
    """
    @method_decorator(csrf_exempt)
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True))
    def post(self, request):
        # Log this access
        ip_address = self.get_client_ip(request)
        
        RequestLog.objects.create(
            ip_address=ip_address,
            path='/signin/',
            method='POST',
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        task = detect_suspicious_ips.delay()
        
        return JsonResponse({
            'status': 'login_attempt_logged',
            'message': 'Login attempt recorded - anomaly detection triggered',
            'your_ip': ip_address,
            'celery_task_id': task.id,
            'note': 'Check Celery worker logs to see detection in action'
        })
    def get(self, request):
        """Handle GET requests to /signin/"""
        ip_address = self.get_client_ip(request)
        
        RequestLog.objects.create(
            ip_address=ip_address,
            path='/signin/',
            method='GET',
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        task = detect_suspicious_ips.delay()
        
        return JsonResponse({
            'status': 'signin_page_accessed',
            'message': 'Signin page accessed - anomaly detection triggered',
            'your_ip': ip_address,
            'celery_task_id': task.id,
            'note': 'This access is being monitored for suspicious behavior'
        })

    def get_client_ip(self, request):
        """Get the client IP address - ADD THIS MISSING METHOD"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')

class AdminView(View):
    """
    Admin view that triggers anomaly detection
    """
    def get(self, request):
        ip_address = self.get_client_ip(request)
        
        RequestLog.objects.create(
            ip_address=ip_address,
            path='/admin/',
            method='GET',
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        task = detect_suspicious_ips.delay()
        
        return JsonResponse({
            'status': 'admin_access_logged',
            'message': 'Admin access recorded - checking for suspicious activity',
            'your_ip': ip_address,
            'celery_task_id': task.id
        })

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')

class TriggerDetectionView(View):
    """
    View to manually trigger anomaly detection
    """
    def get(self, request):
        # Simply trigger the Celery task
        task = detect_suspicious_ips.delay()
        
        return JsonResponse({
            'status': 'success',
            'message': 'Anomaly detection task queued in Celery',
            'celery_task_id': task.id,
            'instruction': 'Check your Celery worker terminal to see the task executing'
        })