from django.shortcuts import render
from django.http import JsonResponse
import os


from django.http import HttpResponse

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