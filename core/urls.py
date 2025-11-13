from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('test-logging/', views.test_logging, name='test_logging'),
    path('login/', views.login_view, name='login'),
    path('signin/', views.LoginView.as_view(), name='signin'),
    path('api/', views.api_view, name='api'),
    path('public/', views.public_view, name='public'),
    path('rate-limit-status/', views.rate_limit_status, name='rate_limit_status'),
    path('sensitive-action/', views.SensitiveActionView.as_view(), name='sensitive_action'),
    path('admin/', views.AdminView.as_view(), name='admin'),
    path('trigger-detection/', views.TriggerDetectionView.as_view(), name='trigger_detection'),


    path('test-google/', views.home, name='test_google'),
    path('test-cloudflare/', views.home, name='test_cloudflare'),
    path('test-japan/', views.home, name='test_japan'),
    path('test-germany/', views.home, name='test_germany'),
    path('test-brazil/', views.home, name='test_brazil'),
    path('test-private/', views.home, name='test_private'),

]