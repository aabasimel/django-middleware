from django.urls import path
from .views import home, test_logging
from . import views  # ADD THIS IMPORT


urlpatterns = [
    path("", home, name="home"),
    path('',test_logging, name = 'test_logging'), 
    path('test/', test_logging, name=' test_logging'), 
    path('test-google/', views.home),  
    path('test-japan/', views.home),  
    path('test-germany/', views.home), 
]
