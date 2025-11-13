from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    pass 

class Location(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE,related_name='location')
    latitude = models.DecimalField(max_digits=12, decimal_places=6)
    longitude = models.DecimalField(max_digits=12,decimal_places=6)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username}'s location "
    

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)
    method = models.CharField(max_length=10,default='GET')
    user_agent = models.TextField(blank=True, null=True)
    country = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=255, blank=True)
    class Meta:
        db_table = 'request_logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['path']),
        ]

    def __str__(self):
        return f"{self.ip_address} - {self.path} - {self.timestamp}"
    
class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    reason = models.TextField(blank=True, null=True)

    is_active = models.BooleanField(default=True)  

    class Meta:
        db_table = 'blocked_ips'
        verbose_name = 'Blocked IP'
        verbose_name_plural = 'Blocked IPs'
        ordering = ['-created_at']

    def __str__(self): 
         
        status = "Active" if self.is_active else "Inactive"
        return f"{self.ip_address} - {status} - {self.created_at}"
class SuspiciousIP(models.Model):
    REASON_CHOICES = [
        ('high_volume', 'High request volume (>100/hour)'),
        ('sensitive_paths', 'Accessing sensitive paths'),
        ('multiple_reasons', 'Multiple suspicious activities'),
    ]
    
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=20, choices=REASON_CHOICES)
    detected_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    details = models.JSONField(default=dict, blank=True) 
    
    class Meta:
        db_table = 'suspicious_ips'
        verbose_name = 'Suspicious IP'
        verbose_name_plural = 'Suspicious IPs'
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['detected_at']),
            models.Index(fields=['is_active']),
        ]
        
    def __str__(self):
        status = "Active" if self.is_active else "Inactive"
        return f"{self.ip_address} - {self.get_reason_display()} - {status}"
    
    @classmethod
    def is_suspicious(cls, ip_address):
        """Check if an IP is currently flagged as suspicious"""
        return cls.objects.filter(ip_address=ip_address, is_active=True).exists()
    