from .models import RequestLog, SuspiciousIP, BlockedIP
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count, Q
import logging

logger = logging.getLogger(__name__)
from celery import shared_task


@shared_task
def detect_suspicious_ips():
    """
    Celery task to detect suspicious IPs based on:
    - IPs with >100 requests in the last hour
    - IPs accessing sensitive paths (/admin, /login, etc.)
    """

    logger.info("Starting suspicious IP detection task")

    one_hour_ago = timezone.now() - timedelta(hours = 1)
    high_volume_ips = detect_high_volume_ips(one_hour_ago)
    sensitive_path_ips = detect_sensitive_path_access(one_hour_ago)
    logger.info(f"High volume IPs flagged: {high_volume_ips}")
    logger.info(f"Sensitive path IPs flagged: {sensitive_path_ips}")


def detect_high_volume_ips(one_hour_ago):
    """
    Detect IPs with more than 100 requests in the last hour
    """
    try:
        high_volume_ips = (
            RequestLog.objects
            .filter(timestamp__gte=one_hour_ago)
            .values('ip_address')
            .annotate(request_count=Count('id'))
            .filter(request_count__gt=100)
            .order_by('-request_count')
        )

        created_count = 0
        updated_count = 0

        for ip_data in high_volume_ips:
            if BlockedIP.objects.filter(ip_address=ip_data['ip_address'], is_active=True).exists():
                logger.info(f"Skipping {ip_data['ip_address']} - already blocked")
                continue

            try:
                suspicious_ip, created = SuspiciousIP.objects.update_or_create(
                    ip_address=ip_data['ip_address'],
                    reason='high_volume',
                    defaults={
                        'reason': 'high_volume',
                        'is_active': True,
                        'details': {'request_count': ip_data['request_count']}
                    }
                )
                if created:
                    created_count += 1
                    logger.info(f"Flagged new suspicious IP (high volume): {ip_data['ip_address']} with {ip_data['request_count']} requests")
                else:
                    updated_count += 1

            except Exception as e:
                logger.error(f"Error flagging suspicious IP {ip_data['ip_address']}: {e}")

        return created_count + updated_count

    except Exception as e:
        logger.error(f"Error detecting high volume IPs: {e}")
        return 0

def detect_sensitive_path_access(one_hour_ago):
    try:
        sensitive_paths = [
            '/admin/', '/login/', '/wp-admin/', '/phpmyadmin/',
            '/.env', '/config/', '/api/auth/', '/api/login/',
            '/user/login/', '/account/login/', '/signin/',
            '/administrator/', '/backend/', '/dashboard/'
        ]
        
        sensitive_path_query = Q()
        for path in sensitive_paths:
            sensitive_path_query |= Q(path__startswith=path)
        
        sensitive_access_ips = (
            RequestLog.objects
            .filter(timestamp__gte=one_hour_ago)
            .filter(sensitive_path_query)
            .exclude(ip_address__in=['127.0.0.1', 'localhost', '::1'])
            .values('ip_address')
            .annotate(
                request_count=Count('id'),
                sensitive_paths_count=Count('path', distinct=True)
            )
            .filter(request_count__gt=0)
            .order_by('-request_count')
        )
        
        total_sensitive_requests = 0
        processed_ips = 0
        
        for ip_data in sensitive_access_ips:
            if BlockedIP.objects.filter(ip_address=ip_data['ip_address'], is_active=True).exists():
                logger.info(f"Skipping {ip_data['ip_address']} - already blocked")
                continue
            
            accessed_paths = (
                RequestLog.objects
                .filter(
                    timestamp__gte=one_hour_ago,
                    ip_address=ip_data['ip_address']
                )
                .filter(sensitive_path_query)
                .values_list('path', flat=True)
                .distinct()
            )
            
            try:
                suspicious_ip, created = SuspiciousIP.objects.update_or_create(
                    ip_address=ip_data['ip_address'],
                    reason='sensitive_paths',
                    defaults={
                        'request_count': ip_data['request_count'],
                        'details': {
                            'sensitive_paths_accessed': list(accessed_paths),
                            'total_sensitive_requests': ip_data['request_count'],
                            'unique_sensitive_paths': ip_data['sensitive_paths_count'],
                            'detection_method': 'sensitive_paths_only',
                            'detection_time': timezone.now().isoformat()
                        },
                        'is_active': True
                    }
                )
                
                total_sensitive_requests += ip_data['request_count']
                processed_ips += 1
                
                if created:
                    logger.warning(f"SENSITIVE PATHS - Created SuspiciousIP: {ip_data['ip_address']} - {ip_data['request_count']} requests across {len(accessed_paths)} sensitive paths")
                else:
                    logger.info(f"SENSITIVE PATHS - Updated SuspiciousIP: {ip_data['ip_address']} - {ip_data['request_count']} requests across {len(accessed_paths)} sensitive paths")
                    
            except Exception as e:
                logger.error(f"Error creating sensitive paths SuspiciousIP for {ip_data['ip_address']}: {e}")
        
        logger.info(f"Sensitive paths detection: processed {processed_ips} IPs with {total_sensitive_requests} total sensitive requests")
        return total_sensitive_requests
        
    except Exception as e:
        logger.error(f"Error in sensitive paths detection: {e}")
        return 0