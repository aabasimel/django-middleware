from core.models import RequestLog, BlockedIP
import logging 
from django.core.cache import cache 
from django.http import HttpResponse
import requests
import os
from datetime import datetime
import time  

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter(fmt="%(asctime)s %(levelname)s; %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
class RequestLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.log_file_path = 'result.txt'  
        self._ensure_log_file() 
        self.cache_stats = {'hits': 0, 'misses': 0}  # Add this
        self._ensure_log_file() 

    def _ensure_log_file(self):
        """Create the log file if it doesn't exist"""
        try:
            if not os.path.exists(self.log_file_path):
                with open(self.log_file_path, 'w') as f:
                    f.write("Timestamp,IP Address,Country,City,Path,Method,User Agent,Status\n")
                logger.info(f"Created log file: {self.log_file_path}")
            else:
                logger.info(f"Log file already exists: {self.log_file_path}")
        except Exception as e:
            logger.error(f"Failed to create log file: {e}")

    def __call__(self, request):
        ip_address = self._get_client_ip(request)
        
        if ip_address and self.is_ip_blocked(ip_address):
            logger.warning(f"Blocked request from blacklisted IP: {ip_address}")

            self._log_to_file(ip_address, "Blocked,Blocked", request.path, 
                            request.method, request.META.get("HTTP_USER_AGENT", ""), 'BLOCKED')
            return HttpResponse(
                "Access denied. Your IP address has been blocked.",
                status=403
            )
        
        self._log_request_with_geolocation(request, ip_address)

        response = self.get_response(request)
        return response

    def _get_client_ip(self, request):
        """
        Get the client's IP address from the request object.
        Handles various scenarios like proxies, load balancers, etc.

        """

        """
    Get the client's IP address from the request object.
    TEMPORARY: Simulate different IPs for testing
    """
    # Test IPs based on URL paths
        if request.path.startswith('/test-google'):
            return '8.8.8.8'  # Google DNS - United States
        elif request.path.startswith('/test-cloudflare'):
            return '1.1.1.1'  # Cloudflare - Various locations
        elif request.path.startswith('/test-japan'):
            return '210.249.120.1'  # Example Japanese IP
        elif request.path.startswith('/test-germany'):
            return '5.9.118.1'  # Example German IP
        elif request.path.startswith('/test-brazil'):
            return '200.160.1.1'  # Example Brazilian IP
        elif request.path.startswith('/test-private'):
            return '192.168.1.100'
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip
    
    def _should_skip_logging(self, request):
        excluded_paths = ["/health/", "/admin/"]
        for path in excluded_paths:
            if request.path.startswith(path):
                return True
        return False
    
    def is_ip_blocked(self, ip_address):
        """
        Check if the IP address is in the blocked list and active.
        Uses database query to check for blocked IPs.
        """
        try:
            return BlockedIP.objects.filter(
                ip_address=ip_address,
                is_active=True
            ).exists()
        except Exception as e:
            logger.error(f"Error checking blocked IPs: {e}")
            return False

    def _log_request_with_geolocation(self, request, ip_address):
        """"
        Log the request with geolocation data.
        uses caching to avoid repeated API calls for the same IP.
        """
        if self._should_skip_logging(request):
            return
        
        if not ip_address:
            return

        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        country, city = self._get_cached_geolocation(ip_address)

        try:
            RequestLog.objects.create(
                ip_address=ip_address,
                path=request.path,
                method=request.method,
                user_agent=user_agent[:500],
                country=country,
                city=city
            )
            self._log_to_file(ip_address, f"{country}, {city}", request.path, 
                            request.method, user_agent, 'ALLOWED')
            
            logger.debug(f"Logged request from {ip_address} - {country}, {city}")
            
        except Exception as e:
            logger.error(f"Failed to log request: {e}")
            self._log_to_file(ip_address, "Error,Error", request.path, 
                            request.method, user_agent, 'DB_ERROR')

    def _get_cached_geolocation(self, ip_address):
        """
        Get geolocation data for an IP address with 24-hour caching.
        """
        if not ip_address or ip_address in ['127.0.0.1', 'localhost', '::1']:
            return 'Local', 'Local'
        
        # FIX: Correct method name
        if self._is_private_ip(ip_address):
            return 'Private', 'Private'
        
        cache_key = f"geolocation_{ip_address}"
        cached_data = cache.get(cache_key)

        if cached_data:
            logger.debug(f"Using cached geolocation for {ip_address}")
            logger.info(f"IP {ip_address}: USING CACHED DATA - Country: {cached_data.get('country')}, City: {cached_data.get('city')}")
            self.cache_stats['hits'] += 1  
            logger.info(f"CACHE HIT for {ip_address}. Stats: {self.cache_stats}")
            return cached_data.get('country', 'Unknown'), cached_data.get('city', 'Unknown')
        else:
            self.cache_stats['misses'] += 1  # Track cache miss
            logger.info(f"CACHE MISS for {ip_address}. Stats: {self.cache_stats}")

        country, city = self._fetch_geolocation_ipinfo(ip_address)

        cache.set(cache_key, {'country': country, 'city': city}, 86400)

        return country, city 
    
    def _is_private_ip(self, ip_address):
        """
        Check if the IP address is in a private range.
        """
        private_ranges = [
            '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'
        ]
        return any(ip_address.startswith(prefix) for prefix in private_ranges)
    
    def _fetch_geolocation_ipinfo(self, ip_address):
        """Fetch geolocation data using ipinfo.io API"""
        try:
            api_key = os.environ.get('IPINFO_API_KEY')
            if api_key:
                url = f"https://ipinfo.io/{ip_address}/json?token={api_key}"
            else:
                url = f"https://ipinfo.io/{ip_address}/json"
                
            response = requests.get(url, timeout=3)
            response.raise_for_status()
            data = response.json()

            country = data.get('country', 'Unknown')
            city = data.get('city', 'Unknown')

            country = self._get_country_name(country)

            logger.info(f"Fetched geolocation for {ip_address}: {country}, {city}")

            return country, city
        
        except requests.exceptions.Timeout:
            logger.warning(f"Geolocation API timeout for IP: {ip_address}")
            return 'Unknown', 'Unknown'
        except requests.exceptions.RequestException as e:
            logger.warning(f"Geolocation API error for IP {ip_address}: {e}")
            return 'Unknown', 'Unknown'
        except Exception as e:
            logger.error(f"Unexpected error fetching geolocation for {ip_address}: {e}")
            return 'Unknown', 'Unknown'

    def _get_country_name(self, country_code):
        """
        Convert country code to full country name.
        You can expand this dictionary as needed.
        """
        country_map = {
            'US': 'United States', 'GB': 'United Kingdom', 'CA': 'Canada',
            'AU': 'Australia', 'DE': 'Germany', 'FR': 'France', 'JP': 'Japan',
            'CN': 'China', 'IN': 'India', 'BR': 'Brazil', 'RU': 'Russia',
            'NG': 'Nigeria', 'ZA': 'South Africa', 'EG': 'Egypt', 'KE': 'Kenya',
        }
        return country_map.get(country_code, country_code)

    def _log_to_file(self, ip_address, location, path, method, user_agent, status):
        """
        Log request details to result.txt file
        """
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            user_agent_clean = user_agent.replace(',', ';').replace('\n', ' ').replace('\r', '')[:100]
            path_clean = path.replace(',', ';')
            
            log_entry = f"{timestamp:<10},{ip_address:<10},{location:<10},{path_clean:<10},{method:<10},{user_agent_clean:10},{status:<10}\n"
            
            with open(self.log_file_path, 'a') as f:
                f.write(log_entry)
                
            logger.debug(f"Logged to file: {ip_address} - {status}")
            
        except Exception as e:
            logger.error(f"Failed to write to log file: {e}")