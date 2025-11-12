from django.core.management.base import BaseCommand, CommandError
from core.models import BlockedIP
import ipaddress

class Command(BaseCommand):
    help = 'Add IP addresses to the blocking blacklist'
    
    def add_arguments(self, parser):
        parser.add_argument(
            'ip_addresses',
            nargs='+',
            type=str,
            help='IP addresses to block (space separated)'
        )
        
        parser.add_argument(
            '--reason',
            type=str,
            help='Reason for blocking the IP address(es)'
        )
        
        parser.add_argument(
            '--deactivate',
            action='store_true',
            help='Deactivate instead of blocking (unblock)'
        )
    
    def handle(self, *args, **options):
        ip_addresses = options['ip_addresses']
        reason = options['reason']
        deactivate = options['deactivate']
        
        action = "deactivated" if deactivate else "blocked"
        
        for ip_str in ip_addresses:
            try:
                # Validate IP address
                ipaddress.ip_address(ip_str)
                
                if deactivate:
                    # Deactivate (unblock) the IP
                    blocked_ips = BlockedIP.objects.filter(ip_address=ip_str)
                    if blocked_ips.exists():
                        blocked_ips.update(is_active=False)
                        self.stdout.write(
                            self.style.SUCCESS(
                                f"Successfully deactivated IP: {ip_str}"
                            )
                        )
                    else:
                        self.stdout.write(
                            self.style.WARNING(
                                f"IP not found in blocklist: {ip_str}"
                            )
                        )
                else:
                    # Block the IP (create or update)
                    blocked_ip, created = BlockedIP.objects.update_or_create(
                        ip_address=ip_str,
                        defaults={
                            'reason': reason,
                            'is_active': True
                        }
                    )
                    
                    if created:
                        self.stdout.write(
                            self.style.SUCCESS(
                                f"Successfully blocked IP: {ip_str}"
                            )
                        )
                    else:
                        self.stdout.write(
                            self.style.SUCCESS(
                                f"IP {ip_str} was already blocked - updated"
                            )
                        )
                        
            except ValueError:
                self.stdout.write(
                    self.style.ERROR(
                        f"Invalid IP address: {ip_str}"
                    )
                )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(
                        f"Error processing IP {ip_str}: {str(e)}"
                    )
                )