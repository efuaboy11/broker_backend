from django.http import JsonResponse
from .models import BlacklistedIP

BOT_USER_AGENTS = [
    "Googlebot",
    "Bingbot",
    "DuckDuckBot",
    "YandexBot",
    "Baiduspider",
    "AhrefsBot",
    "SemrushBot",
    "MajesticBot",
    "Screaming Frog",
]

class BlockBotsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user_agent = request.META.get("HTTP_USER_AGENT", "")

        if any(bot in user_agent for bot in BOT_USER_AGENTS):
            return JsonResponse({"error": "Not Found"}, status=404)

        return self.get_response(request)
    

class BlockBlacklistedIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        ip = request.META.get('REMOTE_ADDR')
        
        if BlacklistedIP.objects.filter(ip_address=ip).exists():
            return JsonResponse({'error': 'Your IP is blackisted'})
        
        response = self.get_response(request)
        return response
    
    