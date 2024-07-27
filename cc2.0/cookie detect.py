import http.cookiejar
import urllib.request
import re

def analyze_cookies(url):
    # cookie jar to store cookies
    cookie_jar = http.cookiejar.CookieJar()

    #  an opener with the cookie jar
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))

    opener.open(url)

    # Analyze 
    for cookie in cookie_jar:
        print(f"Cookie Name: {cookie.name}")
        print(f"Value: {cookie.value}")
        print(f"Domain: {cookie.domain}")
        print(f"Path: {cookie.path}")
        print(f"Expires: {cookie.expires}")
        print(f"Secure: {cookie.secure}")
        print(f"HTTP Only: {cookie.has_nonstandard_attr('HttpOnly')}")
        
       
        is_tracking = is_tracking_cookie(cookie)
        print(f"Likely tracking cookie: {is_tracking}")
        
        
        stored_info = analyze_stored_info(cookie)
        print(f"Likely stored information: {stored_info}")
        
        print("---")

def is_tracking_cookie(cookie):
    tracking_keywords = ['track', 'analytic', 'stat', 'visitor', 'session']
    return any(keyword in cookie.name.lower() for keyword in tracking_keywords)

def analyze_stored_info(cookie):
    stored_info = []
    
    if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', cookie.value):
        stored_info.append("Email")
    
    if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', cookie.value):
        stored_info.append("IP Address")
    
    if len(cookie.value) == 32 or len(cookie.value) == 64:  #?
        stored_info.append("Session ID")
    
    if cookie.name.lower() in ['userid', 'user_id']:
        stored_info.append("User ID")
    
    return stored_info if stored_info else "Unable to determine"

# Usage
url = "https://example.com"  
analyze_cookies(url)