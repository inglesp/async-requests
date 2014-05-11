from requests.cookies import *


def extract_cookies_to_jar(jar, request, response):
    req = MockRequest(request)
    res = MockResponse(response)
    jar.extract_cookies(res, req)
