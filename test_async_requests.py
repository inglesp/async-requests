
'Tests for Requests.'
from __future__ import division
import asyncio
import json
import os
import pickle
import unittest
import async_requests
import pytest
from async_requests.adapters import AsyncHTTPAdapter
from async_requests.auth import HTTPDigestAuth
from async_requests.compat import Morsel, cookielib, getproxies, str, urljoin, urlparse
from async_requests.cookies import cookiejar_from_dict, morsel_to_cookie
from async_requests.exceptions import InvalidURL, MissingSchema
from async_requests.structures import CaseInsensitiveDict
try:
    import StringIO
except ImportError:
    import io as StringIO
HTTPBIN = os.environ.get('HTTPBIN_URL', 'http://httpbin.org/')
HTTPBIN = (HTTPBIN.rstrip('/') + '/')

def httpbin(*suffix):
    'Returns url for HTTPBIN resource.'
    return urljoin(HTTPBIN, '/'.join(suffix))

class RequestsTestCase(unittest.TestCase):
    _multiprocess_can_split_ = True

    def setUp(self):
        'Create simple data set with headers.'
        pass

    def tearDown(self):
        'Teardown.'
        pass

    def test_entry_points(self):
        async_requests.session
        async_requests.session().get
        async_requests.session().head
        async_requests.get
        async_requests.head
        async_requests.put
        async_requests.patch
        async_requests.post

    def test_invalid_url(self):
        with pytest.raises(MissingSchema):
            task = asyncio.Task(async_requests.get('hiwpefhipowhefopw'))
            loop = asyncio.get_event_loop()
            loop.run_until_complete(task)
        with pytest.raises(InvalidURL):
            task = asyncio.Task(async_requests.get('http://'))
            loop = asyncio.get_event_loop()
            loop.run_until_complete(task)

    def test_basic_building(self):
        req = async_requests.Request()
        req.url = 'http://kennethreitz.org/'
        req.data = {'life': '42'}
        pr = req.prepare()
        assert (pr.url == req.url)
        assert (pr.body == 'life=42')

    def test_no_content_length(self):
        get_req = async_requests.Request('GET', httpbin('get')).prepare()
        assert ('Content-Length' not in get_req.headers)
        head_req = async_requests.Request('HEAD', httpbin('head')).prepare()
        assert ('Content-Length' not in head_req.headers)

    def test_path_is_not_double_encoded(self):
        request = async_requests.Request('GET', 'http://0.0.0.0/get/test case').prepare()
        assert (request.path_url == '/get/test%20case')

    def test_params_are_added_before_fragment(self):
        request = async_requests.Request('GET', 'http://example.com/path#fragment', params={'a': 'b'}).prepare()
        assert (request.url == 'http://example.com/path?a=b#fragment')
        request = async_requests.Request('GET', 'http://example.com/path?key=value#fragment', params={'a': 'b'}).prepare()
        assert (request.url == 'http://example.com/path?key=value&a=b#fragment')

    def test_mixed_case_scheme_acceptable(self):
        s = async_requests.AsyncSession()
        s.proxies = getproxies()
        parts = urlparse(httpbin('get'))
        schemes = ['http://', 'HTTP://', 'hTTp://', 'HttP://', 'https://', 'HTTPS://', 'hTTps://', 'HttPs://']
        for scheme in schemes:
            url = ((scheme + parts.netloc) + parts.path)
            r = async_requests.Request('GET', url)
            task = asyncio.Task(s.send(r.prepare()))
            loop = asyncio.get_event_loop()
            r = loop.run_until_complete(task)
            assert (r.status_code == 200), 'failed for scheme {0}'.format(scheme)

    def test_HTTP_200_OK_GET_ALTERNATIVE(self):
        r = async_requests.Request('GET', httpbin('get'))
        s = async_requests.AsyncSession()
        s.proxies = getproxies()
        task = asyncio.Task(s.send(r.prepare()))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)

    def test_HTTP_302_ALLOW_REDIRECT_GET(self):
        task = asyncio.Task(async_requests.get(httpbin('redirect', '1')))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)

    def test_HTTP_200_OK_GET_WITH_PARAMS(self):
        heads = {'User-agent': 'Mozilla/5.0'}
        task = asyncio.Task(async_requests.get(httpbin('user-agent'), headers=heads))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (heads['User-agent'] in r.text)
        assert (r.status_code == 200)

    def test_HTTP_200_OK_GET_WITH_MIXED_PARAMS(self):
        heads = {'User-agent': 'Mozilla/5.0'}
        task = asyncio.Task(async_requests.get((httpbin('get') + '?test=true'), params={'q': 'test'}, headers=heads))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)

    def test_set_cookie_on_301(self):
        s = async_requests.session()
        url = httpbin('cookies/set?foo=bar')
        task = asyncio.Task(s.get(url))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (s.cookies['foo'] == 'bar')

    def test_cookie_sent_on_redirect(self):
        s = async_requests.session()
        task = asyncio.Task(s.get(httpbin('cookies/set?foo=bar')))
        loop = asyncio.get_event_loop()
        loop.run_until_complete(task)
        task = asyncio.Task(s.get(httpbin('redirect/1')))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert ('Cookie' in r.json()['headers'])

    def test_cookie_removed_on_expire(self):
        s = async_requests.session()
        task = asyncio.Task(s.get(httpbin('cookies/set?foo=bar')))
        loop = asyncio.get_event_loop()
        loop.run_until_complete(task)
        assert (s.cookies['foo'] == 'bar')
        task = asyncio.Task(s.get(httpbin('response-headers'), params={'Set-Cookie': 'foo=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT'}))
        loop = asyncio.get_event_loop()
        loop.run_until_complete(task)
        assert ('foo' not in s.cookies)

    def test_cookie_quote_wrapped(self):
        s = async_requests.session()
        task = asyncio.Task(s.get(httpbin('cookies/set?foo="bar:baz"')))
        loop = asyncio.get_event_loop()
        loop.run_until_complete(task)
        assert (s.cookies['foo'] == '"bar:baz"')

    def test_cookie_persists_via_api(self):
        s = async_requests.session()
        task = asyncio.Task(s.get(httpbin('redirect/1'), cookies={'foo': 'bar'}))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert ('foo' in r.request.headers['Cookie'])
        assert ('foo' in r.history[0].request.headers['Cookie'])

    def test_request_cookie_overrides_session_cookie(self):
        s = async_requests.session()
        s.cookies['foo'] = 'bar'
        task = asyncio.Task(s.get(httpbin('cookies'), cookies={'foo': 'baz'}))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.json()['cookies']['foo'] == 'baz')
        assert (s.cookies['foo'] == 'bar')

    def test_request_cookies_not_persisted(self):
        s = async_requests.session()
        task = asyncio.Task(s.get(httpbin('cookies'), cookies={'foo': 'baz'}))
        loop = asyncio.get_event_loop()
        loop.run_until_complete(task)
        assert (not s.cookies)

    def test_generic_cookiejar_works(self):
        cj = cookielib.CookieJar()
        cookiejar_from_dict({'foo': 'bar'}, cj)
        s = async_requests.session()
        s.cookies = cj
        task = asyncio.Task(s.get(httpbin('cookies')))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.json()['cookies']['foo'] == 'bar')
        assert (s.cookies is cj)

    def test_param_cookiejar_works(self):
        cj = cookielib.CookieJar()
        cookiejar_from_dict({'foo': 'bar'}, cj)
        s = async_requests.session()
        task = asyncio.Task(s.get(httpbin('cookies'), cookies=cj))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.json()['cookies']['foo'] == 'bar')

    def test_requests_in_history_are_not_overridden(self):
        task = asyncio.Task(async_requests.get(httpbin('redirect/3')))
        loop = asyncio.get_event_loop()
        resp = loop.run_until_complete(task)
        urls = [r.url for r in resp.history]
        req_urls = [r.request.url for r in resp.history]
        assert (urls == req_urls)

    def test_user_agent_transfers(self):
        heads = {'User-agent': 'Mozilla/5.0 (github.com/kennethreitz/requests)'}
        task = asyncio.Task(async_requests.get(httpbin('user-agent'), headers=heads))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (heads['User-agent'] in r.text)
        heads = {'user-agent': 'Mozilla/5.0 (github.com/kennethreitz/requests)'}
        task = asyncio.Task(async_requests.get(httpbin('user-agent'), headers=heads))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (heads['user-agent'] in r.text)

    def test_HTTP_200_OK_HEAD(self):
        task = asyncio.Task(async_requests.head(httpbin('get')))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)

    def test_HTTP_200_OK_PUT(self):
        task = asyncio.Task(async_requests.put(httpbin('put')))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)

    def test_BASICAUTH_TUPLE_HTTP_200_OK_GET(self):
        auth = ('user', 'pass')
        url = httpbin('basic-auth', 'user', 'pass')
        task = asyncio.Task(async_requests.get(url, auth=auth))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)
        task = asyncio.Task(async_requests.get(url))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 401)
        s = async_requests.session()
        s.auth = auth
        task = asyncio.Task(s.get(url))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)

    def test_basicauth_with_netrc(self):
        auth = ('user', 'pass')
        wrong_auth = ('wronguser', 'wrongpass')
        url = httpbin('basic-auth', 'user', 'pass')

        def get_netrc_auth_mock(url):
            return auth

        import requests
        requests.sessions.get_netrc_auth = get_netrc_auth_mock

        task = asyncio.Task(async_requests.get(url))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)
        task = asyncio.Task(async_requests.get(url, auth=wrong_auth))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 401)
        s = async_requests.session()
        task = asyncio.Task(s.get(url))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)
        s.auth = wrong_auth
        task = asyncio.Task(s.get(url))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 401)

    def test_DIGEST_HTTP_200_OK_GET(self):
        auth = HTTPDigestAuth('user', 'pass')
        url = httpbin('digest-auth', 'auth', 'user', 'pass')
        task = asyncio.Task(async_requests.get(url, auth=auth))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)
        task = asyncio.Task(async_requests.get(url))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 401)
        s = async_requests.session()
        s.auth = HTTPDigestAuth('user', 'pass')
        task = asyncio.Task(s.get(url))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)

    def test_DIGEST_AUTH_RETURNS_COOKIE(self):
        url = httpbin('digest-auth', 'auth', 'user', 'pass')
        auth = HTTPDigestAuth('user', 'pass')
        task = asyncio.Task(async_requests.get(url))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.cookies['fake'] == 'fake_value')
        task = asyncio.Task(async_requests.get(url, auth=auth))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)

    def test_DIGEST_AUTH_SETS_SESSION_COOKIES(self):
        url = httpbin('digest-auth', 'auth', 'user', 'pass')
        auth = HTTPDigestAuth('user', 'pass')
        s = async_requests.AsyncSession()
        task = asyncio.Task(s.get(url, auth=auth))
        loop = asyncio.get_event_loop()
        loop.run_until_complete(task)
        assert (s.cookies['fake'] == 'fake_value')

    def test_DIGEST_STREAM(self):
        auth = HTTPDigestAuth('user', 'pass')
        url = httpbin('digest-auth', 'auth', 'user', 'pass')
        task = asyncio.Task(async_requests.get(url, auth=auth, stream=True))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.raw.read() != b'')
        task = asyncio.Task(async_requests.get(url, auth=auth, stream=False))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.raw.read() == b'')

    def test_DIGESTAUTH_WRONG_HTTP_401_GET(self):
        auth = HTTPDigestAuth('user', 'wrongpass')
        url = httpbin('digest-auth', 'auth', 'user', 'pass')
        task = asyncio.Task(async_requests.get(url, auth=auth))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 401)
        task = asyncio.Task(async_requests.get(url))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 401)
        s = async_requests.session()
        s.auth = auth
        task = asyncio.Task(s.get(url))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 401)

    def test_DIGESTAUTH_QUOTES_QOP_VALUE(self):
        auth = HTTPDigestAuth('user', 'pass')
        url = httpbin('digest-auth', 'auth', 'user', 'pass')
        task = asyncio.Task(async_requests.get(url, auth=auth))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert ('"auth"' in r.request.headers['Authorization'])

    def test_POSTBIN_GET_POST_FILES(self):
        url = httpbin('post')
        task = asyncio.Task(async_requests.post(url))
        loop = asyncio.get_event_loop()
        post1 = loop.run_until_complete(task)
        post1.raise_for_status()
        task = asyncio.Task(async_requests.post(url, data={'some': 'data'}))
        loop = asyncio.get_event_loop()
        post1 = loop.run_until_complete(task)
        assert (post1.status_code == 200)
        with open('requirements.txt') as f:
            task = asyncio.Task(async_requests.post(url, files={'some': f}))
            loop = asyncio.get_event_loop()
            post2 = loop.run_until_complete(task)
        assert (post2.status_code == 200)
        task = asyncio.Task(async_requests.post(url, data='[{"some": "json"}]'))
        loop = asyncio.get_event_loop()
        post4 = loop.run_until_complete(task)
        assert (post4.status_code == 200)
        with pytest.raises(ValueError):
            task = asyncio.Task(async_requests.post(url, files=['bad file data']))
            loop = asyncio.get_event_loop()
            loop.run_until_complete(task)

    def test_POSTBIN_GET_POST_FILES_WITH_DATA(self):
        url = httpbin('post')
        task = asyncio.Task(async_requests.post(url))
        loop = asyncio.get_event_loop()
        post1 = loop.run_until_complete(task)
        post1.raise_for_status()
        task = asyncio.Task(async_requests.post(url, data={'some': 'data'}))
        loop = asyncio.get_event_loop()
        post1 = loop.run_until_complete(task)
        assert (post1.status_code == 200)
        with open('requirements.txt') as f:
            task = asyncio.Task(async_requests.post(url, data={'some': 'data'}, files={'some': f}))
            loop = asyncio.get_event_loop()
            post2 = loop.run_until_complete(task)
        assert (post2.status_code == 200)
        task = asyncio.Task(async_requests.post(url, data='[{"some": "json"}]'))
        loop = asyncio.get_event_loop()
        post4 = loop.run_until_complete(task)
        assert (post4.status_code == 200)
        with pytest.raises(ValueError):
            task = asyncio.Task(async_requests.post(url, files=['bad file data']))
            loop = asyncio.get_event_loop()
            loop.run_until_complete(task)

    def test_conflicting_post_params(self):
        url = httpbin('post')
        with open('requirements.txt') as f:
            with pytest.raises(ValueError):
                task = asyncio.Task(async_requests.post(url, data='[{"some": "data"}]', files={'some': f}))
                loop = asyncio.get_event_loop()
                loop.run_until_complete(task)
            with pytest.raises(ValueError):
                task = asyncio.Task(async_requests.post(url, data='[{"some": "data"}]', files={'some': f}))
                loop = asyncio.get_event_loop()
                loop.run_until_complete(task)

    def test_request_ok_set(self):
        task = asyncio.Task(async_requests.get(httpbin('status', '404')))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (not r.ok)

    def test_status_raising(self):
        task = asyncio.Task(async_requests.get(httpbin('status', '404')))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        with pytest.raises(async_requests.exceptions.HTTPError):
            r.raise_for_status()
        task = asyncio.Task(async_requests.get(httpbin('status', '500')))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (not r.ok)

    def test_decompress_gzip(self):
        task = asyncio.Task(async_requests.get(httpbin('gzip')))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        r.content.decode('ascii')

    def test_unicode_get(self):
        url = httpbin('/get')
        task = asyncio.Task(async_requests.get(url, params={'foo': 'føø'}))
        loop = asyncio.get_event_loop()
        loop.run_until_complete(task)
        task = asyncio.Task(async_requests.get(url, params={'føø': 'føø'}))
        loop = asyncio.get_event_loop()
        loop.run_until_complete(task)
        task = asyncio.Task(async_requests.get(url, params={'føø': 'føø'}))
        loop = asyncio.get_event_loop()
        loop.run_until_complete(task)
        task = asyncio.Task(async_requests.get(url, params={'foo': 'foo'}))
        loop = asyncio.get_event_loop()
        loop.run_until_complete(task)
        task = asyncio.Task(async_requests.get(httpbin('ø'), params={'foo': 'foo'}))
        loop = asyncio.get_event_loop()
        loop.run_until_complete(task)

    def test_unicode_header_name(self):
        task = asyncio.Task(async_requests.put(httpbin('put'), headers={str('Content-Type'): 'application/octet-stream'}, data='ÿ'))
        loop = asyncio.get_event_loop()
        loop.run_until_complete(task)

    def test_urlencoded_get_query_multivalued_param(self):
        task = asyncio.Task(async_requests.get(httpbin('get'), params=dict(test=['foo', 'baz'])))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)
        assert (r.url == httpbin('get?test=foo&test=baz'))

    def test_different_encodings_dont_break_post(self):
        task = asyncio.Task(async_requests.post(httpbin('post'), data={'stuff': json.dumps({'a': 123})}, params={'blah': 'asdf1234'}, files={'file': ('test_requests.py', open(__file__, 'rb'))}))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)

    def test_unicode_multipart_post(self):
        task = asyncio.Task(async_requests.post(httpbin('post'), data={'stuff': 'ëlïxr'}, files={'file': ('test_requests.py', open(__file__, 'rb'))}))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)
        task = asyncio.Task(async_requests.post(httpbin('post'), data={'stuff': 'ëlïxr'.encode('utf-8')}, files={'file': ('test_requests.py', open(__file__, 'rb'))}))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)
        task = asyncio.Task(async_requests.post(httpbin('post'), data={'stuff': 'elixr'}, files={'file': ('test_requests.py', open(__file__, 'rb'))}))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)
        task = asyncio.Task(async_requests.post(httpbin('post'), data={'stuff': 'elixr'.encode('utf-8')}, files={'file': ('test_requests.py', open(__file__, 'rb'))}))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)

    def test_unicode_multipart_post_fieldnames(self):
        filename = (os.path.splitext(__file__)[0] + '.py')
        r = async_requests.Request(method='POST', url=httpbin('post'), data={'stuff'.encode('utf-8'): 'elixr'}, files={'file': ('test_requests.py', open(filename, 'rb'))})
        prep = r.prepare()
        assert (b'name="stuff"' in prep.body)
        assert (b'name="b\'stuff\'"' not in prep.body)

    def test_unicode_method_name(self):
        files = {'file': open('test_requests.py', 'rb')}
        task = asyncio.Task(async_requests.request(method='POST', url=httpbin('post'), files=files))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)

    def test_custom_content_type(self):
        task = asyncio.Task(async_requests.post(httpbin('post'), data={'stuff': json.dumps({'a': 123})}, files={'file1': ('test_requests.py', open(__file__, 'rb')), 'file2': ('test_requests', open(__file__, 'rb'), 'text/py-content-type')}))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)
        assert (b'text/py-content-type' in r.request.body)

    def test_hook_receives_request_arguments(self):

        def hook(resp, **kwargs):
            assert (resp is not None)
            assert (kwargs != {})
        async_requests.Request('GET', HTTPBIN, hooks={'response': hook})

    def test_session_hooks_are_used_with_no_request_hooks(self):
        hook = (lambda x, *args, **kwargs: x)
        s = async_requests.AsyncSession()
        s.hooks['response'].append(hook)
        r = async_requests.Request('GET', HTTPBIN)
        prep = s.prepare_request(r)
        assert (prep.hooks['response'] != [])
        assert (prep.hooks['response'] == [hook])

    def test_session_hooks_are_overriden_by_request_hooks(self):
        hook1 = (lambda x, *args, **kwargs: x)
        hook2 = (lambda x, *args, **kwargs: x)
        assert (hook1 is not hook2)
        s = async_requests.AsyncSession()
        s.hooks['response'].append(hook2)
        r = async_requests.Request('GET', HTTPBIN, hooks={'response': [hook1]})
        prep = s.prepare_request(r)
        assert (prep.hooks['response'] == [hook1])

    def test_prepared_request_hook(self):

        def hook(resp, **kwargs):
            resp.hook_working = True
            return resp
        req = async_requests.Request('GET', HTTPBIN, hooks={'response': hook})
        prep = req.prepare()
        s = async_requests.AsyncSession()
        s.proxies = getproxies()
        task = asyncio.Task(s.send(prep))
        loop = asyncio.get_event_loop()
        resp = loop.run_until_complete(task)
        assert hasattr(resp, 'hook_working')

    def test_prepared_from_session(self):

        class DummyAuth(async_requests.auth.AuthBase):

            def __call__(self, r):
                r.headers['Dummy-Auth-Test'] = 'dummy-auth-test-ok'
                return r
        req = async_requests.Request('GET', httpbin('headers'))
        assert (not req.auth)
        s = async_requests.AsyncSession()
        s.auth = DummyAuth()
        prep = s.prepare_request(req)
        task = asyncio.Task(s.send(prep))
        loop = asyncio.get_event_loop()
        resp = loop.run_until_complete(task)
        assert (resp.json()['headers']['Dummy-Auth-Test'] == 'dummy-auth-test-ok')

    def test_links(self):
        r = async_requests.AsyncResponse()
        r.headers = {'cache-control': 'public, max-age=60, s-maxage=60', 'connection': 'keep-alive', 'content-encoding': 'gzip', 'content-type': 'application/json; charset=utf-8', 'date': 'Sat, 26 Jan 2013 16:47:56 GMT', 'etag': '"6ff6a73c0e446c1f61614769e3ceb778"', 'last-modified': 'Sat, 26 Jan 2013 16:22:39 GMT', 'link': '<https://api.github.com/users/kennethreitz/repos?page=2&per_page=10>; rel="next", <https://api.github.com/users/kennethreitz/repos?page=7&per_page=10>;  rel="last"', 'server': 'GitHub.com', 'status': '200 OK', 'vary': 'Accept', 'x-content-type-options': 'nosniff', 'x-github-media-type': 'github.beta', 'x-ratelimit-limit': '60', 'x-ratelimit-remaining': '57'}
        assert (r.links['next']['rel'] == 'next')

    def test_cookie_parameters(self):
        key = 'some_cookie'
        value = 'some_value'
        secure = True
        domain = 'test.com'
        rest = {'HttpOnly': True}
        jar = async_requests.cookies.RequestsCookieJar()
        jar.set(key, value, secure=secure, domain=domain, rest=rest)
        assert (len(jar) == 1)
        assert ('some_cookie' in jar)
        cookie = list(jar)[0]
        assert (cookie.secure == secure)
        assert (cookie.domain == domain)
        assert (cookie._rest['HttpOnly'] == rest['HttpOnly'])

    def test_cookie_as_dict_keeps_len(self):
        key = 'some_cookie'
        value = 'some_value'
        key1 = 'some_cookie1'
        value1 = 'some_value1'
        jar = async_requests.cookies.RequestsCookieJar()
        jar.set(key, value)
        jar.set(key1, value1)
        d1 = dict(jar)
        d2 = dict(jar.iteritems())
        d3 = dict(jar.items())
        assert (len(jar) == 2)
        assert (len(d1) == 2)
        assert (len(d2) == 2)
        assert (len(d3) == 2)

    def test_cookie_as_dict_keeps_items(self):
        key = 'some_cookie'
        value = 'some_value'
        key1 = 'some_cookie1'
        value1 = 'some_value1'
        jar = async_requests.cookies.RequestsCookieJar()
        jar.set(key, value)
        jar.set(key1, value1)
        d1 = dict(jar)
        d2 = dict(jar.iteritems())
        d3 = dict(jar.items())
        assert (d1['some_cookie'] == 'some_value')
        assert (d2['some_cookie'] == 'some_value')
        assert (d3['some_cookie1'] == 'some_value1')

    def test_cookie_as_dict_keys(self):
        key = 'some_cookie'
        value = 'some_value'
        key1 = 'some_cookie1'
        value1 = 'some_value1'
        jar = async_requests.cookies.RequestsCookieJar()
        jar.set(key, value)
        jar.set(key1, value1)
        keys = jar.keys()
        assert (keys == list(keys))
        assert (list(keys) == list(keys))

    def test_cookie_as_dict_values(self):
        key = 'some_cookie'
        value = 'some_value'
        key1 = 'some_cookie1'
        value1 = 'some_value1'
        jar = async_requests.cookies.RequestsCookieJar()
        jar.set(key, value)
        jar.set(key1, value1)
        values = jar.values()
        assert (values == list(values))
        assert (list(values) == list(values))

    def test_cookie_as_dict_items(self):
        key = 'some_cookie'
        value = 'some_value'
        key1 = 'some_cookie1'
        value1 = 'some_value1'
        jar = async_requests.cookies.RequestsCookieJar()
        jar.set(key, value)
        jar.set(key1, value1)
        items = jar.items()
        assert (items == list(items))
        assert (list(items) == list(items))

    def test_time_elapsed_blank(self):
        task = asyncio.Task(async_requests.get(httpbin('get')))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        td = r.elapsed
        total_seconds = ((td.microseconds + ((td.seconds + ((td.days * 24) * 3600)) * (10 ** 6))) / (10 ** 6))
        assert (total_seconds > 0.0)

    def test_response_is_iterable(self):
        r = async_requests.AsyncResponse()
        io = StringIO.StringIO('abc')
        read_ = io.read

        def read_mock(amt, decode_content=None):
            return read_(amt)
        setattr(io, 'read', read_mock)
        r.raw = io
        assert next(iter(r))
        io.close()

    def test_request_and_response_are_pickleable(self):
        task = asyncio.Task(async_requests.get(httpbin('get')))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert pickle.loads(pickle.dumps(r.request))
        pr = pickle.loads(pickle.dumps(r))
        assert (r.request.url == pr.request.url)
        assert (r.request.headers == pr.request.headers)

    def test_get_auth_from_url(self):
        url = 'http://user:pass@complex.url.com/path?query=yes'
        assert (('user', 'pass') == async_requests.utils.get_auth_from_url(url))

    def test_get_auth_from_url_encoded_spaces(self):
        url = 'http://user:pass%20pass@complex.url.com/path?query=yes'
        assert (('user', 'pass pass') == async_requests.utils.get_auth_from_url(url))

    def test_get_auth_from_url_not_encoded_spaces(self):
        url = 'http://user:pass pass@complex.url.com/path?query=yes'
        assert (('user', 'pass pass') == async_requests.utils.get_auth_from_url(url))

    def test_get_auth_from_url_percent_chars(self):
        url = 'http://user%25user:pass@complex.url.com/path?query=yes'
        assert (('user%user', 'pass') == async_requests.utils.get_auth_from_url(url))

    def test_get_auth_from_url_encoded_hashes(self):
        url = 'http://user:pass%23pass@complex.url.com/path?query=yes'
        assert (('user', 'pass#pass') == async_requests.utils.get_auth_from_url(url))

    def test_cannot_send_unprepared_requests(self):
        r = async_requests.Request(url=HTTPBIN)
        with pytest.raises(ValueError):
            task = asyncio.Task(async_requests.AsyncSession().send(r))
            loop = asyncio.get_event_loop()
            loop.run_until_complete(task)

    def test_http_error(self):
        error = async_requests.exceptions.HTTPError()
        assert (not error.response)
        response = async_requests.AsyncResponse()
        error = async_requests.exceptions.HTTPError(response=response)
        assert (error.response == response)
        error = async_requests.exceptions.HTTPError('message', response=response)
        assert (str(error) == 'message')
        assert (error.response == response)

    def test_session_pickling(self):
        r = async_requests.Request('GET', httpbin('get'))
        s = async_requests.AsyncSession()
        s = pickle.loads(pickle.dumps(s))
        s.proxies = getproxies()
        task = asyncio.Task(s.send(r.prepare()))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)

    def test_fixes_1329(self):
        '\n        Ensure that header updates are done case-insensitively.\n        '
        s = async_requests.AsyncSession()
        s.headers.update({'ACCEPT': 'BOGUS'})
        s.headers.update({'accept': 'application/json'})
        task = asyncio.Task(s.get(httpbin('get')))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        headers = r.request.headers
        assert (headers['accept'] == 'application/json')
        assert (headers['Accept'] == 'application/json')
        assert (headers['ACCEPT'] == 'application/json')

    def test_uppercase_scheme_redirect(self):
        parts = urlparse(httpbin('html'))
        url = (('HTTP://' + parts.netloc) + parts.path)
        task = asyncio.Task(async_requests.get(httpbin('redirect-to'), params={'url': url}))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.status_code == 200)
        assert (r.url.lower() == url.lower())

    def test_transport_adapter_ordering(self):
        s = async_requests.AsyncSession()
        order = ['https://', 'http://']
        assert (order == list(s.adapters))
        s.mount('http://git', AsyncHTTPAdapter())
        s.mount('http://github', AsyncHTTPAdapter())
        s.mount('http://github.com', AsyncHTTPAdapter())
        s.mount('http://github.com/about/', AsyncHTTPAdapter())
        order = ['http://github.com/about/', 'http://github.com', 'http://github', 'http://git', 'https://', 'http://']
        assert (order == list(s.adapters))
        s.mount('http://gittip', AsyncHTTPAdapter())
        s.mount('http://gittip.com', AsyncHTTPAdapter())
        s.mount('http://gittip.com/about/', AsyncHTTPAdapter())
        order = ['http://github.com/about/', 'http://gittip.com/about/', 'http://github.com', 'http://gittip.com', 'http://github', 'http://gittip', 'http://git', 'https://', 'http://']
        assert (order == list(s.adapters))
        s2 = async_requests.AsyncSession()
        s2.adapters = {'http://': AsyncHTTPAdapter()}
        s2.mount('https://', AsyncHTTPAdapter())
        assert ('http://' in s2.adapters)
        assert ('https://' in s2.adapters)

    def test_header_remove_is_case_insensitive(self):
        s = async_requests.AsyncSession()
        s.headers['foo'] = 'bar'
        task = asyncio.Task(s.get(httpbin('get'), headers={'FOO': None}))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert ('foo' not in r.request.headers)

    def test_params_are_merged_case_sensitive(self):
        s = async_requests.AsyncSession()
        s.params['foo'] = 'bar'
        task = asyncio.Task(s.get(httpbin('get'), params={'FOO': 'bar'}))
        loop = asyncio.get_event_loop()
        r = loop.run_until_complete(task)
        assert (r.json()['args'] == {'foo': 'bar', 'FOO': 'bar'})

    def test_long_authinfo_in_url(self):
        url = 'http://{0}:{1}@{2}:9000/path?query#frag'.format('E8A3BE87-9E3F-4620-8858-95478E385B5B', 'EA770032-DA4D-4D84-8CE9-29C6D910BF1E', 'exactly-------------sixty-----------three------------characters')
        r = async_requests.Request('GET', url).prepare()
        assert (r.url == url)

    def test_header_keys_are_native(self):
        headers = {'unicode': 'blah', 'byte'.encode('ascii'): 'blah'}
        r = async_requests.Request('GET', httpbin('get'), headers=headers)
        p = r.prepare()
        assert ('unicode' in p.headers.keys())
        assert ('byte' in p.headers.keys())

    def test_can_send_nonstring_objects_with_files(self):
        data = {'a': 0.0}
        files = {'b': 'foo'}
        r = async_requests.Request('POST', httpbin('post'), data=data, files=files)
        p = r.prepare()
        assert ('multipart/form-data' in p.headers['Content-Type'])

    def test_autoset_header_values_are_native(self):
        data = 'this is a string'
        length = '16'
        req = async_requests.Request('POST', httpbin('post'), data=data)
        p = req.prepare()
        assert (p.headers['Content-Length'] == length)

    def test_oddball_schemes_dont_check_URLs(self):
        test_urls = ('data:image/gif;base64,R0lGODlhAQABAHAAACH5BAUAAAAALAAAAAABAAEAAAICRAEAOw==', 'file:///etc/passwd', 'magnet:?xt=urn:btih:be08f00302bc2d1d3cfa3af02024fa647a271431')
        for test_url in test_urls:
            req = async_requests.Request('GET', test_url)
            preq = req.prepare()
            assert (test_url == preq.url)

class TestContentEncodingDetection(unittest.TestCase):

    def test_none(self):
        encodings = async_requests.utils.get_encodings_from_content('')
        assert (not len(encodings))

    def test_html_charset(self):
        'HTML5 meta charset attribute'
        content = '<meta charset="UTF-8">'
        encodings = async_requests.utils.get_encodings_from_content(content)
        assert (len(encodings) == 1)
        assert (encodings[0] == 'UTF-8')

    def test_html4_pragma(self):
        'HTML4 pragma directive'
        content = '<meta http-equiv="Content-type" content="text/html;charset=UTF-8">'
        encodings = async_requests.utils.get_encodings_from_content(content)
        assert (len(encodings) == 1)
        assert (encodings[0] == 'UTF-8')

    def test_xhtml_pragma(self):
        'XHTML 1.x served with text/html MIME type'
        content = '<meta http-equiv="Content-type" content="text/html;charset=UTF-8" />'
        encodings = async_requests.utils.get_encodings_from_content(content)
        assert (len(encodings) == 1)
        assert (encodings[0] == 'UTF-8')

    def test_xml(self):
        'XHTML 1.x served as XML'
        content = '<?xml version="1.0" encoding="UTF-8"?>'
        encodings = async_requests.utils.get_encodings_from_content(content)
        assert (len(encodings) == 1)
        assert (encodings[0] == 'UTF-8')

    def test_precedence(self):
        content = '\n        <?xml version="1.0" encoding="XML"?>\n        <meta charset="HTML5">\n        <meta http-equiv="Content-type" content="text/html;charset=HTML4" />\n        '.strip()
        encodings = async_requests.utils.get_encodings_from_content(content)
        assert (encodings == ['HTML5', 'HTML4', 'XML'])

class TestCaseInsensitiveDict(unittest.TestCase):

    def test_mapping_init(self):
        cid = CaseInsensitiveDict({'Foo': 'foo', 'BAr': 'bar'})
        assert (len(cid) == 2)
        assert ('foo' in cid)
        assert ('bar' in cid)

    def test_iterable_init(self):
        cid = CaseInsensitiveDict([('Foo', 'foo'), ('BAr', 'bar')])
        assert (len(cid) == 2)
        assert ('foo' in cid)
        assert ('bar' in cid)

    def test_kwargs_init(self):
        cid = CaseInsensitiveDict(FOO='foo', BAr='bar')
        assert (len(cid) == 2)
        assert ('foo' in cid)
        assert ('bar' in cid)

    def test_docstring_example(self):
        cid = CaseInsensitiveDict()
        cid['Accept'] = 'application/json'
        assert (cid['aCCEPT'] == 'application/json')
        assert (list(cid) == ['Accept'])

    def test_len(self):
        cid = CaseInsensitiveDict({'a': 'a', 'b': 'b'})
        cid['A'] = 'a'
        assert (len(cid) == 2)

    def test_getitem(self):
        cid = CaseInsensitiveDict({'Spam': 'blueval'})
        assert (cid['spam'] == 'blueval')
        assert (cid['SPAM'] == 'blueval')

    def test_fixes_649(self):
        '__setitem__ should behave case-insensitively.'
        cid = CaseInsensitiveDict()
        cid['spam'] = 'oneval'
        cid['Spam'] = 'twoval'
        cid['sPAM'] = 'redval'
        cid['SPAM'] = 'blueval'
        assert (cid['spam'] == 'blueval')
        assert (cid['SPAM'] == 'blueval')
        assert (list(cid.keys()) == ['SPAM'])

    def test_delitem(self):
        cid = CaseInsensitiveDict()
        cid['Spam'] = 'someval'
        del cid['sPam']
        assert ('spam' not in cid)
        assert (len(cid) == 0)

    def test_contains(self):
        cid = CaseInsensitiveDict()
        cid['Spam'] = 'someval'
        assert ('Spam' in cid)
        assert ('spam' in cid)
        assert ('SPAM' in cid)
        assert ('sPam' in cid)
        assert ('notspam' not in cid)

    def test_get(self):
        cid = CaseInsensitiveDict()
        cid['spam'] = 'oneval'
        cid['SPAM'] = 'blueval'
        assert (cid.get('spam') == 'blueval')
        assert (cid.get('SPAM') == 'blueval')
        assert (cid.get('sPam') == 'blueval')
        assert (cid.get('notspam', 'default') == 'default')

    def test_update(self):
        cid = CaseInsensitiveDict()
        cid['spam'] = 'blueval'
        cid.update({'sPam': 'notblueval'})
        assert (cid['spam'] == 'notblueval')
        cid = CaseInsensitiveDict({'Foo': 'foo', 'BAr': 'bar'})
        cid.update({'fOO': 'anotherfoo', 'bAR': 'anotherbar'})
        assert (len(cid) == 2)
        assert (cid['foo'] == 'anotherfoo')
        assert (cid['bar'] == 'anotherbar')

    def test_update_retains_unchanged(self):
        cid = CaseInsensitiveDict({'foo': 'foo', 'bar': 'bar'})
        cid.update({'foo': 'newfoo'})
        assert (cid['bar'] == 'bar')

    def test_iter(self):
        cid = CaseInsensitiveDict({'Spam': 'spam', 'Eggs': 'eggs'})
        keys = frozenset(['Spam', 'Eggs'])
        assert (frozenset(iter(cid)) == keys)

    def test_equality(self):
        cid = CaseInsensitiveDict({'SPAM': 'blueval', 'Eggs': 'redval'})
        othercid = CaseInsensitiveDict({'spam': 'blueval', 'eggs': 'redval'})
        assert (cid == othercid)
        del othercid['spam']
        assert (cid != othercid)
        assert (cid == {'spam': 'blueval', 'eggs': 'redval'})

    def test_setdefault(self):
        cid = CaseInsensitiveDict({'Spam': 'blueval'})
        assert (cid.setdefault('spam', 'notblueval') == 'blueval')
        assert (cid.setdefault('notspam', 'notblueval') == 'notblueval')

    def test_lower_items(self):
        cid = CaseInsensitiveDict({'Accept': 'application/json', 'user-Agent': 'requests'})
        keyset = frozenset((lowerkey for (lowerkey, v) in cid.lower_items()))
        lowerkeyset = frozenset(['accept', 'user-agent'])
        assert (keyset == lowerkeyset)

    def test_preserve_key_case(self):
        cid = CaseInsensitiveDict({'Accept': 'application/json', 'user-Agent': 'requests'})
        keyset = frozenset(['Accept', 'user-Agent'])
        assert (frozenset((i[0] for i in cid.items())) == keyset)
        assert (frozenset(cid.keys()) == keyset)
        assert (frozenset(cid) == keyset)

    def test_preserve_last_key_case(self):
        cid = CaseInsensitiveDict({'Accept': 'application/json', 'user-Agent': 'requests'})
        cid.update({'ACCEPT': 'application/json'})
        cid['USER-AGENT'] = 'requests'
        keyset = frozenset(['ACCEPT', 'USER-AGENT'])
        assert (frozenset((i[0] for i in cid.items())) == keyset)
        assert (frozenset(cid.keys()) == keyset)
        assert (frozenset(cid) == keyset)

class UtilsTestCase(unittest.TestCase):

    def test_super_len_io_streams(self):
        ' Ensures that we properly deal with different kinds of IO streams. '
        from io import BytesIO
        from async_requests.utils import super_len
        assert (super_len(StringIO.StringIO()) == 0)
        assert (super_len(StringIO.StringIO('with so much drama in the LBC')) == 29)
        assert (super_len(BytesIO()) == 0)
        assert (super_len(BytesIO(b"it's kinda hard bein' snoop d-o-double-g")) == 40)
        try:
            import cStringIO
        except ImportError:
            pass
        else:
            assert (super_len(cStringIO.StringIO('but some how, some way...')) == 25)

    def test_get_environ_proxies_ip_ranges(self):
        ' Ensures that IP addresses are correctly matches with ranges in no_proxy variable '
        from async_requests.utils import get_environ_proxies
        os.environ['no_proxy'] = '192.168.0.0/24,127.0.0.1,localhost.localdomain,172.16.1.1'
        assert (get_environ_proxies('http://192.168.0.1:5000/') == {})
        assert (get_environ_proxies('http://192.168.0.1/') == {})
        assert (get_environ_proxies('http://172.16.1.1/') == {})
        assert (get_environ_proxies('http://172.16.1.1:5000/') == {})
        assert (get_environ_proxies('http://192.168.1.1:5000/') != {})
        assert (get_environ_proxies('http://192.168.1.1/') != {})

    def test_get_environ_proxies(self):
        ' Ensures that IP addresses are correctly matches with ranges in no_proxy variable '
        from async_requests.utils import get_environ_proxies
        os.environ['no_proxy'] = '127.0.0.1,localhost.localdomain,192.168.0.0/24,172.16.1.1'
        assert (get_environ_proxies('http://localhost.localdomain:5000/v1.0/') == {})
        assert (get_environ_proxies('http://www.requests.com/') != {})

    def test_is_ipv4_address(self):
        from async_requests.utils import is_ipv4_address
        assert is_ipv4_address('8.8.8.8')
        assert (not is_ipv4_address('8.8.8.8.8'))
        assert (not is_ipv4_address('localhost.localdomain'))

    def test_is_valid_cidr(self):
        from async_requests.utils import is_valid_cidr
        assert (not is_valid_cidr('8.8.8.8'))
        assert is_valid_cidr('192.168.1.0/24')

    def test_dotted_netmask(self):
        from async_requests.utils import dotted_netmask
        assert (dotted_netmask(8) == '255.0.0.0')
        assert (dotted_netmask(24) == '255.255.255.0')
        assert (dotted_netmask(25) == '255.255.255.128')

    def test_address_in_network(self):
        from async_requests.utils import address_in_network
        assert address_in_network('192.168.1.1', '192.168.1.0/24')
        assert (not address_in_network('172.16.0.1', '192.168.1.0/24'))

    def test_get_auth_from_url(self):
        ' Ensures that username and password in well-encoded URI as per RFC 3986 are correclty extracted '
        from async_requests.utils import get_auth_from_url
        from async_requests.compat import quote
        percent_encoding_test_chars = "%!*'();:@&=+$,/?#[] "
        url_address = 'request.com/url.html#test'
        url = ((((('http://' + quote(percent_encoding_test_chars, '')) + ':') + quote(percent_encoding_test_chars, '')) + '@') + url_address)
        (username, password) = get_auth_from_url(url)
        assert (username == percent_encoding_test_chars)
        assert (password == percent_encoding_test_chars)

class TestMorselToCookieExpires(unittest.TestCase):
    'Tests for morsel_to_cookie when morsel contains expires.'

    def test_expires_valid_str(self):
        'Test case where we convert expires from string time.'
        morsel = Morsel()
        morsel['expires'] = 'Thu, 01-Jan-1970 00:00:01 GMT'
        cookie = morsel_to_cookie(morsel)
        assert (cookie.expires == 1)

    def test_expires_invalid_int(self):
        'Test case where an invalid type is passed for expires.'
        morsel = Morsel()
        morsel['expires'] = 100
        with pytest.raises(TypeError):
            morsel_to_cookie(morsel)

    def test_expires_invalid_str(self):
        'Test case where an invalid string is input.'
        morsel = Morsel()
        morsel['expires'] = 'woops'
        with pytest.raises(ValueError):
            morsel_to_cookie(morsel)

    def test_expires_none(self):
        'Test case where expires is None.'
        morsel = Morsel()
        morsel['expires'] = None
        cookie = morsel_to_cookie(morsel)
        assert (cookie.expires is None)

class TestMorselToCookieMaxAge(unittest.TestCase):
    'Tests for morsel_to_cookie when morsel contains max-age.'

    def test_max_age_valid_int(self):
        'Test case where a valid max age in seconds is passed.'
        morsel = Morsel()
        morsel['max-age'] = 60
        cookie = morsel_to_cookie(morsel)
        assert isinstance(cookie.expires, int)

    def test_max_age_invalid_str(self):
        'Test case where a invalid max age is passed.'
        morsel = Morsel()
        morsel['max-age'] = 'woops'
        with pytest.raises(TypeError):
            morsel_to_cookie(morsel)
if (__name__ == '__main__'):
    unittest.main()
