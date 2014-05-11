import asyncio
from datetime import datetime

from requests.sessions import *

from .adapters import AsyncHTTPAdapter


class AsyncSessionRedirectMixin(object):
    @asyncio.coroutine
    def resolve_redirects(self, resp, req, stream=False, timeout=None,
                          verify=True, cert=None, proxies=None):
        """Receives a Response. Returns a generator of Responses."""

        i = 0
        responses = []

        # ((resp.status_code is codes.see_other))
        while ('location' in resp.headers and resp.status_code in REDIRECT_STATI):
            prepared_request = req.copy()

            resp.content  # Consume socket so it can be released

            if i >= self.max_redirects:
                raise TooManyRedirects('Exceeded %s redirects.' % self.max_redirects)

            # Release the connection back into the pool.
            resp.close()

            url = resp.headers['location']
            method = req.method

            # Handle redirection without scheme (see: RFC 1808 Section 4)
            if url.startswith('//'):
                parsed_rurl = urlparse(resp.url)
                url = '%s:%s' % (parsed_rurl.scheme, url)

            # The scheme should be lower case...
            parsed = urlparse(url)
            url = parsed.geturl()

            # Facilitate non-RFC2616-compliant 'location' headers
            # (e.g. '/path/to/resource' instead of 'http://domain.tld/path/to/resource')
            # Compliant with RFC3986, we percent encode the url.
            if not urlparse(url).netloc:
                url = urljoin(resp.url, requote_uri(url))
            else:
                url = requote_uri(url)

            prepared_request.url = url

            # http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.3.4
            if (resp.status_code == codes.see_other and
                    method != 'HEAD'):
                method = 'GET'

            # Do what the browsers do, despite standards...
            # First, turn 302s into GETs.
            if resp.status_code == codes.found and method != 'HEAD':
                method = 'GET'

            # Second, if a POST is responded to with a 301, turn it into a GET.
            # This bizarre behaviour is explained in Issue 1704.
            if resp.status_code == codes.moved and method == 'POST':
                method = 'GET'

            prepared_request.method = method

            # https://github.com/kennethreitz/requests/issues/1084
            if resp.status_code not in (codes.temporary, codes.resume):
                if 'Content-Length' in prepared_request.headers:
                    del prepared_request.headers['Content-Length']

                prepared_request.body = None

            headers = prepared_request.headers
            try:
                del headers['Cookie']
            except KeyError:
                pass

            extract_cookies_to_jar(prepared_request._cookies,
                                   prepared_request, resp.raw)
            prepared_request._cookies.update(self.cookies)
            prepared_request.prepare_cookies(prepared_request._cookies)

            resp = yield from self.send(
                prepared_request,
                stream=stream,
                timeout=timeout,
                verify=verify,
                cert=cert,
                proxies=proxies,
                allow_redirects=False,
            )

            extract_cookies_to_jar(self.cookies, prepared_request, resp.raw)

            responses.append(resp)

            i += 1

        return responses


class AsyncSession(AsyncSessionRedirectMixin, Session):
    def __init__(self):
        """Register AsyncHTTPAdapter as adapter."""

        super().__init__()
        self.mount('https://', AsyncHTTPAdapter())
        self.mount('http://', AsyncHTTPAdapter())

    @asyncio.coroutine
    def send(self, request, **kwargs):
        """Send a given PreparedRequest."""
        # Set defaults that the hooks can utilize to ensure they always have
        # the correct parameters to reproduce the previous request.
        kwargs.setdefault('stream', self.stream)
        kwargs.setdefault('verify', self.verify)
        kwargs.setdefault('cert', self.cert)
        kwargs.setdefault('proxies', self.proxies)

        # It's possible that users might accidentally send a Request object.
        # Guard against that specific failure case.
        if not isinstance(request, PreparedRequest):
            raise ValueError('You can only send PreparedRequests.')

        # Set up variables needed for resolve_redirects and dispatching of hooks
        allow_redirects = kwargs.pop('allow_redirects', True)
        stream = kwargs.get('stream')
        timeout = kwargs.get('timeout')
        verify = kwargs.get('verify')
        cert = kwargs.get('cert')
        proxies = kwargs.get('proxies')
        hooks = request.hooks

        # Get the appropriate adapter to use
        adapter = self.get_adapter(url=request.url)

        # Start time (approximately) of the request
        start = datetime.utcnow()

        # Send the request
        r = yield from adapter.send(request, **kwargs)

        # Total elapsed time of the request (approximately)
        r.elapsed = datetime.utcnow() - start

        # Response manipulation hooks
        r = dispatch_hook('response', hooks, r, **kwargs)

        # Persist cookies
        if r.history:

            # If the hooks create history then we want those cookies too
            for resp in r.history:
                extract_cookies_to_jar(self.cookies, resp.request, resp.raw)

        extract_cookies_to_jar(self.cookies, request, r.raw)

        # Resolve redirects if allowed.
        if allow_redirects:
            history = yield from self.resolve_redirects(r, request,
                    stream=stream,
                    timeout=timeout,
                    verify=verify,
                    cert=cert,
                    proxies=proxies)
        else:
            history = []

        # Shuffle things around if there's history.
        if history:
            # Insert the first (original) request at the start
            history.insert(0, r)
            # Get the last request made
            r = history.pop()
            r.history = history

        return r


def session():
    return AsyncSession()

del Session
del SessionRedirectMixin
