import asyncio
from datetime import datetime

import requests
import aiohttp


class AsyncSession(requests.sessions.Session):
    def __init__(self):
        """Register AsyncHTTPAdapter as adaptor."""

        super().__init__()
        self.mount('http://', AsyncHTTPAdapter())

    def send(self, request, **kwargs):
        """Send PreparedRequest, and return a Future whose result is response.
        
        Do the first half of the work, up to adapter.send, of Session.send.
        """

        # It's possible that users might accidentally send a Request object.
        # Guard against that specific failure case.
        if not isinstance(request, requests.models.PreparedRequest):
            raise ValueError('You can only send PreparedRequests.')

        # Get the appropriate adapter to use
        adapter = self.get_adapter(url=request.url)

        # Start time (approximately) of the request
        start = datetime.utcnow()

        # Send the request
        future = adapter.send(request, **kwargs)

        callback = lambda f: self.process_response(f, request, start=start, **kwargs)
        future.add_done_callback(callback) 

        return future

    def process_response(self, future, request, **kwargs):
        """Do the second half of the work of Session.send."""

        r = future.result()

        # Set defaults that the hooks can utilize to ensure they always have
        # the correct parameters to reproduce the previous request.
        kwargs.setdefault('stream', self.stream)
        kwargs.setdefault('verify', self.verify)
        kwargs.setdefault('cert', self.cert)
        kwargs.setdefault('proxies', self.proxies)

        # Set up variables needed for resolve_redirects and dispatching of hooks
        allow_redirects = kwargs.pop('allow_redirects', True)
        stream = kwargs.get('stream')
        timeout = kwargs.get('timeout')
        verify = kwargs.get('verify')
        cert = kwargs.get('cert')
        proxies = kwargs.get('proxies')
        hooks = request.hooks

        # Total elapsed time of the request (approximately)
        r.elapsed = datetime.utcnow() - kwargs['start']

        # Response manipulation hooks
        r = requests.hooks.dispatch_hook('response', hooks, r, **kwargs)

        # Persist cookies
        if r.history:

            # If the hooks create history then we want those cookies too
            for resp in r.history:
                extract_cookies_to_jar(self.cookies, resp.request, resp.raw)

        requests.cookies.extract_cookies_to_jar(self.cookies, request, r.raw)

        # Redirect resolving generator.
        gen = self.resolve_redirects(r, request,
            stream=stream,
            timeout=timeout,
            verify=verify,
            cert=cert,
            proxies=proxies)

        # Resolve redirects if allowed.
        history = [resp for resp in gen] if allow_redirects else []

        # Shuffle things around if there's history.
        if history:
            # Insert the first (original) request at the start
            history.insert(0, r)
            # Get the last request made
            r = history.pop()
            r.history = history


class AsyncResponse(requests.models.Response):
    @property
    @asyncio.coroutine
    def content(self):
        """Read data from underlying aiohttp.client.HttpResponse."""
        if self._content is False:
            self._content = yield from self.raw.read()
        return self._content

    def close(self):
        """Close underlying aiohttp.client.HttpResponse.
        
        Must be called on pain of segfault!"""
        self.raw.close()


class AsyncHTTPAdapter(requests.adapters.BaseAdapter):
    def send(self, request, **kwargs):
        """Create Task to handle sending of request."""
        future = asyncio.Future()
        asyncio.Task(self.actually_send(request, future))
        return future

    @asyncio.coroutine
    def actually_send(self, request, future):
        """Extract method and url from request, and pass to aiohttp."""
        method = request.method
        url = request.url
        resp = yield from aiohttp.request(method, url)
        response = yield from self.build_response(request, resp)
        future.set_result(response)

    @asyncio.coroutine
    def build_response(self, req, resp):
        """Build an AsyncResponse from aiohttp.client.HttpResponse."""
        response = AsyncResponse()
        response.status_code = getattr(resp, 'status', None)
        response.headers = requests.structures.CaseInsensitiveDict(getattr(resp, '_headers', {}))
        response.encoding = requests.utils.get_encoding_from_headers(response.headers)

        response.raw = resp
        response.reason = response.raw.reason

        if isinstance(req.url, bytes):
            response.url = req.url.decode('utf-8')
        else:
            response.url = req.url

        requests.cookies.extract_cookies_to_jar(response.cookies, req, resp)

        response.req = req
        response.connection = self

        return response
