import asyncio

import aiohttp

from requests.adapters import *

from .models import AsyncResponse
from .structures import CaseInsensitiveDict
from .utils import get_encoding_from_headers
from .cookies import extract_cookies_to_jar


class AsyncHTTPAdapter(HTTPAdapter):
    @asyncio.coroutine
    def send(self, request, **kwargs):
        method = request.method
        url = request.url
        resp = yield from aiohttp.request(
            method,
            url,
            data=request.body,
            headers=request.headers.items(),
            allow_redirects=False,
        )
        r = self.build_response(request, resp)

        # TODO This should handle streaming
        r._content = yield from r.raw.read_and_close()
        return r

    def build_response(self, req, resp):
        """Builds a :class:`Response <requests.Response>` object from a urllib3
        response. This should not be called from user code, and is only exposed
        for use when subclassing the
        :class:`HTTPAdapter <requests.adapters.HTTPAdapter>`

        :param req: The :class:`PreparedRequest <PreparedRequest>` used to generate the response.
        :param resp: The urllib3 response object.
        """
        response = AsyncResponse()

        # Fallback to None if there's no status_code, for whatever reason.
        response.status_code = getattr(resp, 'status', None)

        # Make headers case-insensitive.
        response.headers = CaseInsensitiveDict(getattr(resp, '_headers', {}))

        # Set encoding.
        response.encoding = get_encoding_from_headers(response.headers)
        response.raw = resp
        response.reason = response.raw.reason

        if isinstance(req.url, bytes):
            response.url = req.url.decode('utf-8')
        else:
            response.url = req.url

        # Add new cookies from the server.
        extract_cookies_to_jar(response.cookies, req, resp)

        # Give the Response some context.
        response.request = req
        response.connection = self

        return response


del HTTPAdapter
