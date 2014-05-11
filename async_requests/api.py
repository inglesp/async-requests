import asyncio

from . import sessions


@asyncio.coroutine
def request(method, url, **kwargs):
    session = sessions.AsyncSession()
    return (yield from session.request(method=method, url=url, **kwargs))


@asyncio.coroutine
def get(url, **kwargs):
    kwargs.setdefault('allow_redirects', True)
    return (yield from request('get', url, **kwargs))


@asyncio.coroutine
def options(url, **kwargs):
    kwargs.setdefault('allow_redirects', True)
    return (yield from request('options', url, **kwargs))


@asyncio.coroutine
def head(url, **kwargs):
    kwargs.setdefault('allow_redirects', False)
    return (yield from request('head', url, **kwargs))


@asyncio.coroutine
def post(url, data=None, **kwargs):
    return (yield from request('post', url, data=data, **kwargs))


@asyncio.coroutine
def put(url, data=None, **kwargs):
    return (yield from request('put', url, data=data, **kwargs))


@asyncio.coroutine
def patch(url, data=None, **kwargs):
    return (yield from request('patch', url,  data=data, **kwargs))


@asyncio.coroutine
def delete(url, **kwargs):
    return (yield from request('delete', url, **kwargs))
