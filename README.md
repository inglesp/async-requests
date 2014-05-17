# AsyncRequests

[![Build Status](https://travis-ci.org/inglesp/async-requests.svg?branch=master)](https://travis-ci.org/inglesp/async-requests)

This is a proof of concept to demonstrate how
[Requests](http://docs.python-requests.org/en/latest/) can be adapted to work
with [asyncio](https://docs.python.org/3.4/library/asyncio.html), using
[aiohttp](https://github.com/KeepSafe/aiohttp/) to do most of the work.

The goal is to create a library that has the same API as Requests, except for
requiring interaction with asyncio's event loop.

With Requests:

````
r = requests.get('https://api.github.com/user', auth=('user', 'pass'))
````

With AsyncRequests:

````
r = yield from async_requests.get('https://api.github.com/user', auth=('user', 'pass'))
````

The project currently has alpha status.  It passes Requests's test suite, but
it could do with some further testing.  In addition, it does not yet support
connection pooling.

Any/all feedback welcome!
