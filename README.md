# AsyncRequests

[![Build Status](https://travis-ci.org/inglesp/async-requests.svg?branch=master)](https://travis-ci.org/inglesp/async-requests)

This is a proof of concept to demonstrate how
[Requests](http://docs.python-requests.org/en/latest/) can be adapted to work
with [asyncio](https://docs.python.org/3.4/library/asyncio.html), using
[aiohttp](https://github.com/KeepSafe/aiohttp/) to do most of the work.

The goal to to create a library that has the same API as Requests, except for
requiring interaction with asyncio's event loop.

With Requests:

````
r = requests.get('https://api.github.com/user', auth=('user', 'pass'))
````

With AsyncRequests:

````
r = yield from async_requests.get('https://api.github.com/user', auth=('user', 'pass'))
````

The first step towards that goal is to make AsyncRequests pass Requests's test
suite.  There is a script, `generate_tests.py`, that produces a test file,
`test_async_requests.py`, derived from Request's `test_requests.py`.  There are
currently a handful of remaining failing test cases, related to digest auth.

Once the test suite passes, the next step will be to identify and fix areas
where AsyncRequests does not provide functionality equivalent to Requests,
including response streaming and connection pooling.

Any/all feedback welcome!
