# AsyncRequests

[![Build Status](https://travis-ci.org/inglesp/async-requests.svg?branch=master)](https://travis-ci.org/inglesp/async-requests)

This is a proof of concept to demonstrate how [Requests](python-requests.org)
can be adapted to work with
[asyncio](https://docs.python.org/3.4/library/asyncio.html), using
[aiohttp](https://github.com/KeepSafe/aiohttp/) to do most of the work.

It is currently very limited, and only allows you to make simple requests for
urls with a given method.  It doesn't allow you to set any headers, provide any
params or data, use cookies or connection pooling, or anything else that you
might reasonably want to do with an HTTP library.  (Nor does it have any tests!)

There are two examples of its use, in curl.py and crawl.py, both of which are
modified from examples in aiohttp.

Any/all feedback welcome!
