#!/usr/bin/env python3

import sys
import asyncio

import async_requests


@asyncio.coroutine
def curl(url):
    session = async_requests.AsyncSession()

    response = yield from session.get(url)
    print(response)

    content = yield from response.content
    print(content)

    response.close()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(curl(sys.argv[1]))
