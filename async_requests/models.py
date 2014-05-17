import asyncio

import aiohttp

from requests.models import *


class AsyncResponse(Response):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        del self._content
        self.content = False
        self._lines = []
        self._next_line_fragment = b''

    def close(self):
        self.raw.close()

    def __iter__(self):
        raise NotImplementedError

    @asyncio.coroutine
    def iter_content(self):
        if self._content_consumed:
            raise RuntimeError('The content for this response was already consumed')

        try:
            chunk = yield from self.raw.content.read()
            return chunk
        except aiohttp.EofStream:
            self.close()
            self._content_consumed = True
            return None

    @asyncio.coroutine
    def iter_lines(self):
        while True:
            if self._lines:
                line, *self._lines = self._lines
                return line

            chunk = yield from self.iter_content()

            if chunk is None:
                self._lines = [None]

            else:
                data = self._next_line_fragment + chunk

                lines = data.splitlines()

                if lines[-1][-1] == chunk[-1]:
                    self._lines = lines[:-1]
                    self._next_line_fragment = lines[-1]
                else:
                    self._lines = lines
                    self._next_line_fragment = b''

    @asyncio.coroutine
    def load_content(self):
        if self.content is False:
            if self.status_code == 0:
                self.content = None
            else:
                chunks = []

                while True:
                    chunk = yield from self.iter_content()
                    if chunk is None:
                        break
                    else:
                        chunks.append(chunk)

                self.content = b''.join(chunks)

        self._content_consumed = True
        return self.content


del Response.content
del Response
