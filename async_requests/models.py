from requests.models import *


class AsyncResponse(Response):
    def close(self):
        self.raw.close()

del Response
