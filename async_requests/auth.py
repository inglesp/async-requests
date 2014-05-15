from requests.auth import *

from .cookies import extract_cookies_to_jar


class AsyncHTTPDigestAuth(HTTPDigestAuth):
    def handle_401(self, r, **kwargs):
        """Takes the given response and tries digest-auth, if needed."""

        if self.pos is not None:
            # Rewind the file position indicator of the body to where
            # it was to resend the request.
            r.request.body.seek(self.pos)
        num_401_calls = getattr(self, 'num_401_calls', 1)
        s_auth = r.headers.get('www-authenticate', '')

        if 'digest' in s_auth.lower() and num_401_calls < 2:

            setattr(self, 'num_401_calls', num_401_calls + 1)
            pat = re.compile(r'digest ', flags=re.IGNORECASE)
            self.chal = parse_dict_header(pat.sub('', s_auth, count=1))

            # Consume content and release the original connection
            # to allow our new request to reuse the same one.
            r.content
            r.raw.close()
            prep = r.request.copy()
            extract_cookies_to_jar(prep._cookies, r.request, r.raw)
            prep.prepare_cookies(prep._cookies)

            prep.headers['Authorization'] = self.build_digest_header(
                prep.method, prep.url)
            _r = yield from r.connection.send(prep, **kwargs)
            _r.history.append(r)
            _r.request = prep

            return _r

        setattr(self, 'num_401_calls', 1)
        return r


del HTTPDigestAuth
