import base64
import hashlib

import requests


DEFAULT_CONN = 'http://10.0.0.1:5000'


class HttpClient:

    def __init__(self, url=DEFAULT_CONN):
        self.url = url

    def send_update(self, key, file_content: bytes) -> None:
        url = self.url + '/update'
        b64 = base64.urlsafe_b64encode(file_content).decode('utf-8')
        hash = hashlib.sha512(key).hexdigest()
        data = {'hash': hash, 'data': b64}
        r = requests.post(url, data=data)
        if r.status_code == 200:
            return
        else:
            raise Exception((r.text, r.status_code))

    def send_get(self, key) -> bytes:
        url = self.url + '/get'
        hash = hashlib.sha512(key).hexdigest()
        data = {'hash': hash}
        r = requests.post(url, data=data)
        if r.status_code == 200:
            return base64.urlsafe_b64decode(r.text.encode('utf-8'))
        else:
            raise ConnectionError((r.text, r.status_code))


if __name__ == '__main__':
    client = HttpClient()
    client.send_update('key', b'hello')
    print(client.send_get('key'))
