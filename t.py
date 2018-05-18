import os

import requests

# https://speca.io/speca/digital-ocean-api-v2


class DigitalOcean:
    """A DigitalOcean instance."""
    base_url = 'https://api.digitalocean.com/v2/'

    def __init__(self, *, token=None):
        if token is None:
            token = os.environ['DO_TOKEN']

        self.__token = token
        self.__session = requests.Session()
        self.__session.auth = self

    def __prepare_url(self, url):
        # Complete the URL if a relative link was provided.
        if url:
            if not url.startswith('http'):
                url = '{}{}'.format(self.base_url, url)
        return url

    def request(self, *, method='GET', url, json=True, **kwargs):
        r = self.__session.request(method, url, **kwargs)
        return r.json() if json else r

    def get(self, url, **kwargs):
        url = self.__prepare_url(url=url)
        return self.request(url=url, **kwargs)

    def post(self, url, data, **kwargs):
        url = self.__prepare_url(url=url)
        return self.request(url=url, data=data, **kwargs)

    def patch(self, url, data, **kwargs):
        url = self.__prepare_url(url=url)
        return self.request(url=url, **kwargs)

    def delete(self, url, **kwargs):
        url = self.__prepare_url(url=url)
        return self.request(url=url, **kwargs)

    def __call__(self, r):
        """Auth handler for Requests."""
        r.headers['Authorization'] = "Bearer {}".format(self.__token)
        return r

    def account(self):
        return self.get('account')

    def actions(self, page=1, per_page=25):
        return self.get('actions', params={'page': page, 'per_page': per_page})

    def get_action(self, action_id):
        return self.get(f'actions/{action_id}')

    def volumes(self):
        return self.get('volumes')

    def new_volume(self, size_gigabytes, name, description, region):
        return self.post('volumes', data={'size_gigabytes': size_gigabytes, 'name': name, 'description': description, 'region': region}, json=True)

    def get_volume(self, volume_id):
        return self.get(f'volumes/{volume_id}')



do = DigitalOcean()
print(do.get_volume('7c0b5e7b-4fe4-11e8-aa6c-0242ac116308'))