#!/usr/bin/python3

import json
import os.path
import requests
import urllib.parse
#!/usr/bin/python3

import argparse
import json
import mimetypes
import os.path
import requests

script_path = os.path.abspath(__file__)
script_dir = os.path.dirname(script_path)

def get_folder_id(self, folder, parent):
    _r = None
    try:
        url = 'https://www.googleapis.com/drive/v3/files?q={0}'. \
            format(quote(
                "mimeType='application/vnd.google-apps.folder'"
                " and name ='{0}'"
                " and trashed != true"
                " and '{1}' in parents".format(folder, parent),
                safe='~()*!.\''
                )
            )
        _r = requests.get(url, headers={
            "Authorization": "Bearer {0}".format(self.get_access_token()),
            "Content-Type": self.file_bean.get_content_type(),
        })
        _r.raise_for_status()
        _dict = _r.json()
        if 'files' in _dict and len(_dict['files']):
            return _dict['files'][0]['id']
        else:
            _f = self.create_folder(folder, parent)
            if _f:
                return _f
            status, status_message = self.get_invalid_folder()
    except requests.exceptions.HTTPError:
        status, status_message = self.get_http_error(_r)
    except Exception as e:
        logger.exception(e)
        status, status_message = self.get_unknown_error()


def create_folder(self, folder_name, parent_folder_id):
    url = 'https://www.googleapis.com/drive/v3/files'
    headers = {
        'Authorization': 'Bearer {}'.format(self.get_access_token()), # get your access token
        'Content-Type': 'application/json'
    }
    metadata = {
        'name': folder_name, #folder_name as a string
        'parents': [parent_folder_id], # parent folder id (="root" if you want to create a folder in root)
        'mimeType': 'application/vnd.google-apps.folder'
    }
    response = requests.post(url, headers=headers, data=json.dumps(metadata))
    response = response.json()
    if 'error' not in response:
        return response['id']  # finally return folder id
def upload(file_path,folder_id,verbose=False):
    file_obj = open(file_path, mode='rb')
    file_name = os.path.basename(file_path)
    file_mime_type = mimetypes.guess_type(file_path)[0]
    ### client secret ###
    client = None
    client_name = 'client_secret.json'
    client_path = os.path.join(script_dir, client_name)
    with open(client_path, 'r') as f:
        client = json.load(f)
    assert client is not None and 'installed' in client
    client = client['installed']

    assert 'client_id' in client
    if verbose:
        print('=== client id ===')
        print(client['client_id'])
        print()

    assert 'client_secret' in client
    if verbose:
        print('=== client secret ===')
        print(client['client_secret'])
        print()


    ### refresh token ###

    refresh_token = None
    refresh_name = 'refresh_token.txt'
    refresh_path = os.path.join(script_dir, refresh_name)
    with open(refresh_path, mode='r') as f:
        refresh_token = f.read().rstrip()

    if verbose:
        print('=== refresh token ===')
        print(refresh_token)
        print()


    ### access token ###

    r = requests.post('https://accounts.google.com/o/oauth2/token', data={
        'client_id': client['client_id'],
        'client_secret': client['client_secret'],
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token',
    })
    r = r.json()
    assert 'error' not in r, r['error_description']

    access_token = r['access_token']
    if verbose:
        print('=== access token ===')
        print(access_token)
        print()
    ### upload file ###
    r = requests.post('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', files={
        'metadata': (
            None,
            json.dumps({
                'name': file_name,
                'parents': [
                    folder_id,
                ],
            }),
            'application/json; charset=UTF-8'
        ),
        'file': (
            file_name,
            file_obj,
            file_mime_type,
        ),
    }, headers={
        'Authorization': 'Bearer ' + access_token,
    })
    r = r.json()
    assert 'error' not in r, '{} - {}'.format(r['error']['code'], r['error']['message'])
    if verbose:
        print('=== file id ===')
        print(r['id'])
        print()


def auth(file_name,directory_id):
    client = None
    client_name = 'client_secret.json'
    client_path = os.path.join(script_dir, client_name)
    with open(client_path, 'r') as f:
        client = json.load(f)
    assert client is not None and 'installed' in client
    client = client['installed']
    assert 'client_id' in client
    print('=== client id ===')
    print(client['client_id'])
    print()

    assert 'client_secret' in client
    print('=== client secret ===')
    print(client['client_secret'])
    print()

    print('=== url ===')
    print('https://accounts.google.com/o/oauth2/auth?' + urllib.parse.urlencode({
        'client_id': client['client_id'],
        'scope': 'https://www.googleapis.com/auth/drive.file',
        'response_type': 'code',
        'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
    }))
    print()

    code = input('code: ')
    print()
    print('=== code ===')
    print(code)
    print()

    r = requests.post('https://oauth2.googleapis.com/token', data={
        'client_id': client['client_id'],
        'client_secret': client['client_secret'],
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
    })
    r = r.json()
    assert 'error' not in r, r['error_description']

    refresh_token = r['refresh_token']
    print('=== refresh token ===')
    print(refresh_token)
    print()

    refresh_name = 'refresh_token.txt'
    refresh_path = os.path.join(script_dir, refresh_name)
    with open(refresh_path, mode='w') as f:
        f.write(refresh_token + '\n')

parser = argparse.ArgumentParser()
parser.add_argument('file', metavar='FILE')
parser.add_argument('folder', metavar='FOLDER_ID')
parser.add_argument('-v', '--verbose', action='store_true')
args = parser.parse_args()
file_path = args.file
folder_id=args.folder
upload(file_path, folder_id,args.verbose)