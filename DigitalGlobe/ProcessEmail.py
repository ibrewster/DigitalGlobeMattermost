import config
import os
import pickle

from datetime import datetime, timezone
from io import BytesIO
from xml.etree import ElementTree

import mattermostdriver
import pymysql

# Gmail API utils
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

# for encoding/decoding messages in base64
from base64 import urlsafe_b64decode

FILEDIR = os.path.dirname(__file__)

def get_colored_volcanoes():
    try:
        conn = pymysql.connect(host=config.MYSQL_SERVER, user=config.MYSQL_USER,
                               password=config.MYSQL_PASSWORD,
                               database=config.MYSQL_DB)
        cur = conn.cursor()
        SQL = """SELECT
            volcano_name
        FROM current_codes
        INNER JOIN volcano
        ON volcano.volcano_id=current_codes.volcano_id
        WHERE color_code NOT IN ('GREEN','UNASSIGNED')"""
        cur.execute(SQL)
        to_check = [x[0].lower() for x in cur]
        conn.close()
    except:
        to_check = []
        
    return to_check

def connect_to_mattermost():
    mattermost = mattermostdriver.Driver({
        'url': config.MATTERMOST_URL,
        'login_id': config.MATTERMOST_USER,
        'password': config.MATTERMOST_PASSWORD,
        'port': config.MATTERMOST_PORT
    })

    mattermost.login()
    channel_id = mattermost.channels.get_channel_by_name_and_team_name(config.MATTERMOST_TEAM,
                                                                       config.MATTERMOST_CHANNEL)['id']
    return (mattermost, channel_id)


def gmail_authenticate():
    SCOPES = ['https://mail.google.com/']
    creds = None
    # the file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first time
    token_path = os.path.join(FILEDIR, 'token.pickle')
    if os.path.exists(token_path):
        with open(token_path, "rb") as token:
            creds = pickle.load(token)
    # if there are no (valid) credentials availablle, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            creds_path = os.path.join(FILEDIR, 'credentials.json')            
            flow = InstalledAppFlow.from_client_secrets_file(creds_path, SCOPES)
            creds = flow.run_local_server(port=0)
        # save the credentials for the next run
        with open(token_path, "wb") as token:
            pickle.dump(creds, token)
    return build('gmail', 'v1', credentials=creds)


def search_messages(service, query):
    result = service.users().messages().list(userId='me',
                                             q=query
                                             # labelIds = ['INBOX']
                                             ).execute()
    messages = []
    if 'messages' in result:
        messages.extend(result['messages'])
    while 'nextPageToken' in result:
        page_token = result['nextPageToken']
        result = service.users().messages().list(userId='me', q=query, pageToken=page_token).execute()
        if 'messages' in result:
            messages.extend(result['messages'])
    return messages


def upload_to_mattermost(feature_id, image, meta, mattermost, channel_id):
    volcano = meta['volcano']
    date = meta['date']
    filename = f"{feature_id}.png"
    url = f"https://evwhs.digitalglobe.com/myDigitalGlobe/autoLoginService?featureId={feature_id}"

    # First, upload the thumbnail
    upload_result = mattermost.files.upload_file(
        channel_id=channel_id,
        files={'files': (filename, image)}
    )

    matt_id = upload_result['file_infos'][0]['id']
    matt_message = f"""### {volcano.title()} image available
**Published Date:** {date.strftime('%Y-%m-%d %H:%M:%S')}
**Feature ID:** {feature_id}
**Download URL:** {url}
"""

    mattermost.posts.create_post({
        'channel_id': channel_id,
        'message': matt_message,
        'file_ids': [matt_id],
    })

def parse_metadata(metadata):
    metadata = urlsafe_b64decode(metadata.get('data'))
    root = ElementTree.fromstring(metadata)
    items = root[0].findall('item')
    info = {}
    for item in items:
        ident_str = item.find('title').text
        pub_date = item.find('pubDate').text
        pub_date = datetime.strptime(pub_date[5:],
                                     '%d %b %Y %H:%M:%S %Z').replace(tzinfo = timezone.utc)
        ident_info = dict(x.split(': ') for x in ident_str.split(' - '))
        ident_info['date'] = pub_date
        ident_info['volcano'] = ident_info['Area'].replace(' new', '')
        info[ident_info['FeatureID']] = ident_info
    
    return info

def process_email():
    service = gmail_authenticate()
    messages = search_messages(service, "from:noreply@digitalglobe.com")
    if not messages:
        print("No new messages")
        return        
    
    mattermost, channel_id = connect_to_mattermost()
    colored_volcanoes = get_colored_volcanoes()

    for message in messages:
        message_id = message['id']
        msg = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        print('----------------')
        
        attachment_headers = [
            (part, part['body'].get('attachmentId'))
            for part in msg['payload']['parts']
            if part['mimeType'] == 'application/octet-stream'
            and part['filename'] != 'metadata'
        ]
        
        metadata_id = next(
            part['body'].get('attachmentId')
            for part in msg['payload']['parts']
            if part['mimeType'] == 'application/octet-stream'
            and part['filename'] == 'metadata'
        )
        
        metadata = service.users().messages().attachments()\
                .get(id = metadata_id, userId = 'me', messageId = message_id).execute()
        
        metadata = parse_metadata(metadata)
        
        # The volcano is the same for all attachments, so just grab the "first" one
        volcano:str = tuple(metadata.values())[0]['volcano']
        if volcano.lower() not in colored_volcanoes:
            continue        
        
        for attachment, attachment_id in attachment_headers:
            feature_id = attachment['filename']
            meta = metadata[feature_id]
            

            print(f"New imagery for {volcano}")
            file = service.users().messages().attachments()\
                .get(id = attachment_id, userId = 'me', messageId = message_id).execute()

            file_data = urlsafe_b64decode(file.get('data'))
            file_stream = BytesIO(file_data)
            file_stream.seek(0)

            upload_to_mattermost(feature_id, file_stream, meta, mattermost,
                                 channel_id)

            # Archive the message
            modify_body = {
                "addLabelIds": [],
                "removeLabelIds": ['UNREAD', 'INBOX'],
            }
            service.users().messages().modify(userId = "me",
                                              id = message_id,
                                              body = modify_body).execute()


if __name__ == "__main__":
    process_email()
