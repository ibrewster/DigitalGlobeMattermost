import config
import os
import pickle

from io import BytesIO

import mattermostdriver

# Gmail API utils
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

# for encoding/decoding messages in base64
from base64 import urlsafe_b64decode


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
    if os.path.exists("token.pickle"):
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)
    # if there are no (valid) credentials availablle, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # save the credentials for the next run
        with open("token.pickle", "wb") as token:
            pickle.dump(creds, token)
    return build('gmail', 'v1', credentials=creds)


def search_messages(service, query):
    result = service.users().messages().list(userId='me',
                                             q=query,
                                             labelIds = ['INBOX']).execute()
    messages = []
    if 'messages' in result:
        messages.extend(result['messages'])
    while 'nextPageToken' in result:
        page_token = result['nextPageToken']
        result = service.users().messages().list(userId='me', q=query, pageToken=page_token).execute()
        if 'messages' in result:
            messages.extend(result['messages'])
    return messages


def upload_to_mattermost(feature_id, image, volcano, mattermost, channel_id):
    filename = f"{feature_id}.png"
    url = f"https://evwhs.digitalglobe.com/myDigitalGlobe/autoLoginService?featureId={feature_id}"

    # First, upload the thumbnail
    upload_result = mattermost.files.upload_file(
        channel_id=channel_id,
        files={'files': (filename, image)}
    )

    matt_id = upload_result['file_infos'][0]['id']
    matt_message = f"""### {volcano.title()} image available
**Feature ID:** {feature_id}
**Download URL:** {url}
"""

    mattermost.posts.create_post({
        'channel_id': channel_id,
        'message': matt_message,
        'file_ids': [matt_id],
    })


def get_email():
    service = gmail_authenticate()
    messages = search_messages(service, "from:noreply@digitalglobe.com")
    if messages:
        mattermost, channel_id = connect_to_mattermost()
    else:
        print("No new messages")
        return

    for message in messages:
        message_id = message['id']
        msg = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        print('----------------')
        volcano = next(
            i['value']
            for i in msg['payload']['headers']
            if i["name"] == "Subject"
        )
        volcano = volcano.split(':')[1].replace('new_archive', '').strip()
        print("Subject: ", volcano)
        attachment_headers = [
            (part, part['body'].get('attachmentId'))
            for part in msg['payload']['parts']
            if part['mimeType'] == 'application/octet-stream'
        ]
        for attachment, attachment_id in attachment_headers:
            feature_id = attachment['filename']
            if feature_id == "metadata":
                continue

            print(f"New imagery for {volcano}")
            file = service.users().messages().attachments()\
                .get(id = attachment_id, userId = 'me', messageId = message_id).execute()

            file_data = urlsafe_b64decode(file.get('data'))
            file_stream = BytesIO(file_data)
            file_stream.seek(0)

            upload_to_mattermost(feature_id, file_stream, volcano, mattermost,
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
    get_email()
