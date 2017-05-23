from flask import Flask

import requests
import json
import logging
import base64

app = Flask(__name__)

APIC_URL = 'https://172.17.0.1'  # Fixed, APIC's gateway for the app
KEY_FILE_PATH = '/home/app/credentials/plugin.key'  # Fixed for every app
APP_USER = 'Imapex_APICTest'
USER_CERT = APP_USER
USER_CERT_DN = 'uni/userext/appuser-{}/usercert-{}'.format(APP_USER, USER_CERT)


def requestAppToken():
    session = requests.session()

    try:
        from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, sign
    except:
        logging.info("=== could not import openssl crypto ===")

    ### Login Using RequestAppToken ###
    uri = "/api/requestAppToken.json"
    app_token_payload = {"aaaAppToken": {"attributes": {"appName": APP_USER}}}

    data = json.dumps(app_token_payload)
    payLoad = "POST" + uri + data

    p_key = ''
    with open(KEY_FILE_PATH, "r") as file:
        p_key = file.read()
    p_key = load_privatekey(FILETYPE_PEM, p_key)

    signedDigest = sign(p_key, payLoad.encode(), 'sha256')
    signature = base64.b64encode(signedDigest).decode()

    cookie = "APIC-Request-Signature=" + signature + ";"
    cookie += "APIC-Certificate-Algorithm=v1.0;"
    cookie += "APIC-Certificate-Fingerprint=fingerprint;"
    cookie += "APIC-Certificate-DN=" + USER_CERT_DN

    reply = session.post("{}{}".format(APIC_URL, uri), data=data, headers={'Cookie': cookie}, verify=False)
    json_reply = json.loads(reply.text)
    logging.info("Reply of requestAppToken: {}".format(json_reply))
    auth_token = json_reply['imdata'][0]['aaaLogin']['attributes']['token']

    token_cookie = {}
    token_cookie['APIC-Cookie'] = auth_token

    return token_cookie


def getClass(clazz, cookie):
    session = requests.session()

    ### Login Using RequestAppToken ###
    uri = "/api/class/"
    reply = session.get("{}{}{}.json".format(APIC_URL, uri, clazz), cookies=cookie, verify=False)
    logging.info("Reply: {}".format(reply))
    json_reply = json.loads(reply.text)

    return json_reply


def getMo(mo, cookie):
    session = requests.session()

    ### Login Using RequestAppToken ###
    uri = "/api/mo/"
    reply = session.get("{}{}{}.json".format(APIC_URL, uri, mo), cookies=cookie, verify=False)
    logging.info("Reply: {}".format(reply))
    json_reply = json.loads(reply.text)

    return json_reply


@app.route('/testAPI.json')
def hello_world():
    ''' Test the connectivity.
    '''
    logging.info('Received API Request from Client - /')
    return "You have reached the docker container, it\'s alive!"


@app.route('/getTenant.json')
def get_tenant():
    try:
        cookie = requestAppToken()

        reply = getClass('fvTenant', cookie)

        tenants = []

        for tenant in reply['imdata']:
            tenants.append(tenant['fvTenant']['attributes']['name'])

        return json.dumps(tenants)

    except Exception as e:
        import traceback
        logging.info(e)
        logging.info(traceback.format_exc())
        return 'Error: \n{} \n{}'.format(e, traceback.format_exc())


if __name__ == '__main__':
    # Setup logging
    fStr = '%(asctime)s %(levelname)5s %(message)s'
    logging.basicConfig(filename='/home/app/log/server.log', format=fStr, level=logging.DEBUG)

    # Run app flask server
    app.run(host='0.0.0.0', port=80)
