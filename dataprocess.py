import pandas as pd
import json
import miscfunc as mf


def getdata():
    data = []
    with open('honeypot.json') as f:
        for line in f:
            data.append(json.loads(line))

    glastopf = []
    amun = []
    for i in range(len(data)):
        temp = []
        j = json.dumps(data[i])
        load_j = json.loads(j)
        temp.append(load_j['_id']['$oid'])
        temp.append(load_j['ident'])
        temp.append(load_j['normalized'])
        temp.append(load_j['timestamp']['$date'])
        temp.append(load_j['channel'])
        if load_j['channel'] == 'glastopf.events':
            payload = json.loads(load_j['payload'])
            temp.append(payload['pattern'])
            temp.append(payload['filename'])
            temp.append(payload['request_raw'])
            temp.append(payload['request_url'])
            temp.append(payload['source'][0])
            temp.append(payload['source'][1])
            glastopf.append(temp)
        elif load_j['channel'] == 'amun.events':
            payload = json.loads(load_j['payload'])
            temp.append(payload['attackerIP'])
            temp.append(payload['attackerPort'])
            temp.append(payload['victimIP'])
            temp.append(payload['victimPort'])
            temp.append(payload['connectionType'])
            amun.append(temp)

    amun_df = pd.DataFrame(amun, columns=['id', 'ident', 'normalized', 'timestamp', 'channel', 'attackerIP',
                                          'attackerPort', 'victimIP', 'victimPort', 'connectionType'])
    glastopf_df = pd.DataFrame(glastopf, columns=['id', 'ident', 'normalized', 'timestamp', 'channel', 'pattern',
                                                  'filename', 'request_raw', 'request_url', 'attackerIP', 'attackerPort'])

    amun_df['timestamp'] = amun_df['timestamp'].apply(lambda x: str(x).replace('T', 'T '))
    glastopf_df['timestamp'] = glastopf_df['timestamp'].apply(lambda x: str(x).replace('T', 'T '))

    amun_df['timestamp'] = pd.to_datetime(amun_df['timestamp'])
    glastopf_df['timestamp'] = pd.to_datetime(glastopf_df['timestamp'])

    amun_df['attackerCountry'] = amun_df['attackerIP'].apply(lambda x: mf.countryiso(x))
    glastopf_df['attackerCountry'] = glastopf_df['attackerIP'].apply(lambda x: mf.countryiso(x))

    amun_df['Longitude'] = amun_df['attackerIP'].apply(lambda x: mf.iplong(x))
    glastopf_df['Longitude'] = glastopf_df['attackerIP'].apply(lambda x: mf.iplong(x))

    amun_df['Latitude'] = amun_df['attackerIP'].apply(lambda x: mf.iplat(x))
    glastopf_df['Latitude'] = glastopf_df['attackerIP'].apply(lambda x: mf.iplat(x))

    glastopf_df['victimPort'] = 80
    glastopf_df['victimIP'] = 0
    glastopf_df['victimIP'] = glastopf_df.ident.apply\
        (lambda x: '111.111.111.111' if x == 'a16f5f36-3c41-11e4-9ee4-0a0b6e7c3e9e' else '222.222.222.222')
    amun_df['victimIP'] = amun_df.ident.apply\
        (lambda x: '333.333.333.333' if x == 'eb030eb8-3c69-11e4-9ee4-0a0b6e7c3e9e' else '444.444.444.444')

    amun_df.to_csv('amun.csv', index=False)
    glastopf_df.to_csv('glas.csv', index=False)
