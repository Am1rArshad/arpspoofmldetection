import requests

def check_ip_abuse(ip, api_key):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()['data']
            return {
                'ip': ip,
                'abuseConfidenceScore': data['abuseConfidenceScore'],
                'countryCode': data.get('countryCode'),
                'usageType': data.get('usageType'),
                'domain': data.get('domain'),
                'totalReports': data.get('totalReports'),
                'lastReportedAt': data.get('lastReportedAt')
            }
        else:
            return {'ip': ip, 'error': f'HTTP {response.status_code}: {response.text}'}
    except Exception as e:
        return {'ip': ip, 'error': str(e)} 