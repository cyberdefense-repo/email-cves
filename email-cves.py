import requests
import json
import pandas as pd
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import ClientError
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import sys
import io

# NVD resources for this code based on the latest NVD API
# developer api call examples:  https://nvd.nist.gov/developers/vulnerabilities

# function to flatten vulnerabilities column and other deep nested json.
def flatten_json(nested_json: dict, exclude: list=[''], sep: str='_') -> dict:
        out = dict()
        def flatten(x: (list, dict, str), name: str='', exclude=exclude):
                if type(x) is dict:
                        for a in x:
                                if a not in exclude:
                                        flatten(x[a], f'{name}{a}{sep}')
                elif type(x) is list:
                        i = 0
                        for a in x:
                                flatten(a, f'{name}{i}{sep}')
                                i += 1
                else:
                     	out[name[:-1]] = x

        flatten(nested_json)
        return out
# get date lookback working for a 1 hour lookback.
# "message":"Date format should be yyyy-MM-dd'T'HH:mm:ss:SSS Z"
now_date_time = datetime.now()
last_hour_date_time = datetime.now() - timedelta(hours = 1)
last_2hours_date_time = datetime.now() - timedelta(hours = 2)
last_24hours_date_time = datetime.now() - timedelta(hours = 24)
last_7days_date_time = datetime.now() - timedelta(hours = 168)
last_14days_date_time = datetime.now() - timedelta(hours = 336)
last_30days_date_time = datetime.now() - timedelta(days = 30)

# print(last_hour_date_time.strftime('%Y-%m-%d %H:%M:%S'))
now = now_date_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
last2Hours = last_2hours_date_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
lastHour = last_hour_date_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
last24Hours = last_24hours_date_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
last7Days = last_7days_date_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
last2Weeks = last_14days_date_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
last30Days = last_30days_date_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]

# working for pub date range search
# url2 = 'https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=2023-04-14T20:16:55.280&pubEndDate=2023-05-14T20:16:55.280'
# url2 = 'https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev'
# url2 = 'https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=2023-04-14T20:16:55.280&lastModEndDate=2023-05-14T20:16:55.280'

# customized urls for lookback timing of lookback
cve_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/" \
    f"?pubStartDate={lastHour}" \
    f"&pubEndDate={now}" \
    "&noRejected"

# check on general cves that have been release based on time specified in url
cve_resp = requests.get(cve_url)
cves = cve_resp.json()

# list of cve ids
cve_ids = []
for item in cves['vulnerabilities']:
    cve_id = item['cve']['id']
    cve_item = [cve_id]
    cve_ids.append(cve_item)
# print(f"cves from the last 7 days: {cve_ids}")
# print(f"Number of CVES: {len(cve_ids)}")

# check if a public exploit exists in CISA db
cisa_exploit_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/" \
    f"?hasKev&pubStartDate={last7Days}" \
    f"&pubEndDate={now}"
#print(cisa_exploit_url)

cisa_exploit_resp = requests.get(cisa_exploit_url)
cves_exploitable = cisa_exploit_resp.json()

# send hasKev resp to df
df_kev = pd.read_json(io.StringIO(json.dumps(cisa_exploit_resp.json())))
df_kev = pd.DataFrame.from_dict(cves_exploitable['vulnerabilities'])
rowcount = df_kev.shape[0]
#print(df_kev.shape[0])
if rowcount == 0:
    print('No new CVES with Public Exploits')
    df_kev = pd.DataFrame()
    none_df = pd.DataFrame([{'CVE with Exploit':'None','LastModified':'None','Exploit Added':'None','Mitigation Actions':'None','CISA Exploit Name':'None','CISA_URL':'None', 'Product_URL':'None'}])
    df_kev = pd.concat([df_kev, none_df])
    #df_kev.loc[-1] = ['None','None', 'None', 'None','None','None','None']  # adding a row
    df_kev.index = df_kev.index + 1  # shifting index
    df_kev = df_kev.sort_index()  # sorting by index
    #print(df_kev)

else:
    df_kev = df_kev.join(pd.json_normalize(df_kev['cve'])).drop('cve', axis='columns',errors='ignore')

    # flatten, rename, drop columns not required in kev data
    df_kev = df_kev.rename(columns={'id':'CVE with Exploit','lastModified':'LastModified','cisaVulnerabilityName':'CISA Exploit Name','cisaExploitAdd':'Exploit Added','cisaRequiredAction':'Mitigation Actions','references':'related_url'})

    # Create NVD URL for Exploitable CVE's: Bind CVE # to this URL: "https://nvd.nist.gov/vuln/detail/" + CVE-ID and make it available in final email.
    kevids = df_kev['CVE with Exploit']
    burl1 = 'https://nvd.nist.gov/vuln/detail/'
    nvdurl1 = 'https://nvd.nist.gov/general/nvd-dashboard'
    cisa_urls = [burl1 + x for x in kevids]
    df_kev['CISA_URL'] = cisa_urls

    df_kev = df_kev[['CVE with Exploit','LastModified','Exploit Added','Mitigation Actions','CISA Exploit Name','related_url','CISA_URL']]

    # get embedded json in related_url column and merge with df_kev
    df_kevurl = pd.DataFrame([flatten_json(x) for x in df_kev['related_url']])
    #print(df_kevurl)
    df_kev = pd.concat([df_kev,df_kevurl], axis=1)

    # change date format in df_kev
    df_kev['LastModified'] =  df_kev['LastModified'].apply(pd.to_datetime, format='ISO8601')
    df_kev['LastModified'] =  df_kev['LastModified'].dt.date

    # final columns to keep and place in order
    df_kev = df_kev.rename(columns={'0_url': 'Product_URL'})
    df_kev = df_kev[['CVE with Exploit','LastModified','Exploit Added','Mitigation Actions','CISA Exploit Name','CISA_URL','Product_URL']]
    # negate CVE's with exploits after about 7 days by inserting the CVE number.
    df_kev = df_kev[~df_kev['CVE with Exploit'].isin(['CVE-2023-29336'])]

# move data to pandas
df = pd.read_json(io.StringIO(json.dumps(cve_resp.json())))
df = pd.DataFrame.from_dict(cves['vulnerabilities'])
#print(df)

'''
rowcount = df.shape[0]
if rowcount == 0:
    print('No new vulnerable products')
    sys.exit(0)
'''

df_fixed = df.join(pd.json_normalize(df['cve'])).drop('cve',axis='columns')
df_fixed['descriptions'] = df_fixed['descriptions'].replace(to_replace=r'^\[\{\'lang\'\:\s\'en\'\,\s\'value\'\:', value='', regex=True)


# flatten, rename, drop columns not required.
df_products = pd.DataFrame([flatten_json(x) for x in df_fixed['descriptions']])
df_products = df_products.rename(columns={'0_value': 'Software'})
df_products['Software'] = df_products['Software'].replace(to_replace=r'\n', value='', regex=True)
df_products = df_products.drop(columns=['0_lang'])

# flatten, rename, drop.
df_metrics = pd.DataFrame([flatten_json(x) for x in df_fixed['metrics.cvssMetricV31']])
df_metrics = df_metrics.rename(columns={'0_cvssData_baseScore': 'CVSS_Score','0_cvssData_baseSeverity':'Severity','0_exploitabilityScore':'ExploitabilityScore','0_impactScore':'ImpactScore'})
df_metrics = df_metrics[['CVSS_Score','Severity','ExploitabilityScore']]

# flatten, rename, drop columns not required.
df_urls = pd.DataFrame([flatten_json(x) for x in df_fixed['references']])
print(df_urls)
df_urls = df_urls.rename(columns={'0_url': 'Related_URL1'})
df_urls = df_urls[['Related_URL1']]

# Create NVD URL: If there is a CVE of interest bind this string: "https://nvd.nist.gov/vuln/detail/" + CVE-ID and make it available in final email.
cveids = df_fixed['id']
burl = 'https://nvd.nist.gov/vuln/detail/'
nvdurl = 'https://nvd.nist.gov/general/nvd-dashboard'
cve_urls = [burl + x for x in cveids]
df_urls['NVD_URL'] = cve_urls

# merge dfs
df_main = df_fixed[["id","published","lastModified"]].copy()
df_main = df_main.rename(columns={'id': 'CVE-Identification'})

#to_merge = [df_metrics,df_products,df_urls,]
df_email = pd.concat([df_main, df_metrics, df_products, df_urls], axis=1)


# FILTER BASED ON YOUR PRODUCTS!!

search_values = ['microsoft','juniper','chrome','apache','windows','Sophos','Fortigate','tomcat']
df_email = df_email[df_email.Software.str.contains('|'.join(search_values),case=False)]

# change date format
df_email['published'] =  df_email['published'].apply(pd.to_datetime, format='ISO8601')
df_email['lastModified'] =  df_email['lastModified'].apply(pd.to_datetime, format='ISO8601')
#df_email['published'] =  df_email['published'].dt.date
#df_email['lastModified'] =  df_email['lastModified'].dt.date
df_email = df_email.rename(columns={'published': 'Published','lastModified': 'LastModified'})

# rename new NVD URL field to replace the CVE Identification field.
df_email = df_email.rename(columns={'NVD_URL': 'CVE-Description-URL'})
df_email = df_email.drop(columns=['CVE-Identification'])

# final columns to keep and place in order
df_email = df_email[['CVE-Description-URL','Published','LastModified','CVSS_Score','Software','Related_URL1']]

# filter so that we only see CVE's with a V3 CVSS score of 7.5 or greater and apply the AND mask for hourly check
cvsscore = df_email['CVSS_Score'] > 7.4
#dfall = df_email.dropna()
df_email = df_email[cvsscore]

# sort final df
df_email = df_email.sort_values(by=['CVSS_Score'], ascending=False)

# email code
rowcount = df_email.shape[0]
if rowcount == 0:
    print('No new vulnerable products')
    sys.exit(0)
else:
    html1 = df_email.to_html(index=False, justify='left')
    html2 = df_kev.to_html(index=False, justify='left')
    x = [html2, html1]
    html = x[0]+x[1]

    # Start Email Code:
    AWS_REGION = "us-east-1"
        # Replace sender@example.com with your "From" address.
        # This address must be verified with Amazon SES.
    SENDER = "NVD CVE Notification <yourhandle@youremail.com>"

        # The subject line for the email.
    SUBJECT = "New CVE's Threat Intelligence Email - National Vulnerability Database (NVD)"

# The email body for recipients with non-HTML email clients.
    BODY_TEXT = "Hello,\r\nPlease Read."

# The HTML body of the email.
        #add back in the 3 double quotes around the HTML!
    BODY_HTML = html

    CHARSET = "UTF-8"

# Create a new SES resource and specify a region.
    client = boto3.client('ses',region_name=AWS_REGION)
# Try to send the email.
    try:
    #Provide the contents of the email.
        response = client.send_email(
            Destination={
                'ToAddresses': [
                    'engineer1@company.com','analyst1@company.com'
],
                'BccAddresses': ['copyyourprivatemail@gmail.com']
	},
	Message={
            'Body': {
                'Html': {
                    'Charset': CHARSET,
                    'Data': BODY_HTML,
                },
                'Text': {
                    'Charset': CHARSET,
                    'Data': BODY_TEXT,
                },
            },
            'Subject': {
                'Charset': CHARSET,
                'Data': SUBJECT,
            },
	},
	Source=SENDER,

    )
# Display an error if something goes wrong.
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
	    print("Email sent! Message ID:")
