import requests
import json
import pandas as pd
from datetime import datetime, timedelta
import numpy as np
import boto3
from botocore.exceptions import ClientError
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import sys

# NVD resources for this code.
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

# Normal CVE Check
# customized urls for lookback time frames
cve_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/" \
    f"?pubStartDate={last2Hours}" \
    f"&pubEndDate={now}"

# check general cves that have been release based on time specified in url (default = 4 hours)
cve_resp = requests.get(cve_url)
cves = cve_resp.json()

# list of cve ids
cve_ids = []
for item in cves['vulnerabilities']:
    cve_id = item['cve']['id']
    cve_item = [cve_id]
    cve_ids.append(cve_item)

# Check normal CVE's for public exploits publiched by CISA 
# https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
cisa_exploit_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
cisa_exploit_resp = requests.get(cisa_exploit_url)
cves_exploitable = cisa_exploit_resp.json()

# additional url's to place in the email for manual checking of exploits in the wild
url1 = "https://sploitus.com/"
url2 = "https://www.exploit-db.com/"
url3 = "https://www.google.com/search?q=site%253Agithub.com+cve+poc"
url4 = "https://0day.today/"
url5 = "https://cxsecurity.com/search/"

df_kev_urls = pd.DataFrame()
df_kev_urls = pd.DataFrame([{"Additional Exploit Intel Sources": url1}])
df_kev_urls.loc[len(df_kev_urls)] = [url2]
df_kev_urls.loc[len(df_kev_urls)] = [url3]
df_kev_urls.loc[len(df_kev_urls)] = [url4]
df_kev_urls.loc[len(df_kev_urls)] = [url5]

# get cves with exploits from CISA
cisa_exploit_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
cisa_exploit_resp = requests.get(cisa_exploit_url)
cves_exploitable = cisa_exploit_resp.json()

# create a pandas df
df_kev = pd.DataFrame.from_dict(cves_exploitable)
df_kev = pd.DataFrame([flatten_json(x) for x in df_kev['vulnerabilities']])
df_kev = df_kev.rename(columns={'dateAdded':'DateAdded','cveID':'CVEID','vendorProject':'Vendor','vulnerabilityName':'ExploitedVul','shortDescription':'Description','requiredAction':'Mitigation Actions','notes':'URL'})
df_kev = df_kev.loc[(df_kev['DateAdded'] >= last7Days)]
neworder = ['DateAdded','CVEID','Vendor','ExploitedVul','Description','Mitigation Actions','URL']
df_kev=df_kev.reindex(columns=neworder)
df_kev.to_csv('df_kevs.csv')

# check if there are CVE's with Exploits within the last 7 days.
if df_kev.empty == True:
    print('No new CVES with Public Exploits')
    df_kev = pd.DataFrame()
    none_df = pd.DataFrame([{'DateAdded':'None','CVEID':'None','Vendor':'None','ExploitedVul':'None','Description':'None','Mitigation Actions':'None','URL':'None'}])
    df_kev_filtered = pd.concat([df_kev, none_df])
    
elif df_kev.empty == False:
    df_kev_filtered = df_kev[['DateAdded','CVEID','Vendor','Mitigation Actions','ExploitedVul','URL']]
    df_kev_filtered.to_csv('df_kevs.csv')

# move data to pandas
df = pd.read_json(json.dumps(cve_resp.json()))
df = pd.DataFrame.from_dict(cves['vulnerabilities'])

if df.empty == True:
    print('No new CVES Published by the NVD')


elif df.empty == False:
      
    #if a new CVE has been published in the last 2 hours 
    df_fixed = df.join(pd.json_normalize(df['cve'])).drop('cve',axis='columns')
    # get vulnerability data from description column wrapped in embedded json

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

    # filter based on product/software name
    search_values = ['adobe','cold fusion','okta','keepass','splunk','BIG-IP','F5','Red Hat','confluence','jira','openssl','atlassian','jre','jdk','chrome','firefox','git','gitlab']
    df_email = df_email[df_email.Software.str.contains('|'.join(search_values),case=False)]

    # change date format
    df_email['published'] =  df_email['published'].apply(pd.to_datetime)
    df_email['lastModified'] =  df_email['lastModified'].apply(pd.to_datetime)
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
        html1 = df_email.to_html(index=False, justify='left',render_links=True)
        html1b = df_kev_urls.to_html(index=False, justify='left',render_links=True)
        html2 = df_kev_filtered.to_html(index=False, justify='left',render_links=True)
        x = [html2, html1b, html1]
        html = x[0]+' '+x[1]+' '+x[2]

        # Start Email Code:
        AWS_REGION = "us-east-1"
            # Replace sender@example.com with your "From" address.
            # This address must be verified with Amazon SES.
        SENDER = "SMX Threat Analytics Team (STAT) <smxthreat@smartronix.com>"

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
                    'ToAddresses':  ['brianequick@protonmail.com']
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