import requests
import streamlit as st
import pandas as pd
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
from requests.packages.urllib3.util.ssl_ import create_urllib3_context

# Constants
CIPHERS = 'ALL:@SECLEVEL=1'
USERNAME = "nsroot"
PASSWORD = ""
DEFAULT_TIMEOUT = 5

DEVICES = [
    {"name": "ns1", "ip": ""}
]

METRICS = [
    "mgmtcpuusagepcnt", "pktcpuusagepcnt", "memusagepcnt", "rxmbitsrate", "txmbitsrate",
    "httprequestsrate", "httpresponsesrate", "httprxrequestbytesrate", "httprxresponsebytesrate",
    "tcpcurclientconn", "tcpcurserverconn", "tcpcurclientconnestablished", "tcpcurserverconnestablished",
    "ssltransactionsrate", "sslsessionhitsrate", "cachehitsrate", "cachetothits", "disk0perusage",
    "disk1perusage", "powersupply1status", "powersupply2status", "cpufan0speed", "systemfanspeed",
    "cpu0temp", "internaltemp"
]


class SSLAdapter(HTTPAdapter):
    """Custom SSL Adapter to handle insecure SSL connections."""
    def __init__(self, *args, **kwargs):
        self.ciphers = kwargs.pop('ciphers', CIPHERS)
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=self.ciphers)
        context.check_hostname = False
        context.verify_mode = False
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)


class CitrixADCSession:
    """A session manager for Citrix ADC."""
    def __init__(self, username, password):
        self.session = requests.Session()
        self.session.mount('https://', SSLAdapter())
        self.headers = {
            'X-NITRO-USER': username,
            'X-NITRO-PASS': password
        }

    def fetch_data(self, ip, endpoint):
        """
        Generic method to fetch data from Citrix ADC.
        """
        url = f"https://{ip}/nitro/v1/config/{endpoint}"
        try:
            response = self.session.get(url, headers=self.headers, verify=False, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            st.error(f"Error fetching data from {ip} ({endpoint}): {e}")
            return {}

    def fetch_stats(self, ip, items):
        """
        Fetches statistics from the Citrix ADC for specified metrics.
        """
        stats = {}
        for item in items:
            url = f"https://{ip}/nitro/v1/stat/{item}"
            try:
                response = self.session.get(url, headers=self.headers, verify=False, timeout=DEFAULT_TIMEOUT)
                response.raise_for_status()
                data = response.json()
                stats.update(data.get(item, {}))
            except requests.exceptions.RequestException as e:
                st.error(f"Error fetching stats from {ip} ({item}): {e}")
        return stats

    def fetch_lbvservers(self, ip):
        """
        Fetch LB vServer information.
        """
        return self.fetch_data(ip, "lbvserver").get('lbvserver', [])

    def fetch_gateway_vservers(self, ip):
        """
        Fetch Citrix Gateway vServer information.
        """
        return self.fetch_data(ip, "vpnvserver").get('vpnvserver', [])

    def fetch_license_info(self, ip):
        """
        Fetch ADC license information.
        """
        return self.fetch_data(ip, "nslicense").get('nslicense', {})

    def fetch_ssl_certificates(self, ip):
        """
        Fetch SSL certificate information.
        """
        return self.fetch_data(ip, "sslcertkey").get('sslcertkey', [])


def create_vserver_dataframe(vservers):
    """
    Converts vServer data into a pandas DataFrame.
    """
    data = {
        "Name": [],
        "IP": [],
        "Port": [],
        "State": [],
        "Protocol": []
    }

    for vserver in vservers:
        data["Name"].append(vserver.get("name", "N/A"))
        data["IP"].append(vserver.get("ipv46", "N/A"))
        data["Port"].append(vserver.get("port", "N/A"))
        data["State"].append(vserver.get("curstate", "N/A"))
        data["Protocol"].append(vserver.get("servicetype", "N/A"))

    return pd.DataFrame(data)


def create_metrics_dataframe(stats, metrics):
    """
    Converts metrics statistics into a pandas DataFrame.
    """
    data = {
        "Metric": [],
        "Value": []
    }

    for metric in metrics:
        if metric in stats:
            data["Metric"].append(metric)
            data["Value"].append(stats[metric])

    return pd.DataFrame(data)


def create_license_dataframe(licenses):
    """
    Converts license data into a pandas DataFrame.
    Displays only 'Days to Expiration'.
    """
    data = {
        "Days to Expiration": []
    }

    if "daystoexpiration" in licenses:
        data["Days to Expiration"].append(licenses.get("daystoexpiration", "N/A"))

    return pd.DataFrame(data)


def create_ssl_cert_dataframe(certificates):
    """
    Converts SSL certificate data into a pandas DataFrame.
    Filters only certificates expiring in less than 365 days.
    """
    data = {
        "Name": [],
        "Issuer": [],
        "Days to Expire": []
    }

    for cert in certificates:
        days_to_expire = cert.get("daystoexpiration", 9999)
        if days_to_expire < 365:  # Only include certificates expiring in less than 365 days
            data["Name"].append(cert.get("certkey", "N/A"))
            data["Issuer"].append(cert.get("issuer", "N/A"))
            data["Days to Expire"].append(days_to_expire)

    return pd.DataFrame(data)


def render_dashboard(devices, session, metrics):
    """
    Renders the Streamlit dashboard with fetched data.
    """
    st.set_page_config(page_title="Citrix ADC Dashboard", page_icon="📊")
    st.title("Citrix ADC Status Dashboard")

    for device in devices:
        ip = device["ip"]
        st.subheader(f"{device['name']} - {ip}")

        # Fetch and display metrics
        stats = session.fetch_stats(ip, ["ns", "system"])
        metrics_df = create_metrics_dataframe(stats, metrics)
        st.table(metrics_df)

        # Fetch and display LB vServers
        lbvservers = session.fetch_lbvservers(ip)
        lbvserver_df = create_vserver_dataframe(lbvservers)

        st.subheader("LB vServer Details")
        st.table(lbvserver_df)

        # Fetch and display Gateway vServers
        gateway_vservers = session.fetch_gateway_vservers(ip)
        gateway_vserver_df = create_vserver_dataframe(gateway_vservers)

        st.subheader("Citrix Gateway vServer Details")
        st.table(gateway_vserver_df)

        # Fetch and display license expiration
        licenses = session.fetch_license_info(ip)
        license_df = create_license_dataframe(licenses)

        st.subheader("License Expiration Days")
        st.table(license_df)

        # Fetch and display SSL certificate information
        certificates = session.fetch_ssl_certificates(ip)
        ssl_cert_df = create_ssl_cert_dataframe(certificates)

        st.subheader("SSL Certificates (Expiring in < 365 Days)")
        st.table(ssl_cert_df)


def main():
    session = CitrixADCSession(USERNAME, PASSWORD)
    render_dashboard(DEVICES, session, METRICS)


if __name__ == "__main__":
    main()
