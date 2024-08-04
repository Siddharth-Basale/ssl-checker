import ssl
import socket
from datetime import datetime
import streamlit as st
import pandas as pd
import altair as alt


def get_cert_info(host):
    context = ssl.create_default_context()
    with socket.create_connection((host, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            expiry_str = cert['notAfter']
            expiry = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
            issuer = dict(x[0] for x in cert['issuer'])
            issuer_name = issuer.get('organizationName', 'Unknown Issuer')
            return expiry, issuer_name


def check_expiry(hosts):
    results = []
    for host in hosts:
        try:
            expiry, issuer_name = get_cert_info(host)
            now = datetime.now()
            days_left = (expiry - now).days
            if days_left < 0:
                status = "Expired"
            elif days_left < 30:
                status = "Expiring Soon"
            else:
                status = "Valid"
            results.append((host, days_left, status, issuer_name))
        except Exception as e:
            results.append((host, None, f"Error: {str(e)}", "Unknown Issuer"))
    return results


def main():
    st.set_page_config(page_title="SSL Checker", page_icon="🔒", layout="wide")
    st.title("🔒 SSL Certificate Expiry Checker")
    st.markdown(
        """
        <style>
        .reportview-container {
            background: linear-gradient(to bottom right, #f8f9fa, #e9ecef);
        }
        .css-1d391kg p {
            color: #333;
            font-size: 18px;
            font-weight: 500;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        "Check if your website's SSL certificate is about to expire. Stay secure by renewing certificates on time!"
    )

    with st.expander("ℹ️ Instructions"):
        st.write(
            "Enter the hostnames of the websites you want to check, one per line. Click 'Check Expiry' to see the results."
        )

    host_input = st.text_area(
        "Enter hostnames (one per line):",
        "google.com\nredbus.com\nfacebook.com\nudemy.com\nstreamlit.io",
    )

    if st.button("Check Expiry"):
        hosts = host_input.strip().split("\n")
        progress = st.progress(0)
        results = []

        for i, host in enumerate(hosts):
            results.extend(check_expiry([host]))
            progress.progress((i + 1) / len(hosts))

        st.subheader("Results")
        df = pd.DataFrame(
            results, columns=["Hostname", "Days Until Expiry", "Status", "Issuer"]
        )
        st.table(df)

        st.markdown("### Expiry Status Chart")
        chart = alt.Chart(df).mark_bar().encode(
            x="Hostname",
            y="Days Until Expiry",
            color=alt.Color(
                "Status",
                scale=alt.Scale(
                    domain=["Expired", "Expiring Soon", "Valid"],
                    range=["#dc3545", "#ffc107", "#28a745"],
                ),
            ),
            tooltip=["Hostname", "Days Until Expiry", "Status", "Issuer"],
        ).properties(width=700, height=400)

        st.altair_chart(chart, use_container_width=True)

        st.markdown("### Alerts")
        for host, days_left, status, issuer in results:
            if status == "Expired":
                st.error(f"❌ {host} has expired {abs(days_left)} days ago. Issuer: {issuer}")
            elif status == "Expiring Soon":
                st.warning(f"⚠️ {host} is expiring in {days_left} days. Issuer: {issuer}")
            else:
                st.success(f"✅ {host} is valid for {days_left} more days. Issuer: {issuer}")


if __name__ == "__main__":
    main()
