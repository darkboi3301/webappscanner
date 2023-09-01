#import sockets
import socket
import pandas as pd
import streamlit as st
import nmap	
from io import StringIO 

st.set_page_config(
    page_title="WARP",
    page_icon="🚀",
    layout="centered",
    initial_sidebar_state="auto",
)

#st.title("WARP Scanner")
st.markdown("<h1 style='text-align: center; color: white;font-size: 50px'>WARP Scanner</h1>", unsafe_allow_html=True)
st.subheader("Input IP address or Domain ")
scan_ip = st.text_input('example: 8.8.8.8 or scanme.nmap.org', 'Enter Domain/IP here')



def ConvertToIP(scan_ip):
	try:
		ip = socket.gethostbyname(scan_ip)
		return ip
	except socket.gaierror:
		st.write("Invalid Domain")
		return "Invalid Domain"
	
scanned_ip = ConvertToIP(scan_ip)

def PortScanner(scanned_ip):
	scanner = nmap.PortScanner()
	scanner.scan(scanned_ip, '1-1024', "-sV T4 --script=vuln")
	for i in scanner.all_hosts():
		if scanner[i].state() == 'up':
			st.write(f"Host: {i} ({scanner[i].hostname()})")
			st.write(f"State: {scanner[i].state()}")
			for proto in scanner[i].all_protocols():
				st.write(f"Protocol: {proto}")
				lport = scanner[i][proto].keys()
				for port in lport:
					st.write(f"Port: {port} \t State: {scanner[i][proto][port]['state']}")
	# print nmap csv output into a trealit dataframe
	df = pd.read_csv(StringIO(scanner.csv()), index_col=0, sep=";")
	#scanner.scan(scanned_ip, '1-1024')
	st.dataframe(df)
	#st.write(scanner.traceroute())
	#perform a os detection scan on the target
	st.write(scanner.scan(scanned_ip, arguments='-sV T4 --script=vuln'))
	


if st.button("Scan"):
	with st.spinner('Running'):
		st.write(PortScanner(scanned_ip))

st.markdown(
    """
    <style>
		background-color: #000000;
        footer {
            visibility: hidden;
        }
    </style>
    """,
    unsafe_allow_html=True,
)