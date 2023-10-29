#import sockets
import socket
import pandas as pd
import streamlit as st
import nmap	
from io import StringIO 

st.set_page_config(
    page_title="WARP",
    page_icon="🚀",
    initial_sidebar_state="auto",
	layout="wide")
st.markdown(
    """
    <style>
    .reportview-container {
        background: url("https://images.app.goo.gl/LFCobouKtT7oZ7Qv7")
    }
   .sidebar .sidebar-content {
        background: url("https://images.app.goo.gl/LFCobouKtT7oZ7Qv7")
    }
    </style>
    """,
    unsafe_allow_html=True
)


#st.title("WARP Scanner")
st.markdown("<h1 style='text-align: center; color: Black;font-size: 50px'>WARP Scanner</h1>", unsafe_allow_html=True)
st.subheader("Input IP address or Domain ")
scan_ip = st.text_input('example: 8.8.8.8 or scanme.nmap.org', 'scanme.nmap.org')



def ConvertToIP(scan_ip):
	try:
		ip = socket.gethostbyname(scan_ip)
		return ip
	except socket.gaierror:
		st.write("Invalid Domain")
		return "Invalid Domain"
	

def PortScannerOS(scanned_ip,portsopen):
	scanner = nmap.PortScanner()
	scanner.scan(scanned_ip, arguments='-O -T4 -p' + portsopen)
	for i in scanner.all_hosts():
		if scanner[i].state() == 'up':
			st.write(f"Host: {i} ({scanner[i].hostname()})")
			st.write(f"State: {scanner[i].state()}")
			for protocols in scanner[i].all_protocols():
				st.write(f"Protocol: {protocols}")
				lport = scanner[i][protocols].keys()
				for port in lport:
					st.write(f"Port: {port} \t State: {scanner[i][protocols][port]['state']}")
	df = pd.read_csv(StringIO(scanner.csv()), index_col=0, sep=";")
	st.dataframe(df,use_container_width=True)

def PortScannerSV(scanned_ip,portsopen):
	scanner = nmap.PortScanner()
	scanner.scan(scanned_ip, arguments='-sV -T4 -p' + portsopen)
	for i in scanner.all_hosts():
		if scanner[i].state() == 'up':
			st.write(f"Host: {i} ({scanner[i].hostname()})")
			st.write(f"State: {scanner[i].state()}")
			for protocols in scanner[i].all_protocols():
				st.write(f"Protocol: {protocols}")
				lport = scanner[i][protocols].keys()
				for port in lport:
					st.write(f"Port: {port} \t State: {scanner[i][protocols][port]['state']}")
	df = pd.read_csv(StringIO(scanner.csv()), index_col=0, sep=";")
	st.dataframe(df,use_container_width=True)

	



def getopenports(scanned_ip):
	opports=""
	for port in range(1,100):
		soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		socket.setdefaulttimeout(2)
		result = soc.connect_ex((scanned_ip,port))
		if result ==0:
			print("Port {} is open".format(port))
			st.write(port,' is open, Saving for in depth scan')
			opports = opports + str(port) + ',' 
		else:
			print(port,' is closed/unavailable')
		soc.close()
	return opports
	

if st.button("OS Scan"):
	scanned_ip = ConvertToIP(scan_ip)
	portsopen=getopenports(scanned_ip)
	st.subheader("Open Ports")
	print(str(portsopen))
	st.write(portsopen)
	PortScannerOS(scanned_ip,portsopen)

if st.button("SV Scan"):
	scanned_ip = ConvertToIP(scan_ip)
	portsopen=getopenports(scanned_ip)
	st.subheader("Open Ports")
	print(str(portsopen))
	st.write(portsopen)
	PortScannerSV(scanned_ip,portsopen)

st.markdown(
    """
    <style>
		footer {
            visibility: hidden;
        }
    </style>
    """,
    unsafe_allow_html=True,
)
