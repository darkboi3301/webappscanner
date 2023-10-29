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
	# print nmap csv output into a trealit dataframe
	df = pd.read_csv(StringIO(scanner.csv()), index_col=0, sep=";")
	#scanner.scan(scanned_ip, '1-1024')
	#st.write(scanner.traceroute())
	st.dataframe(df,use_container_width=True)
	#perform a os detection scan on the target
	#st.write(scanner.scan(scanned_ip, arguments='-sV T4 '))
	



def getopenports(scanned_ip):
	opports=""
	for port in range(1,100):
		soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		socket.setdefaulttimeout(1)
		result = soc.connect_ex((scanned_ip,port))
		if result ==0:
			print("Port {} is open".format(port))
			st.write(port,' is open, Saving for in depth scan')
			opports = opports + str(port) + ',' 
		else:
			print(port,' is closed/unavailable')
		soc.close()
	return opports
	

if st.button("Scan"):
	scanned_ip = ConvertToIP(scan_ip)
	portsopen=getopenports(scanned_ip)
	st.subheader("Open Ports")
	print(str(portsopen))
	st.write(portsopen)
	PortScannerOS(scanned_ip,portsopen)

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