from rekall.plugins.windows import common
from ctypes import *
from ctypes.wintypes import *
from socket import  inet_aton,inet_ntoa,htons
from psutil import Process

#CONSTANT DEFINITIONS - #define equivalent
AF_INET=2

#TCP STATES 
TCP_TABLE_BASIC_LISTENER = 0
TCP_TABLE_BASIC_CONNECTIONS = 1
TCP_TABLE_BASIC_ALL = 2
TCP_TABLE_OWNER_PID_LISTENER = 3
TCP_TABLE_OWNER_PID_CONNECTIONS = 4
TCP_TABLE_OWNER_PID_ALL = 5
TCP_TABLE_OWNER_MODULE_LISTENER = 6
TCP_TABLE_OWNER_MODULE_CONNECTIONS = 7
TCP_TABLE_OWNER_MODULE_ALL = 8

#UDP STATES
UDP_TABLE_BASIC=0
UDP_TABLE_OWNER_PID=1
UDP_TABLE_OWNER_MODULE=2

states = {
	1 : "CLOSED",
	2 : "LISTENING",
	3 : "SYN_SENT",
	4 : "SYN_RCVD",
	5 : "ESTABLISHED",
	6 : "FIN_WAIT",
	7 : "FIN_WAIT2",
	8 : "CLOSE_WAIT",
	9 : "CLOSING",
	10 : "LAST_ACK",
	11 : "TIME_WAIT",
	12 : "DELETE_TCB",

	"CLOSED" : 1,
	"LISTENING" : 2,
	"SYN_SENT" : 3,
	"SYN_RCVD" : 4,
	"ESTABLISHED" : 5,
	"FIN_WAIT" : 6,
	"FIN_WAIT2" : 7,
	"CLOSE_WAIT" : 8,
	"CLOSING" : 9,
	"LAST_ACK" :10,
	"TIME_WAIT" : 11,
	"DELETE_TCB" : 12 }

_GetExtendedTcpTable = windll.iphlpapi.GetExtendedTcpTable
_GetExtendedUdpTable = windll.iphlpapi.GetExtendedUdpTable
#basic socket class object for yielding purposes
class socket_info:

	State = None
	LocalAddr = None
	LocalPort = None
	RemoteAddr = None
	RemotePort = None

	def __init__ (self, **kwargs):
		for key, word in kwargs.items():
			setattr(self, key, word)

def formatip (ip):
	ip = inet_aton (str(ip))
	return inet_ntoa (ip[::-1])

class MIB_TCPROW_OWNER_PID(Structure):
	_fields_ = [
		("dwState", DWORD),
		("dwLocalAddr", DWORD),
		("dwLocalPort", DWORD),
		("dwRemoteAddr", DWORD),
		("dwRemotePort", DWORD),
		("dwOwningPid", DWORD)
		]

class MIB_TCPTABLE_OWNER_PID(Structure):
	_fields_ = [
		("dwNumEntries", DWORD),
		("MIB_TCPROW_OWNER_PID", MIB_TCPROW_OWNER_PID * 0)
		]

class MIB_UDPROW_OWNER_PID(Structure):
	_fields_ = [
		("dwLocalAddr", DWORD),
		("dwLocalPort", DWORD),
		("dwOwningPid", DWORD)
		]

class MIB_UDPTABLE_OWNER_PID(Structure):
	_fields_ = [
		("dwNumEntries", DWORD),
		("MIB_UDPROW_OWNER_PID", MIB_UDPROW_OWNER_PID * 0)
		]



class NetScanNew(common.WinProcessFilter):
	__name='netscan_new'

	table_header = [
		#dict(name="offset", style="address"),
		dict(name="protocol", width=8),
		dict(name="local_addr", width=20),
		dict(name="remote_addr", width=30),
		dict(name="state", width=16),
		dict(name="pid", width=5, align="r"),
		dict(name="owner")
		#dict(name="created")
	]

	def validateversion(self):
		current_version=float(self.session.profile.metadata('version'))
		if current_version < 6.1:
			return False
		else:
			return True
	def getnamefrompid(self,pid):
		p_obj=Process(pid)
		return p_obj.name()

	def validatemode(self):
		return self.session.HasParameter('live')

	def GetExtendedUdpTable(self,vip=AF_INET):
		table=MIB_UDPTABLE_OWNER_PID()
		size = DWORD ()
		order = 1
		failure= _GetExtendedUdpTable (byref (table),byref (size),order,vip,UDP_TABLE_OWNER_PID,0)

		if failure == 122:
			resize(table, size.value)
			memset(byref(table), 0, sizeof(table))
			failure = _GetExtendedUdpTable(byref(table),byref(size),order,vip,UDP_TABLE_OWNER_PID,0)

		if failure: raise WinError(failure)

		ptr_type = POINTER(MIB_UDPROW_OWNER_PID * table.dwNumEntries)
		tables = cast(table.MIB_UDPROW_OWNER_PID, ptr_type)[0]

		pytables=[]
		for table in tables:
			try:
				pytables.append(socket_info(
					LocalAddr=formatip (table.dwLocalAddr),
					LocalPort=htons(table.dwLocalPort),
					OwningPid = int (table.dwOwningPid)))
			except OverflowError as oe:
				print "Overflow Error Occured in GetExtendedUdpTable"
		return pytables

	def GetExtendedTcpTable(self,vip=AF_INET):
		table=MIB_TCPTABLE_OWNER_PID()
		size = DWORD ()
		order = 1
		failure= _GetExtendedTcpTable (byref (table),byref (size),order,vip,TCP_TABLE_OWNER_PID_ALL,0)

		if failure == 122:
			resize(table, size.value)
			memset(byref(table), 0, sizeof(table))
			failure = _GetExtendedTcpTable(byref(table),byref(size),order,vip,TCP_TABLE_OWNER_PID_ALL,0)

		if failure: raise WinError(failure)

		ptr_type = POINTER(MIB_TCPROW_OWNER_PID * table.dwNumEntries)
		tables = cast(table.MIB_TCPROW_OWNER_PID, ptr_type)[0];

		pytables=[]
		for table in tables:
			try:
				pytables.append(socket_info(
					State=states.get (table.dwState, "UNKNOWN_STATE_%s" %(str(table.dwState))),
					LocalAddr=formatip (table.dwLocalAddr),
					LocalPort=htons(table.dwLocalPort),
					RemoteAddr=formatip (table.dwRemoteAddr),
					RemotePort=htons(table.dwRemotePort),
					OwningPid = int (table.dwOwningPid)))
			except OverflowError as oe:
				print "Overflow Error Occured in GetExtendedTcpTable"
			#pytables.append(socket_info(LocalAddr=formatip (table.dwLocalAddr),LocalPort=htons(table.dwLocalPort),OwningPid = int (table.dwOwningPid)))
		return pytables


	def collect(self):
		if self.validateversion() and self.validatemode():
			#first yeild all tcp connections
			tcp_info=self.GetExtendedTcpTable()
			for item in tcp_info:
				local_addr=str(item.LocalAddr)+':'+str(item.LocalPort)
				remote_addr=str(item.RemoteAddr)+':'+str(item.RemotePort)
				yield('TCPv4',local_addr,remote_addr,item.State,item.OwningPid,self.getnamefrompid(item.OwningPid))
			udp_info=self.GetExtendedUdpTable()
			for item in udp_info:
				local_addr=str(item.LocalAddr)+':'+str(item.LocalPort)
				yield('UDPv4',local_addr,'*:*','',item.OwningPid,self.getnamefrompid(item.OwningPid))


