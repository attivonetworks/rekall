#Attivo based plugin imports
import os

from rekall.plugins.windows.attivo import procscan
if str(os.name)=='nt':
	from rekall.plugins.windows.attivo import netscan_new
from rekall.plugins.windows.attivo import officescanner
from rekall.plugins.windows.attivo import testprofile
