#Attivo Networks
#Release : 4.2
#Author: Ashutosh Raina
import pdb
import os

from rekall.plugins.windows import common
from rekall.plugins.windows import filescan
from rekall.plugins import core
from rekall import plugin
from rekall import utils
import yara

class TProcessScanner(common.WinProcessFilter,common.WindowsCommandPlugin):
	"Detect known malicious processes against predefined yara_rules"
	
	__name='procscanner'

	table_header=[
		dict(name='DummyTag',align='l',width=16),
		dict(type="_EPROCESS", name="_EPROCESS"),
		dict(name='Description',align='l')
	]
	
	def __init__(self,*args,**kwargs):
		super(TProcessScanner, self).__init__(*args, **kwargs)
		self.pe_profile = self.session.LoadProfile("pe")
		try:
			self.rule_file=os.path.join(str(self.session.GetParameter('epdatapath')[0]),'rekall_ioc.rules')
		except Exception as e:
			print e
			if len(self.session.GetParameter('epdatapath'))==0:
				print "epdatapath arguement has not been passed to rekall"
				self.rule_file=None

	def WritePEFile(self, fname=None, address_space=None, image_base=None):

		"""
        Source: rekall.plugins.windows.procdump.PEDump.WritePEFile()

        Dumps the PE file found into the filelike object.

        Note that this function can be used for any PE file (e.g. executable,
        dll, driver etc). Only a base address need be specified. This makes this
        plugin useful as a routine in other plugins.

        Args:
          fname: A writable filelike object which must support seeking.
          address_space: The address_space to read from.
          image_base: The offset of the dos file header.
        """

		pedat=""
		dos_header = self.pe_profile._IMAGE_DOS_HEADER(offset=image_base, vm=address_space)
		image_base = dos_header.obj_offset
		nt_header = dos_header.NTHeader
		# First copy the PE file header, then copy the sections.
		data = dos_header.obj_vm.read(image_base, min(1000000, nt_header.OptionalHeader.SizeOfHeaders))

		if not data:
			return

		if not fname:
			pedat=pedat+data
			for section in nt_header.Sections:
				size_of_section = min(10000000,section.SizeOfRawData)
				physical_offset = min(100000000,int(section.PointerToRawData))
				data = section.obj_vm.read(section.VirtualAddress + image_base, size_of_section)
				pedat=pedat+data
			return pedat

	def collect(self):
		if not self.rule_file:
			pass
		elif not os.path.exists(self.rule_file):
			print "Rules file does not exists on ",self.rule_file
		else:
			rules=yara.load(file=open(self.rule_file,'rb'))
			counter=1
			for task in self.filter_processes():
				ep=(int(task))
				task_address_space = task.get_process_address_space()
				bdata=self.WritePEFile(address_space=task_address_space,image_base=task.Peb.ImageBaseAddress)
				matches=rules.match(data=bdata)
				for i in matches:
					tag='rule_matched_'+str(counter)
					counter=counter+1
					yield (tag,task,i.meta['description'])