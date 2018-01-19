#Attivo Networks
#Release 4.0MR2
#Author : araina

import sys
import subprocess
from rekall.plugins.windows import common

class ProfileTester(common.WinProcessFilter):
    "Test the profile"

    __name = 'profiletester'

    def collect123(self):
        flag = -1
        counter = 0
        for eprocess in self.filter_processes():
            counter = counter + 1
            if(counter == 5):
                break
        if counter ==5:
            return 0
        else:
            return -1
    
    #def collect(self):
    def render(self,renderer):
        is_live_mode = self.session.HasParameter('live')
        #renderer.section()
        #renderer = self.session.GetRenderer()
        renderer.format("\r\n<==========================profiletester=====================>\r\n")
        renderer.format("\r\n**Valid profiles were not found in Rekall. Please send the following report to Attivo Tech Support**\r\n")
        if is_live_mode:
            renderer.format("\r\nMode : Live\r\n")
        else:
            renderer.format("\r\nMode : Offline\r\n")
        #renderer.format("\r\nDebug Info: \r\n")
        renderer.format("\r\n<======System Information======>\r\n")
        if is_live_mode:
            proc = subprocess.Popen('systeminfo',stdin=subprocess.PIPE,stdout=subprocess.PIPE)
            stdout,stderr = proc.communicate()
            renderer.format(stdout)
        else:
            os_type = self.session.profile.metadata('windows')
            os_version = self.session.profile.metadata('version')
            os_arch = self.session.profile.metadata('arch')
            renderer.format("\r\n OS Type : {0}\r\nOS Version : {1}\r\nOS Arch : {2}\r\n",os_type,os_version,os_arch)
        renderer.format("\r\n<======VersionScan Info======>\r\n")
        vs = self.session.plugins.version_scan(name_regex='ntkr')
        for pdb_info in vs.collect_as_dicts():
            renderer.format("\r\nGUID: {0} PdbName: {1}\r\n",str(pdb_info['guid']),str(pdb_info['pdb']))