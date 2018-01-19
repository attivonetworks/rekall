#Attivo Networks
#Release 4.1
#Author : Ashutosh Raina

whitelist_json = '''{"process":[{"name":"conhost.exe","filepath":"<windir>\\\\System32\\\\conhost.exe","notparent":["winword.exe","excel.exe","powerpnt.exe"]}]}'''

from rekall.plugins.windows import common
from rekall.plugins.windows import filescan
from rekall.plugins import core
from rekall import plugin
from rekall import utils
import json

class OfficeScanner(common.WinProcessFilter):
    "Detect any suspicious process launched from office applications"

    __name = 'officescanner'
    
    def __init__(self,*args,**kwargs):
        super(OfficeScanner,self).__init__(*args,**kwargs)
        self.setEnvDict()
        self.whiteListArray=[]
        try:
            wl = whitelist_json
            self.whiteListArray = json.loads(wl)['process']
        except Exception as e:
            print e
            self.whiteListArray = None

    table_header = [
        dict(name="",cname="divider",type = "Divider"),
        dict(name="DummyTag",cname="dummy",width=8),
        dict(name="Process",cname="process",width=25),
        dict(name="PPID",cname="ppid",width=6),
        dict(name="Full Path",cname="fullpath",width = 60),
        dict(name="Command Line",cname="cmdline")
    ]

    def replaceEnvVarWithValue(self,inputstr):
        outputstr = inputstr
        if ("windir" in inputstr):
            pass
        while True:
            index_1 = outputstr.find('<')
            index_2 = outputstr.find('>')
            if not ((index_1+1) and (index_2+1)):
                return outputstr
            l_string = outputstr[:index_1]
            r_string = outputstr[index_2+1:]
            env_var = outputstr[index_1+1:index_2]
            try:
                outputstr = l_string + self.envvardict[env_var] + r_string
            except KeyError:
                outputstr = l_string + '<' + env_var + '>' + r_string
        
    def setEnvDict(self):
        self.envvardict={}
        for task in self.filter_processes():
            if (str(task.ImageFileName).lower() == "explorer.exe" and str((self.get_eprocess_by_pid(task.InheritedFromUniqueProcessId)).ImageFileName).lower() == "userinit.exe"):
                for line in task.Peb.ProcessParameters.Environment:
                    line = str(line)
                    index = line.find('=')
                    envvar = line[:index]
                    envval = line[index+1:]
                    self.envvardict[envvar] = envval 

    def get_eprocess_by_pid(self,pid):
        for task in self.filter_processes():
            if task.pid == pid:
                return task
        return None

    def whitelistprocess(self,task):
        result = False
        process_name = str(task.ImageFileName).lower()
        process_path = str(task.Peb.ProcessParameters.ImagePathName).lower()
        parent_proc = self.get_eprocess_by_pid(task.InheritedFromUniqueProcessId)
        if parent_proc:
            parent_name = parent_proc.ImageFileName
        else:
            parent_name = None
        for processinfo in self.whiteListArray:
            if str(processinfo['name']).lower() == process_name:
                if not (process_path.lower()==self.replaceEnvVarWithValue(processinfo['filepath']).lower()):
                    continue
                '''
                parent_path = self.get_eprocess_by_pid(task.InheritedFromUniqueProcessId).ImagePathName
                for temp_path in processinfo['parentpath']:
                    if(parent_path.endswith(temp_path)):
                        result = True
                        return result
                '''
                '''
                notparent key rule
                '''
                try:
                    if str(parent_name).lower() not in processinfo['notparent']:
                        result = True
                except KeyError:
                    pass
        return result

    def getchildprocesslist(self,pad,pid,p_dict,app_name = "Temp"):
        for task in sorted(p_dict.values(),key=lambda x:x.pid):
            if task.InheritedFromUniqueProcessId !=pid:
                continue
            process_params = task.Peb.ProcessParameters
            process_details = "{0} ({1})".format(task.ImageFileName,task.pid)
            if not self.whitelistprocess(task):
                yield dict(
                    dummy=app_name,
                    process=process_details,
                    ppid=int(task.InheritedFromUniqueProcessId),
                    fullpath=process_params.ImagePathName,
                    cmdline=process_params.CommandLine 
                )   
            p_dict.pop(task.pid, None)
            for x in self.getchildprocesslist(pad + 1, task.pid,p_dict,app_name):
                yield x


    def collect(self):
        self.process_dict={}
        winword_list=[]
        excel_list=[]
        powerpoint_list=[]
        for eprocess in self.filter_processes():
            self.process_dict[int(eprocess.UniqueProcessId)] = eprocess
            if(str(eprocess.ImageFileName).lower()=="winword.exe"):
                winword_list.append(int(eprocess.UniqueProcessId))
            elif (str(eprocess.ImageFileName).lower()=="excel.exe"):
                excel_list.append(int(eprocess.UniqueProcessId))
            elif (str(eprocess.ImageFileName).lower()=="powerpnt.exe"):
                powerpoint_list.append(int(eprocess.UniqueProcessId))
    
        for pids in winword_list:
            divider = "Microsoft Word\nProcessName : {0} ProcessId : {1}\nCommandLine : {2}".format(
                self.process_dict[pids].ImageFileName,
                pids,
                self.process_dict[pids].Peb.ProcessParameters.CommandLine
                )
            yield dict(divider=divider)
            for x in self.getchildprocesslist(0,pids,self.process_dict,app_name="winword"):yield x

        for pids in excel_list:
            divider = "Microsoft Excel\nProcessName : {0} ProcessId : {1}\nCommandLine : {2}".format(
                self.process_dict[pids].ImageFileName,
                pids,
                self.process_dict[pids].Peb.ProcessParameters.CommandLine
                )
            yield dict(divider=divider)

            for x in self.getchildprocesslist(0,pids,self.process_dict,app_name="excel"):yield x

        for pids in powerpoint_list:
            divider = "Microsoft Powerpoint\nProcessName : {0} ProcessId : {1}\nCommandLine : {2}".format(
                self.process_dict[pids].ImageFileName,
                pids,
                self.process_dict[pids].Peb.ProcessParameters.CommandLine
                )
            yield dict(divider=divider)

            for x in self.getchildprocesslist(0,pids,self.process_dict,app_name="powerpnt"):yield x
                


