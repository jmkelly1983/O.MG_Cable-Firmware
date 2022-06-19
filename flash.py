# Copyright 2022 Mischief Gadgets LLC

import os
import sys
import json
import glob
import serial
import base64
import platform
import argparse
import platform
import mimetypes
import http.client
import urllib.parse
from sys import exit
from time import time
from signal import signal, SIGINT
from serial.tools.list_ports import comports
from serial.tools import hexlify_codec

from pprint import pprint

try:
    raw_input
except NameError:
    # pylint: disable=redefined-builtin,invalid-name
    raw_input = input   # in python3 it's "raw"
    unichr = chr


VERSION = "FIRMWARE FLASHER VERSION NUMBER [ 220125 @ 161018 UTC ]"
FLASHER_VERSION = 2 # presume we have an old style flasher 
FLASHER_SKIP_ON_VALID_DETECTION = True

BRANCH = "master"
FIRMWARE_DIR="./firmware"
FIRMWARE_URL = "https://raw.githubusercontent.com/O-MG/O.MG_Cable-Firmware/%BRANCH%"
MEMMAP_URL = "https://raw.githubusercontent.com/O-MG/WebFlasher/main/assets/memmap.json"

UPDATES = "FOR UPDATES VISIT: [ https://github.com/O-MG/O.MG_Cable-Firmware ]\n"

MOTD = """\
               ./ohds. -syhddddhys: .oddo/.
                `: oMM+ dMMMMMMMMm`/MMs :`
             `/hMh`:MMm .:-....-:- hMM+`hMh/
           `oNMm:`sMMN:`:+osssso+:`-NMMy.:dMNo`
          +NMMs +NMMh`:mMMMMMMMMMMN/`yMMNo +MMN+
        .dMMMy sMMMh oMNhs+////+shNMs yMMMy sMMMd.
       -NMMM+  NMMMd`-.  `.::::.`  .:`hMMMM` +MMMN-
      -NMMN-   hMMMMMdhhmMMMMMMMMmhhdNMMMMd   -NMMN.
      mMMM- `m:`hMMMMMMMMMmhyyhmMMMMMMMMMd.-d` -MMMm
     +MMMs  dMMs -sMMMMm+`      `+mMMMMs: oMMh  sMMM+
     dMMM` :MMMy  oMMMy            yMMMo  hMMM: `MMMd
     MMMm  sMMM:  NMMN              NMMN  :MMMs  mMMM
    `MMMd  yMMM- `MMMd              dMMM` :MMMs  dMMM`
     NMMN  +MMMo  dMMM:            :MMMN. +MMM+  NMMN
     yMMM/ `NMMN` .NMMN+          +MMMMMMh.+MN` /MMMy
     .MMMm` /MMMd` .hMMMNy+:--:+yNMMMdsNMMN.+/ `mMMM.
      +MMMh  +MMMN/  :hMMMMMMMMMMMMh:  yMMM/   hMMM+
       sMMMh` -mMMMd/` `:oshhhhy+:` `/dMMMh  `hMMMs
        oMMMN/  +mMMMMho:.      .:ohMMMMm/  :NMMMo
         -mMMMd:  :yNMMMMMMNNNNMMMMMMNy:  :dMMMm-
           +NMMMmo   -+shmNMMMMNmhs+-  .omMMMN+
            `/dNo.:/              `-+ymMMMMd/
                /mM-.:/+ossyyhhdmNMMMMMMdo.
              -mMMMMMMMMMMMMMMMMMMNdy+-
             /MMMMMMmyso+//::--.`
            :MMMMNNNNs-
           `Ndo:`    `.`
           :-\
"""

def omg_dependency_imports():
    # load pyserial
    try:
        global serial
        import serial
    except:
        print("\n<<< PYSERIAL MODULE MISSING, MANUALLY INSTALL TO CONTINUE >>>")
        print("<<< YOU CAN TRY: npm install serial or pip install pyserial >>>")
        complete(1)

    try:
        from scripts import flashapi as flashtest
    except:
        if not os.path.exists('./scripts/'):
            os.mkdir("./scripts/")
        dependencies = ['flashapi.py', 'miniterm.py']
        for dependency in dependencies:
            file_path = "scripts/"+dependency
            file_url = FIRMWARE_URL.replace("%BRANCH%",BRANCH) + "/scripts/" + dependency
            try:
                res = get_resource_file(file_url)
                if res['status'] == 200:
                    with open(file_path,"wb") as f:
                            f.write(res['data'])
                    print("succesfully fetched missing dependency %s from %s"%(dependency,file_url))
            except:
                print("failed to get missing dependency %s from %s"%(dependency,file_url))
    try:
        global flashapi
        from scripts import flashapi as flashapi 
    except:
        print("<<< flashapi.PY MISSING FROM scripts/flashapi.py >>>")
        print("<<< PLEASE MANUALLY DOWNLOAD FROM https://github.com/O-MG/O.MG_Cable-Firmware >>>")
        complete(1)

def handler(signal_received, frame):
    # Handle any cleanup here
    print('SIGINT or CTRL-C detected. Exiting gracefully')
    exit(0)

class omg_results():
    def __init__(self):
        self.OS_DETECTED = ""
        self.PROG_FOUND = False
        self.PORT_PATH = ""
        self.WIFI_DEFAULTS = False
        self.WIFI_SSID = "O.MG"
        self.WIFI_PASS = "12345678"
        self.WIFI_MODE = "1"
        self.WIFI_TYPE = "STATION"
        self.FILE_PAGE = "page.mpfs"
        self.FILE_INIT = "esp_init_data_default_v08.bin"
        self.FILE_ELF0 = "image.elf-0x00000.bin"
        self.FILE_ELF1 = "image.elf-0x10000.bin"
        self.FILE_BLANK = "blank.bin"
        self.FILE_OFAT_INIT = "init.bin"
        self.FLASH_SLOTS = 0
        self.FLASH_PAYLOAD_SIZE = 1

def get_dev_info(dev):
    esp = flashapi.ESP8266ROM(dev, baudrate, None)
    esp.connect(None)
    mac = esp.read_mac()

    esp.flash_spi_attach(0)
    flash_id = esp.flash_id()
    size_id = flash_id >> 16
    flash_size = {0x14: 0x100000, 0x15: 0x200000, 0x16: 0x400000}[size_id]
    return mac, flash_size

def ask_for_flasherhwver():
    """
        Ask for the flasher version, either 1 or 2 right now...
    """
    #if  and FLASHER_VERSION != 1:
    #    return FLASHER_VERSION
    FLASHER_VERSION = 1    
    flash_version = FLASHER_VERSION
    if FLASHER_VERSION is None:
        while True:
            try:
                flash_version = int(raw_input("--- Enter version of programmer hardware [Available Versions: Programmer V1 or Programmer V2]: ".format(FLASHVER=flash_version)))
            except:
                pass
            if flash_version == 1 or flash_version == 2:
                break
        print("<<< USER REPORTED HARDWARE FLASHER REVISION AS VERSION", flash_version, ">>>")
    return flash_version    
    
def ask_for_port():
    """\
    Show a list of ports and ask the user for a choice. To make selection
    easier on systems with long device names, also allow the input of an
    index.
    """
    i = 0
    sys.stderr.write('\n--- Available ports:\n')
    ports = []
    ports_info = {}
    skippedports = []
    for n, (port, desc, hwid) in enumerate(sorted(comports()), 1):
        includedport = "CP210"
        if includedport in desc:
            i+=1
            sys.stderr.write('--- {:2}: {:20} {!r}\n'.format(i, port, desc))
            ports.append(port)
            ports_info[port]={'port': port,'desc': desc,'hwid': hwid}
        else: 
            skippedports.append(port)
    pprint(ports_info)
    while True:
        num_ports = len(ports)
        #if num_ports == 1:
        #    return ports[0]
        #else:
        port = raw_input('--- Enter port index or full name: ')
        try:
            index = int(port) - 1
            if not 0 <= index < len(ports):
                sys.stderr.write('--- Invalid index!\n')
                continue
        except ValueError:
            pass
        else:
            port = ports[index]
            FLASHER_VERSION = 1 # update back to 1 
            if 'cp2102n' in str(ports_info[port]['desc'].lower()):
                print("Found programmer version: 2")
                print("This programmer will not require reconnection, please utilize the visual indicators on the programmer to ensure omg device is properly connected.")
                FLASHER_VERSION = 2
            else:
                print("Found programmer version: 1")
        return port

def omg_flash(command,tries=2):
    global FLASHER_VERSION
    ver = FLASHER_VERSION
    from pprint import pprint
    pprint(ver)
    if int(ver) == 2:
        try:
            flashapi.main(command)
            return True
        except (flashapi.FatalError, serial.SerialException, serial.serialutil.SerialException) as e:
            print("Error", str(e))
            return False
    else:
        ret = False
        while tries>0:
            try:
                ret = flashapi.main(command)
                print("<<< GOOD FLASH. PLEASE UNPLUG AND REPLUG CABLE BEFORE CONTINUING >>>")
                input("Press Enter to continue when ready...")
                ret = True
                break
            except (flashapi.FatalError, serial.SerialException, serial.serialutil.SerialException) as e:
                tries-=1
                print("Unsuccessful communication,", tries, "trie(s) remain")
        if not ret:
            print("<<< ERROR DURING FLASHING PROCESS PREVENTED SUCCESSFUL FLASH. TRY TO RECONNECT CABLE OR REBOOT >>>")
            complete(1)
        else:
            return ret

def complete(statuscode, message="Press Enter to continue..."):
    input(message)
    sys.exit(statuscode)

def make_request(url):
    urlparse = urllib.parse.urlparse(url)
    url_parts = None
    if ":" in str(urlparse.netloc):
        url_parts = str(urlparse.netloc).split(":")
    else:
        port = 443
        if urlparse.scheme != "https":
            port = 80
        url_parts = (urlparse.netloc, port)
    if urlparse.scheme == "https":
        conn = http.client.HTTPSConnection(host=url_parts[0], port=url_parts[1])
    else:
        conn = http.client.HTTPConnection(host=url_parts[0], port=url_parts[1])
    return conn

def get_resource_file(url,params=None):
    pyver = sys.version_info
    uas = "httplib ({0}) python/{1}.{2}.{3}-{4}".format(sys.platform,pyver.major,pyver.minor,pyver.micro,pyver.serial)
    headers = {
        "Content-type": "application/x-www-form-urlencoded",
        "Accept": "text/plain",
        "User-Agent": uas
    }
    status = None
    try:
        conn = make_request(url)
        conn.request("GET", url, params, headers)
        response = conn.getresponse()
        status = int(response.status)
        data = response.read()
    except ConnectionError:
        data = None
        status = 500
    return {'data': data, 'status': status}

def omg_fetch_latest_firmware(create_dst_dir=False,dst_dir="./firmware"):
    curr_branch = BRANCH
    mem_map = get_resource_file(MEMMAP_URL)
    data = None
    if mem_map is not None and 'status' in mem_map and mem_map['status'] == 200:
        # attempt to create dir
        if not dst_dir=="./" or create_dst_dir:
            if os.path.exists(dst_dir):
                for f in os.listdir(dst_dir):
                    os.remove(dst_dir + "/" + f)
                os.rmdir(dst_dir)
            os.mkdir(dst_dir)
        json_map = json.loads(mem_map['data'])
        data = json_map
        pymap = {}
        dl_files = []
        for flash_size,files in json_map.items():
            mem_size = int(int(flash_size)/1024)
            file_map = []
            for resource in files:
                file_map.append(resource['offset'])
                file_map.append(resource['name'])
                if resource['name'] not in dl_files:
                    dl_files.append(resource['name'])
            pymap[mem_size]=file_map
        #pprint(pymap)
        #pprint(dl_files)
        for dl_file in dl_files:
            dl_url = ("%s/firmware/%s"%(FIRMWARE_URL,dl_file)).replace("%BRANCH%",curr_branch)
            n = get_resource_file(dl_url)    
            if n is not None and 'data' in n and n['status']==200:
                dl_file_path = "%s/%s"%(dst_dir,dl_file)
                with open(dl_file_path,'wb') as f:
                    print("writing %d bytes of data to file %s from %s"%(len(n['data']),dl_file_path,dl_url))
                    f.write(n['data'])
    return data

def omg_locate():
    def omg_check(fw_path):
    
        pprint(fw_path)
        PAGE_LOCATED = False
        INIT_LOCATED = False
        ELF0_LOCATED = False
        ELF1_LOCATED = False
        ELF2_LOCATED = False

        if os.path.isfile(results.FILE_PAGE):
            PAGE_LOCATED = True
        else:
            if os.path.isfile(fw_path + results.FILE_PAGE):
                results.FILE_PAGE = fw_path + results.FILE_PAGE
                PAGE_LOCATED = True

        if os.path.isfile(results.FILE_INIT):
            INIT_LOCATED = True
        else:
            if os.path.isfile(fw_path + results.FILE_INIT):
                results.FILE_INIT = fw_path + results.FILE_INIT
                INIT_LOCATED = True

        if os.path.isfile(results.FILE_ELF0):
            ELF0_LOCATED = True
        else:
            if os.path.isfile(fw_path + results.FILE_ELF0):
                results.FILE_ELF0 = fw_path + results.FILE_ELF0
                ELF0_LOCATED = True

        if os.path.isfile(results.FILE_ELF1):
            ELF1_LOCATED = True
        else:
            if os.path.isfile(fw_path + results.FILE_ELF1):
                results.FILE_ELF1 = fw_path + results.FILE_ELF1
                ELF1_LOCATED = True

        if os.path.isfile(results.FILE_BLANK):
            ELF2_LOCATED = True
        else:
            if os.path.isfile(fw_path + results.FILE_BLANK):
                results.FILE_BLANK = fw_path + results.FILE_BLANK
                ELF2_LOCATED = True
        # return data
        return (PAGE_LOCATED,INIT_LOCATED,ELF0_LOCATED,ELF1_LOCATED,ELF2_LOCATED)

    # do lookups
    fw_path = FIRMWARE_DIR + "/"
    if not os.path.exists(fw_path):
        omg_fetch_latest_firmware(True,fw_path)
    # try one
    PAGE_LOCATED,INIT_LOCATED,ELF0_LOCATED,ELF1_LOCATED,ELF2_LOCATED = omg_check(fw_path)
    
    if not (PAGE_LOCATED and INIT_LOCATED and ELF0_LOCATED and ELF1_LOCATED and ELF2_LOCATED):
        omg_fetch_latest_firmware(False,fw_path)
        PAGE_LOCATED,INIT_LOCATED,ELF0_LOCATED,ELF1_LOCATED,ELF2_LOCATED = omg_check(fw_path)
    
    # now see if things worked
    if PAGE_LOCATED and INIT_LOCATED and ELF0_LOCATED and ELF1_LOCATED and ELF2_LOCATED:
        print("\n<<< ALL FIRMWARE FILES LOCATED >>>\n")
    else:
        print("<<< SOME FIRMWARE FILES ARE MISSING, PLACE THEM IN THIS FILE'S DIRECTORY >>>")
        if not PAGE_LOCATED: print("\n\tMISSING FILE: {PAGE}".format(PAGE=results.FILE_PAGE))
        if not INIT_LOCATED: print("\tMISSING FILE: {INIT}".format(INIT=results.FILE_INIT))
        if not ELF0_LOCATED: print("\tMISSING FILE: {ELF0}".format(ELF0=results.FILE_ELF0))
        if not ELF1_LOCATED: print("\tMISSING FILE: {ELF1}".format(ELF1=results.FILE_ELF1))
        if not ELF2_LOCATED: print("\tMISSING FILE: {ELF2}".format(ELF2=results.FILE_BLANK))
        print('')
        complete(1)



def omg_probe():
    devices = ""
    results.PROG_FOUND = False

    detected_ports = ask_for_port()
    devices = detected_ports
    
    results.PORT_PATH = devices
    if len(devices) > 1:
        results.PROG_FOUND = True
    
    if results.PROG_FOUND:
        print("\n<<< O.MG-CABLE-PROGRAMMER WAS FOUND ON {PORT} >>>".format(PORT=results.PORT_PATH))
    else:
        if results.OS_DETECTED == "DARWIN":
            print("<<< O.MG-CABLE-PROGRAMMER WAS NOT FOUND IN DEVICES, YOU MAY NEED TO INSTALL THE DRIVERS FOR CP210X USB BRIDGE >>>\n")
            print("VISIT: [ https://www.silabs.com/products/development-tools/software/usb-to-uart-bridge-vcp-drivers ]\n")
        else:
            print("<<< O.MG-CABLE-PROGRAMMER WAS NOT FOUND IN DEVICES >>>\n")
        complete(1)


def omg_patch(_ssid, _pass, _mode, slotsize=0, percent=30%):
    FILE_INIT = results.FILE_INIT

    init_cmd = "INIT;"
    settings = {
        "wifimode": _mode,
        "wifissid": _ssid,
        "wifipass": _pass
    }
    for config,value in settings.items():
        init_cmd+=f"{KEY}{SEP}{VALUE};".format(SEP=":", KEY=config,VALUE=value)
    #  once booted we know more, this is a sane default for now
    # if we set this to %f we can actually erase and allocate at once
    if slotsize>0 :
        init_cmd += "f{SEP}keylog=0".format(SEP=":")
        ns = floor(((250*4)*(percent*.01))/(slotsize*4))
        for i in range(1,ns+1):
            init+="f{SEP}payload={SLOT};".format(SEP=":",SLOT=slotsize)
        init_cmd += "f{SEP}keylog=*;".format(SEP=":")    
    init_cmd += "\0"

    try:
        with open(FILE_INIT,'wb') as f:
            length = len(init_cmd)
            fill = (4*1024)-length
            init_cmd += "\00"*abs(fill)
            f.write(init_cmd)  
    except KeyError:
        print("\n<<< PATCH FAILURE, ABORTING >>>")
        complete(1)


def omg_input():
    WIFI_MODE = ''
    SANITIZED_SELECTION = False

    while not SANITIZED_SELECTION:

        try:
            WIFI_MODE = input("\nSELECT WIFI MODE\n1: STATION - (Connect to existing network. 2.4GHz)\n2: ACCESS POINT - (Create SSID. IP: 192.168.4.1)\n")
            if WIFI_MODE == '' or WIFI_MODE == '1' or WIFI_MODE == '2':
                SANITIZED_SELECTION = True
        except:
            pass

    if len(WIFI_MODE) == 1:
        results.WIFI_DEFAULTS = False
        results.WIFI_MODE = WIFI_MODE
        if WIFI_MODE == '1':
            results.WIFI_TYPE = 'STATION'
        else:
            results.WIFI_TYPE = 'ACCESS POINT'
    else:
        results.WIFI_DEFAULTS = True

    if not results.WIFI_DEFAULTS:

        WIFI_SSID = ''
        SANITIZED_SELECTION = False

        while not SANITIZED_SELECTION:
            try:
                WIFI_SSID = input("\nENTER WIFI SSID (1-32 Characters): ")
                if len(WIFI_SSID) > 1 and len(WIFI_SSID) < 33:
                    SANITIZED_SELECTION = True
            except:
                pass

        results.WIFI_SSID = WIFI_SSID

        WIFI_PASS = ''
        SANITIZED_SELECTION = False

        while not SANITIZED_SELECTION:
            try:
                WIFI_PASS = input("\nENTER WIFI PASS (8-64 Characters): ")
                if len(WIFI_PASS) > 7 and len(WIFI_PASS) < 65:
                    SANITIZED_SELECTION = True
            except:
                pass

        results.WIFI_PASS = WIFI_PASS
       
    FLASH_CUSTOMIZE = 0
    FLASH_SIZE = 0
    FLASH_PAYLOAD_PERCENT = 40
    while not SANITIZED_SELECTION:
        try:
            CUST_INPUT = str(input("\nCUSTOMIZE PAYLOAD AND KEYLOG ALLOCATIONS?\n(Note: Only compatible with Keylogger and Advanced O.MG Devices)\nBegin Customization? (Yes or No)")).lower()
            if "yes" in CUST_INPUT or "no" in CUST_INPUT:
                SANITIZED_SELECTION = True
            if "yes" in CUST_INPUT:
                FLASH_CUSTOMIZE=1
        except:
            pass

    if FLASH_CUSTOMIZE:
        while not SANITIZED_SELECTION:
            try:
                CUST_INPUT = int(str(input("\nPERCENTAGE OF FLASH ALLOCATED TO PAYLOAD: [Usually 40%] ")).lower().replace("%",""))
                if CUST_INPUT>0 and CUST_INPUT<101:
                    SANITIZED_SELECTION=true
                    FLASH_PAYLOAD_PERCENT = CUST_INPUT
                    break
            except:
                pass
                
        while not SANITIZED_SELECTION:
            try:
                CUST_INPUT = int(str(input("\nENTER PAYLOAD SLOT SIZE [In 4k chunks]: ")).lower().replace("%",""))
                if (CUST_INPUT%4)==0:
                    FLASH_SIZE=(CUST_INPUT)/4
                else:
                    print(f"\n{CUST_INPUT} is not divisible by 4, try again. Note: Default is 4k")
            except:
                pass
        results.FLASH_SLOTS = FLASH_SIZE
        results.FLASH_PAYLOAD_SIZE = FLASH_PAYLOAD_PERCENT
        

def omg_flashfw():
    mac, flash_size = get_dev_info(results.PORT_PATH)

    try:
        FILE_PAGE = results.FILE_PAGE
        FILE_INIT = results.FILE_INIT
        FILE_ELF0 = results.FILE_ELF0
        FILE_ELF1 = results.FILE_ELF1
        FILE_OFAT_INIT = results.OFAT_INIT

        if flash_size < 0x200000:
            command = ['--baud', baudrate, '--port', results.PORT_PATH, 'write_flash', '-fs', '1MB', '-fm', 'dout', '0xfc000', FILE_INIT, '0x00000', FILE_ELF0, '0x10000', FILE_ELF1, '0x80000', FILE_PAGE, '0x7f000', FILE_OFAT_INIT]
        else:
            command = ['--baud', baudrate, '--port', results.PORT_PATH, 'write_flash', '-fs', '2MB', '-fm', 'dout', '0x1fc000', FILE_INIT, '0x00000', FILE_ELF0, '0x10000', FILE_ELF1, '0x80000', FILE_PAGE, '0x7f000', FILE_OFAT_INIT]
        omg_flash(command)

    except:
        print("\n<<< SOMETHING FAILED WHILE FLASHING >>>")
        complete(1)


def get_script_path():
    return os.path.dirname(os.path.realpath(sys.argv[0]))


if __name__ == '__main__':
    signal(SIGINT, handler)
    print("\n" + VERSION)
    print("\n" + UPDATES)
    print("\n" + MOTD + "\n")

    results = omg_results()
    baudrate = '115200'

    thedirectory = get_script_path()
    os.chdir(thedirectory)


    omg_dependency_imports()

    results.OS_DETECTED = platform.system().upper()

    omg_locate()

    omg_probe()
    
    FLASHER_VERSION = ask_for_flasherhwver()
    MENU_MODE = ''
    SANITIZED_SELECTION = False

    while not SANITIZED_SELECTION:
        try:
            menu_options = [
                'FLASH NEW FIRMWARE',
                'FACTORY RESET',
                'FIRMWARE UPGRADE - BATCH MODE',
                'FACTORY RESET - BATCH MODE',
                'BACKUP CABLE',
                'DOWNLOAD FIRMWARE UPDATES',
                'EXIT FLASHER',
            ]
            print("Available Options \n")
            i = 1
            for menu_option in menu_options:
                 print(i," ",menu_option,end="")
                 if i == 1:
                     print(" (DEFAULT)")
                 else:
                     print("")
                 i+=1    
            menu_options = [''] 
            MENU_MODE = str(input("Select Option: ")).replace(" ","")
            if MENU_MODE == '1' or MENU_MODE == '2' or MENU_MODE == '3' or MENU_MODE == '4' or MENU_MODE == '5' or MENU_MODE == '6' or  MENU_MODE == '7' or  MENU_MODE == '8':
                SANITIZED_SELECTION = True
        except:
            pass
    # handle python serial exceptions here        
    try:
    
        if MENU_MODE == '1':
            print("\nFIRMWARE UPGRADE")
            #mac, flash_size = get_dev_info(results.PORT_PATH)
            #command = ['--baud', baudrate, '--port', results.PORT_PATH, 'erase_region', '0x7F0000', '0x1000']
            #omg_flash(command)

            omg_input()
            omg_patch(results.WIFI_SSID, results.WIFI_PASS, results.WIFI_MODE, results.FLASH_SLOTS, results.FLASH_PAYLOAD_SIZE)
            omg_flashfw()
            print("\n[ WIFI SETTINGS ]")
            print("\n\tWIFI_SSID: {SSID}\n\tWIFI_PASS: {PASS}\n\tWIFI_MODE: {MODE}\n\tWIFI_TYPE: {TYPE}".format(SSID=results.WIFI_SSID, PASS=results.WIFI_PASS, MODE=results.WIFI_MODE, TYPE=results.WIFI_TYPE))
            print("\n[ FIRMWARE USED ]")
            print("\n\tINIT: {INIT}\n\tELF0: {ELF0}\n\tELF1: {ELF1}\n\tPAGE: {PAGE}".format(INIT=results.FILE_INIT, ELF0=results.FILE_ELF0, ELF1=results.FILE_ELF1, PAGE=results.FILE_PAGE, OFAT_INIT=results.OFAT_INIT))
            print("\n<<< FIRMWARE PROCESS FINISHED, REMOVE CABLE >>>\n")
        elif MENU_MODE == '2':
            print("\nFACTORY RESET")
            mac, flash_size = get_dev_info(results.PORT_PATH)
            if flash_size < 0x200000:
                command = ['--baud', baudrate, '--port', results.PORT_PATH, 'erase_region', '0x70000', '0x8A000']
            else:
                command = ['--baud', baudrate, '--port', results.PORT_PATH, 'erase_region', '0x70000', '0x18A000']
            omg_flash(command)

            #omg_input()
            #omg_patch(results.WIFI_SSID, results.WIFI_PASS, results.WIFI_MODE)
            #omg_flashfw()
            #print("\n[ WIFI SETTINGS ]")
            #print("\n\tWIFI_SSID: {SSID}\n\tWIFI_PASS: {PASS}\n\tWIFI_MODE: {MODE}\n\tWIFI_TYPE: {TYPE}".format(SSID=results.WIFI_SSID, PASS=results.WIFI_PASS, MODE=results.WIFI_MODE, TYPE=results.WIFI_TYPE))
            #print("\n[ FIRMWARE USED ]")
            #print("\n\tINIT: {INIT}\n\tELF0: {ELF0}\n\tELF1: {ELF1}\n\tPAGE: {PAGE}".format(INIT=results.FILE_INIT, ELF0=results.FILE_ELF0, ELF1=results.FILE_ELF1, PAGE=results.FILE_PAGE))
            print("\n<<< FACTORY RESET PROCESS FINISHED, REMOVE CABLE >>>\n")
        elif MENU_MODE == '3':
            baudrate = '460800'
            mac, flash_size = get_dev_info(results.PORT_PATH)
            print("\nFIRMWARE UPGRADE - BATCH MODE")
            omg_input()
            repeating = ''
            while repeating != 'e':
                #command = ['--baud', baudrate, '--port', results.PORT_PATH, 'erase_region', '0x7F0000', '0x1000']
                #omg_flash(command)
                omg_patch(results.WIFI_SSID, results.WIFI_PASS, results.WIFI_MODE, results.FLASH_SLOTS, results.FLASH_PAYLOAD_SIZE)
                omg_flashfw()
                print("\n[ WIFI SETTINGS ]")
                print("\n\tWIFI_SSID: {SSID}\n\tWIFI_PASS: {PASS}\n\tWIFI_MODE: {MODE}\n\tWIFI_TYPE: {TYPE}".format(SSID=results.WIFI_SSID, PASS=results.WIFI_PASS, MODE=results.WIFI_MODE, TYPE=results.WIFI_TYPE))
                print("\n[ FIRMWARE USED ]")
                print("\n\tINIT: {INIT}\n\tELF0: {ELF0}\n\tELF1: {ELF1}\n\tPAGE: {PAGE}".format(INIT=results.FILE_INIT, ELF0=results.FILE_ELF0, ELF1=results.FILE_ELF1, PAGE=results.FILE_PAGE, OFAT_INIT=results.OFAT_INIT))
                print("\n<<< PROCESS FINISHED, REMOVE CABLE AND PLUG IN NEW CABLE >>>\n")
                repeating = input("\n\n<<< PRESS ENTER TO UPGRADE NEXT CABLE, OR 'E' TO EXIT >>>\n")
                complete(0)
        elif MENU_MODE == '4':
            baudrate = '460800'
            mac, flash_size = get_dev_info(results.PORT_PATH)
            print("\nFACTORY RESET - BATCH MODE")
            omg_input()
            repeating = ''
            while repeating != 'e':
                if flash_size < 0x200000:
                    command = ['--baud', baudrate, '--port', results.PORT_PATH, 'erase_region', '0x70000', '0x8A000']
                else:
                    command = ['--baud', baudrate, '--port', results.PORT_PATH, 'erase_region', '0x70000', '0x18A000']
                repeating = input("\n\n<<< PRESS ENTER TO RESTORE NEXT CABLE, OR 'E' TO EXIT >>>\n")
        elif MENU_MODE == '5':
            print("\nBACKUP CABLE")
            mac, flash_size = get_dev_info(results.PORT_PATH)
            filename = "backup-{MACLOW}-{TIMESTAMP}.img".format(MACLOW="".join([hex(m).lstrip("0x") for m in mac]).lower(),TIMESTAMP=int(time()))
            if flash_size < 0x200000:
                command = ['--baud', baudrate, '--port', results.PORT_PATH, 'read_flash', '0x00000', '0x100000', filename]
            else:
                command = ['--baud', baudrate, '--port', results.PORT_PATH, 'read_flash', '0x00000', '0x200000', filename]
            omg_flash(command)
            print('Backup written to ', filename)
        elif MENU_MODE == '6':
            print("Attempting to update flash data...")
            d = omg_fetch_latest_firmware(True,FIRMWARE_DIR)
            if d is not None and len(d) > 1:
                print("\n<<< LOAD SUCCESS. RELOADING DATA >>>\n\n")
            else:
                print("\n<<< LOAD FAILED. PLEASE MANUALLY DOWNLOAD FIRMWARE AND PLACE IN '%s' >>>\n\n"%FIRMWARE_DIR)
                complete(0)
        elif MENU_MODE == '7':
            print("<<< GOODBYE. FLASHER EXITING >>> ")
            sys.exit(0)
        else:
            print("<<< NO VALID INPUT WAS DETECTED. >>>")
    except (flashapi.FatalError, serial.SerialException, serial.serialutil.SerialException) as e:
        print("<<< FATAL ERROR: %s. PLEASE DISCONNECT AND RECONNECT CABLE AND START TASK AGAIN >>>"%str(e))
        sys.exit(1) # special case
    complete(0)
    
