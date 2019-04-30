#!/usr/bin/python

from DB import update_mods, new_task, select_mods 
from Config import ModulesDirectory 
import os, base64

def check_module_loaded(module_name, randomuri, user, force=False):
  try:
    modules_loaded = select_mods(randomuri)
    if force:
      for modname in os.listdir(ModulesDirectory):
        if modname.lower() in module_name.lower():
          module_name = modname
      new_task(("loadmodule %s" % module_name), user, randomuri)
    if modules_loaded:
      new_modules_loaded = "%s %s" % (modules_loaded, module_name)
      if module_name not in modules_loaded:
        for modname in os.listdir(ModulesDirectory):
          if modname.lower() in module_name.lower():
            module_name = modname
        new_task(("loadmodule %s" % module_name), user, randomuri)
        update_mods(new_modules_loaded, randomuri)
    else:
      new_modules_loaded = "%s" % (module_name)
      new_task(("loadmodule %s" % module_name), user, randomuri)
      update_mods(new_modules_loaded, randomuri)
  except Exception as e:
    print ("Error loadmodule: %s" % e)