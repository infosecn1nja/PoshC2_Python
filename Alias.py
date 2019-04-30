#!/usr/bin/python

# Powershell Implant
ps_alias = [
    ["s","get-screenshot"],
    ["whoami","([Security.Principal.WindowsIdentity]::GetCurrent()).name"],
]

# Python Implant
py_alias = [
    ["s","get-screenshot"]
]

# C# Implant
cs_alias = [
    ["s","get-screenshot"],
]

# Parts of commands to replace if command starts with the key
cs_replace = [
    ["safetydump", "run-exe SafetyDump.Program SafetyDump"],
<<<<<<< Updated upstream
    ["seatbelt", "run-exe Seatbelt.Program Seatbelt all"],
    ["sharpup", "run-exe SharpUp.Program SharpUp"],
    ["rubeus", "run-exe Rubeus.Program Rubeus kerberoast"],
=======
    ["seatbelt", "run-exe Seatbelt.Program Seatbelt"],
    ["sharpup", "run-exe SharpUp.Program SharpUp"],
    ["rubeus", "run-exe Rubeus.Program Rubeus"],
>>>>>>> Stashed changes
    ["sharpview", "run-exe SharpView.Program SharpView"],
    ["sharphound", "run-exe Sharphound2.Sharphound Sharphound"],
    ["watson", "run-exe Watson.Program Watson"]
]
