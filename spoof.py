import random
import winreg
import uuid
import random
import string
import wmi
import winreg
import tkinter as tk
class Spoofer:
    class HWID:
        regedit_path = r"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001"
        key = "HwProfileGuid"

        @classmethod
        def get_value(cls):
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, cls.regedit_path) as key:
                return winreg.QueryValueEx(key, cls.key)[0]

        @classmethod
        def set_value(cls, value):
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, cls.regedit_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, cls.key, 0, winreg.REG_SZ, value)
                return True

        log = ""
        @classmethod
        def spoof(cls):
            cls.log = ""
            old_value = cls.get_value()
            new_value = "{" + str(uuid.uuid4()) + "}"
            if cls.set_value(new_value):
                cls.log += f"  [SPOOFER] HWID changed from {old_value} to {new_value}"
                return True
            else:
                cls.log += "  [SPOOFER] Error accessing the registry... Maybe run as admin"
                return False

    class PCGuid:
        regedit_path = r"SOFTWARE\Microsoft\Cryptography"
        key = "MachineGuid"

        @classmethod
        def get_value(cls):
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, cls.regedit_path) as key:
                return winreg.QueryValueEx(key, cls.key)[0]

        @classmethod
        def set_value(cls, value):
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, cls.regedit_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, cls.key, 0, winreg.REG_SZ, value)
                return True

        log = ""
        @classmethod
        def spoof(cls):
            cls.log = ""
            old_value = cls.get_value()
            new_value = str(uuid.uuid4())
            if cls.set_value(new_value):
                cls.log += f"  [SPOOFER] GUID changed from {old_value} to {new_value}"
                return True
            else:
                cls.log += "  [SPOOFER] Error accessing the registry... Maybe run as admin"
                return False

    class PCName:
        regedit_path = r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName"
        key = "ComputerName"

        @classmethod
        def get_value(cls):
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, cls.regedit_path) as key:
                return winreg.QueryValueEx(key, cls.key)[0]

        @classmethod
        def set_value(cls, value):
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, cls.regedit_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, cls.key, 0, winreg.REG_SZ, value)
                return True

        log = ""
        @classmethod
        def spoof(cls):
            cls.log = ""
            old_value = cls.get_value()
            new_value = "DESKTOP-" + ''.join(random.choice("ABCDEF0123456789") for _ in range(15))
            if cls.set_value(new_value):
                cls.log += f"  [SPOOFER] Computer Name changed from {old_value} to {new_value}"
                return True
            else:
                            cls.log += "  [SPOOFER] Error accessing the registry... Maybe run as admin"
            return False

@classmethod
def spoof(cls):
    spoofed_hwid = Spoofer.HWID.spoof()
    spoofed_guid = Spoofer.PCGuid.spoof()
    spoofed_name = Spoofer.PCName.spoof()
    return spoofed_hwid and spoofed_guid and spoofed_name

@classmethod
def print_logs(cls):
    print(cls.HWID.log)
    print(cls.PCGuid.log)
    print(cls.PCName.log)
