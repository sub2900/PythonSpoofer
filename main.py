#imports
import os 
from spoof import *
import subprocess
import random
import string
import wmi
import winreg
import tkinter as tk
#GUI might get it to work later. its just some crappy tkinter gui
"""
import tkinter as tk
from spoof import Spoofer
class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.master.title("Spoofer")
        self.master.geometry('400x300')
        self.create_widgets()

    def create_widgets(self):
        self.hw_button = tk.Button(self.master, text="Spoof HWID", command=self.spoof_hwid)
        self.hw_button.pack(pady=10)

        self.pc_button = tk.Button(self.master, text="Spoof PC Guid", command=self.spoof_pc_guid)
        self.pc_button.pack(pady=10)

        self.name_button = tk.Button(self.master, text="Spoof Computer Name", command=self.spoof_pc_name)
        self.name_button.pack(pady=10)

        self.pid_button = tk.Button(self.master, text="Spoof Product ID", command=self.spoof_product_id)
        self.pid_button.pack(pady=10)

        self.mac_button = tk.Button(self.master, text="Spoof MAC Address", command=self.spoof_mac_address)
        self.mac_button.pack(pady=10)

        self.log_text = tk.Text(self.master, height=5, width=40)
        self.log_text.pack(pady=10)

        self.quit_button = tk.Button(self.master, text="Quit", fg="red", command=self.master.quit)
        self.quit_button.pack(side="bottom", pady=10)

    def spoof_hwid(self):
        if Spoofer.HWID.Spoof():
            self.log_text.insert(tk.END, Spoofer.HWID.Log + '\n')
        else:
            self.log_text.insert(tk.END, Spoofer.HWID.Log + '\n')

    def spoof_pc_guid(self):
        if Spoofer.PCGuid.Spoof():
            self.log_text.insert(tk.END, Spoofer.PCGuid.Log + '\n')
        else:
            self.log_text.insert(tk.END, Spoofer.PCGuid.Log + '\n')

    def spoof_pc_name(self):
        if Spoofer.PCName.Spoof():
            self.log_text.insert(tk.END, Spoofer.PCName.Log + '\n')
        else:
            self.log_text.insert(tk.END, Spoofer.PCName.Log + '\n')

    def spoof_product_id(self):
        if Spoofer.ProductId.Spoof():
            self.log_text.insert(tk.END, Spoofer.ProductId.Log + '\n')
        else:
            self.log_text.insert(tk.END, Spoofer.ProductId.Log + '\n')

    def spoof_mac_address(self):
        if Spoofer.MAC.Spoof():
            self.log_text.insert(tk.END, Spoofer.MAC.Log + '\n')
        else:
            self.log_text.insert(tk.END, Spoofer.MAC.Log + '\n')

root = tk.Tk()
app = Application(master=root)
app.mainloop()
"""

# code
class Spoofer:
    class HWID:
        Log = ''
        @staticmethod
        def Spoof():
            try:
                os.system('REG ADD HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001\HwProfileGuid /v HwProfileGuid /t REG_SZ /d "{00000000-0000-0000-0000-000000000000}" /f')
                os.system('REG ADD HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001\System\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001 /v HwProfileGuid /t REG_SZ /d "{00000000-0000-0000-0000-000000000000}" /f')
                Spoofer.HWID.Log = 'HWID spoofed successfully!'
                return True
            except:
                Spoofer.HWID.Log = 'Failed to spoof HWID'
                return False
            
    class PCGuid:
        Log = ''
        @staticmethod
        def Spoof():
            try:
                os.system('REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid /t REG_SZ /d "{00000000-0000-0000-0000-000000000000}" /f')
                Spoofer.PCGuid.Log = 'PC Guid spoofed successfully'
                return True
            except:
                Spoofer.PCGuid.Log = 'failed to spoof Guid'
                return False
    
    class PCName:
        Log = ''
        @staticmethod
        def Spoof():
            try:
                os.system('REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName /v ComputerName /t REG_SZ /d "PC-{}" /f'.format(str(os.getpid())))
                os.system('REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName /v ComputerName /t REG_SZ /d "PC-{}" /f'.format(str(os.getpid())))
                Spoofer.PCName.Log = 'Computer name succesfully spoofed'
                return True
            except: 
                Spoofer.PCName.Log = 'failed to spoof cumputer name'

    class ProductId:
        Log = ''
        @staticmethod
        def Spoof():
            try:
                os.system('REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion /v ProductId /t REG_SZ /d "00000-00000-00000-AAAAA-00000" /f')
                Spoofer.ProductId.Log = "Product ID spoofed succesfully"
                return True
            except: 
                Spoofer.ProductId.Log = "failed to spoof product ID"
                return False
    class MAC:
       Log = ""
       @staticmethod
       def Spoof():
        try:
            c = wmi.WMI()
            adapters = c.Win32_NetworkAdapter(PhysicalAdapter=True)
            for adapter in adapters:
                netConnectionID = adapter.NetConnectionID
                caption = adapter.Caption
                name = adapter.Name
                deviceId = adapter.DeviceID.lstrip("PCI\\").replace("&", "_").replace("\\", "_").zfill(8)
                if "Bluetooth" in caption or "Bluetooth" in name or "Bluetooth" in netConnectionID:
                    continue
                macAddress = [random.randint(0x00, 0xff) for _ in range(6)]
                spoofedMacAddress = "-".join([f"{x:02X}" for x in macAddress])
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"SYSTEM\\CurrentControlSet\\Control\\Class\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\{deviceId}", 0, winreg.KEY_ALL_ACCESS) as registryKey:
                    winreg.SetValueEx(registryKey, "NetworkAddress", 0, winreg.REG_SZ, spoofedMacAddress)
                subprocess.call(["netsh.exe", f"interface set interface \"{netConnectionID}\" admin=disable"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.call(["netsh.exe", f"interface set interface \"{netConnectionID}\" admin=enable"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                Spoofer.MAC.Log = "Mac spoofed successfully"
                return True
        except Exception as exception:
            Spoofer.MAC.Log = "Mac was not spoofed :("
            print(f"Error: {exception}")
            return False
            
if __name__ == '__main__':
    textLogo = '''
 __________.__                                                               _____             
\______   \  | _____    ______ _____ _____      ____________   ____   _____/ ____\___________ 
 |     ___/  | \__  \  /  ___//     \\__  \    /  ___/\____ \ /  _ \ /  _ \   __\/ __ \_  __ \
 |    |   |  |__/ __ \_\___ \|  Y Y  \/ __ \_  \___ \ |  |_> >  <_> |  <_> )  | \  ___/|  | \/
 |____|   |____(____  /____  >__|_|  (____  / /____  >|   __/ \____/ \____/|__|  \___  >__|   
                    \/     \/      \/     \/       \/ |__|                           \/       
'''
while True:
    print("Made by seb#5925 go to the site https:://sbc.sell.app")
    print(textLogo)
    print("If still banned after spoofing run cleaners")
    print("┌ Func------------------------------┐")
    print("| [1] Spoof HWID                    |")
    print("| [2] Spoof GUID                    |")
    print("| [3] Spoof your computer name      |")
    print("| [4] Spoof ProductID               |")
    print("| [5] Spoof Mac Address             |")
    print("| [6] cleaners                      |")
    print("└─----------------------------------┘")

    input_str = input()
    if input_str == "1":
        os.system("cls" if os.name == "nt" else "clear")
        print(textLogo)
        if Spoofer.HWID.Spoof():
            print("\033[32m]" + Spoofer.HWID.Log + "\033[0m")
        else:
            print("\033[31m]" + Spoofer.HWID.Log + "\033[0m")
        input()
    elif input_str == "2":
        os.system("cls" if os.name == "nt" else "clear")
        print(textLogo)
        if Spoofer.PCGuid.Spoof():
            print("\033[32m]" + Spoofer.PCGuid.Log + "\033[0m")
        else:
            print("\033[31m]" + Spoofer.PCGuid.Log + "\033[0m")
        input()
    elif input_str == "3":
        os.system("cls" if os.name == "nt" else "clear")
        print(textLogo)
        if Spoofer.PCName.Spoof():
            print("\033[32m]" + Spoofer.PCName.Log + "\033[0m")
        else:
            print("\033[31m]" + Spoofer.PCName.Log + "\033[0m")
        input()
    elif input_str == "4":
        os.system("cls" if os.name == "nt" else "clear")
        print(textLogo)
        if Spoofer.ProductId.Spoof():
            print("\033[32m]" + Spoofer.ProductId.Log + "\033[0m")
        else:
            print("\033[31m]" + Spoofer.ProductId.Log + "\033[0m")
        input()
    elif input_str == "5":
        os.system("cls" if os.name == "nt" else "clear")
        print(textLogo)
        if Spoofer.MAC.Spoof():
            print(Spoofer.MAC.Log)
        else:
            print(Spoofer.MAC.Log)
        input()
    else:
        os.system("cls" if os.name == "nt" else "clear")
     
