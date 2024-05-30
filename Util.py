import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import winreg

def set_registry_value(path, name, value):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, path)
            winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
            winreg.CloseKey(key)
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to set registry value: {e}")
            return False
    except Exception as e:
        messagebox.showerror("Error", f"Failed to set registry value: {e}")
        return False

def show_info(action, success=True):
    state = "enabled" if action.endswith("True") else "disabled"
    item = action.split("_")[1].replace("state", "").strip()
    message = f"{item} {state} successfully." if success else f"Failed to set {item} state."
    if success:
        messagebox.showinfo("Success", message)
    else:
        messagebox.showerror("Error", message)

def set_task_manager_state(enable):
    success = set_registry_value(r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr", 0 if enable else 1)
    show_info(f"task_manager_{enable}", success)

def set_device_manager_state(enable):
    success = set_registry_value(r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableDevMgr", 0 if enable else 1)
    show_info(f"device_manager_{enable}", success)

def set_cmd_state(enable):
    success = set_registry_value(r"Software\Policies\Microsoft\Windows\System", "DisableCMD", 0 if enable else 1)
    show_info(f"cmd_{enable}", success)

def set_regedit_state(enable):
    success = set_registry_value(r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools", 0 if enable else 1)
    show_info(f"regedit_{enable}", success)

def set_control_panel_state(enable):
    success = set_registry_value(r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoControlPanel", 0 if enable else 1)
    show_info(f"control_panel_{enable}", success)

def set_windows_update_state(enable):
    success = set_registry_value(r"Software\Policies\Microsoft\Windows\WindowsUpdate", "DisableWindowsUpdateAccess", 0 if enable else 1)
    show_info(f"windows_update_{enable}", success)

def set_windows_defender_state(enable):
    success = set_registry_value(r"Software\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", 0 if enable else 1)
    show_info(f"windows_defender_{enable}", success)

def set_windows_firewall_state(enable):
    success = set_registry_value(r"Software\Policies\Microsoft\WindowsFirewall\DomainProfile", "EnableFirewall", 1 if enable else 0)
    success &= set_registry_value(r"Software\Policies\Microsoft\WindowsFirewall\PrivateProfile", "EnableFirewall", 1 if enable else 0)
    success &= set_registry_value(r"Software\Policies\Microsoft\WindowsFirewall\PublicProfile", "EnableFirewall", 1 if enable else 0)
    show_info(f"windows_firewall_{enable}", success)

def set_windows_audio_state(enable):
    success = set_registry_value(r"Software\Microsoft\Multimedia\Audio", "DisableSystemSounds", 1 if enable else 0)
    show_info(f"windows_audio_{enable}", success)

def set_windows_autoplay_state(enable):
    success = set_registry_value(r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 0 if enable else 255)
    show_info(f"windows_autoplay_{enable}", success)

def set_windows_remote_assistance_state(enable):
    success = set_registry_value(r"Software\Policies\Microsoft\Windows NT\Terminal Services", "fAllowToGetHelp", 1 if enable else 0)
    show_info(f"windows_remote_assistance_{enable}", success)

def set_windows_uac_state(enable):
    success = set_registry_value(r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1 if enable else 0)
    show_info(f"windows_uac_{enable}", success)

def create_button(frame, text, command):
    button = ttk.Button(frame, text=text, command=command, width=25)
    button.pack(pady=5)
    return button

def show_warning():
    messagebox.showwarning("Warning", "This program can potentially harm your system. Use it at your own risk. The author is not responsible for any damage caused.")

root = tk.Tk()
root.title("SystemСontrolPanel")

show_warning()

root.resizable(False, False)

notebook = ttk.Notebook(root)
notebook.pack(padx=10, pady=10, expand=True, fill='both')

frame_system_utils = ttk.Frame(notebook)
notebook.add(frame_system_utils, text='System Utilities')

create_button(frame_system_utils, "Enable Task Manager", lambda: set_task_manager_state(True))
create_button(frame_system_utils, "Disable Task Manager", lambda: set_task_manager_state(False))

create_button(frame_system_utils, "Enable Device Manager", lambda: set_device_manager_state(True))
create_button(frame_system_utils, "Disable Device Manager", lambda: set_device_manager_state(False))

create_button(frame_system_utils, "Enable Command Prompt", lambda: set_cmd_state(True))
create_button(frame_system_utils, "Disable Command Prompt", lambda: set_cmd_state(False))

create_button(frame_system_utils, "Enable Registry Editor", lambda: set_regedit_state(True))
create_button(frame_system_utils, "Disable Registry Editor", lambda: set_regedit_state(False))

create_button(frame_system_utils, "Enable Control Panel", lambda: set_control_panel_state(True))
create_button(frame_system_utils, "Disable Control Panel", lambda: set_control_panel_state(False))

frame_windows_settings = ttk.Frame(notebook)
notebook.add(frame_windows_settings, text='Windows Settings')

create_button(frame_windows_settings, "Enable Windows Update", lambda: set_windows_update_state(True))
create_button(frame_windows_settings, "Disable Windows Update", lambda: set_windows_update_state(False))

create_button(frame_windows_settings, "Enable Windows Defender", lambda: set_windows_defender_state(True))
create_button(frame_windows_settings, "Disable Windows Defender", lambda: set_windows_defender_state(False))

create_button(frame_windows_settings, "Enable Windows Firewall", lambda: set_windows_firewall_state(True))
create_button(frame_windows_settings, "Disable Windows Firewall", lambda: set_windows_firewall_state(False))

create_button(frame_windows_settings, "Enable Windows Audio", lambda: set_windows_audio_state(True))
create_button(frame_windows_settings, "Disable Windows Audio", lambda: set_windows_audio_state(False))

create_button(frame_windows_settings, "Enable Windows Autoplay", lambda: set_windows_autoplay_state(True))
create_button(frame_windows_settings, "Disable Windows Autoplay", lambda: set_windows_autoplay_state(False))

create_button(frame_windows_settings, "Enable Windows Remote Assistance", lambda: set_windows_remote_assistance_state(True))
create_button(frame_windows_settings, "Disable Windows Remote Assistance", lambda: set_windows_remote_assistance_state(False))

create_button(frame_windows_settings, "Enable Windows UAC", lambda: set_windows_uac_state(True))
create_button(frame_windows_settings, "Disable Windows UAC", lambda: set_windows_uac_state(False))

frame_info = ttk.Frame(notebook)
notebook.add(frame_info, text='Information')

info_text = tk.Text(frame_info)
info_text.insert(tk.END, "Created: ProcessHacker (free)                                                   ")
info_text.insert(tk.END, "Telegram: @Pr0cHacker                                                           ")
info_text.insert(tk.END, "Update: 1.0.0.0, the program is updated every month                             ")
info_text.config(state=tk.DISABLED)
info_text.pack(expand=True, fill='both')

root.mainloop()
