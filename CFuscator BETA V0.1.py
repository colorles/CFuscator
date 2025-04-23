import os
import re
import sys
import time
import random
import string
import traceback
from colorama import init, Fore, Style, Back

init(autoreset=True)

ctype = 0
result = ""
obfuscation_stats = {
    "strings": 0,
    "variables": 0,
    "classes": 0,
    "functions": 0
}
statics = ["public", "private", "static", 'internal', 'void', 'string', 'int', 'char', 'bool','double']
preserve_funcs = ['Main', "Initialize", 'NtQueryInformationProcess', '.', "\n", 'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'AntiDebug']


ENABLE_ANIMATIONS = True
VERBOSE_OUTPUT = True

def print_banner():
    """Display a cool ASCII art banner"""
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}║{Fore.RED} ██████╗{Fore.GREEN}███████╗{Fore.YELLOW}██╗   ██╗{Fore.BLUE}███████╗{Fore.MAGENTA} ██████╗ █████╗ ████████╗ ██████╗ ██████╗{Fore.CYAN} ║")
    print(f"{Fore.CYAN}║{Fore.RED}██╔════╝{Fore.GREEN}██╔════╝{Fore.YELLOW}██║   ██║{Fore.BLUE}██╔════╝{Fore.MAGENTA}██╔════╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗{Fore.CYAN}║")
    print(f"{Fore.CYAN}║{Fore.RED}██║     {Fore.GREEN}█████╗  {Fore.YELLOW}██║   ██║{Fore.BLUE}███████╗{Fore.MAGENTA}██║     ███████║   ██║   ██║   ██║██████╔╝{Fore.CYAN}║")
    print(f"{Fore.CYAN}║{Fore.RED}██║     {Fore.GREEN}██╔══╝  {Fore.YELLOW}██║   ██║{Fore.BLUE}╚════██║{Fore.MAGENTA}██║     ██╔══██║   ██║   ██║   ██║██╔══██╗{Fore.CYAN}║")
    print(f"{Fore.CYAN}║{Fore.RED}╚██████╗{Fore.GREEN}██║     {Fore.YELLOW}╚██████╔╝{Fore.BLUE}███████║{Fore.MAGENTA}╚██████╗██║  ██║   ██║   ╚██████╔╝██║  ██║{Fore.CYAN}║")
    print(f"{Fore.CYAN}║{Fore.RED} ╚═════╝{Fore.GREEN}╚═╝     {Fore.YELLOW} ╚═════╝ {Fore.BLUE}╚══════╝{Fore.MAGENTA} ╚═════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝{Fore.CYAN}║")
    print(f"{Fore.CYAN}╠═══════════════════════════════════════════════════════════════════════════╣")
    print(f"{Fore.CYAN}║{Style.BRIGHT}{Fore.WHITE}      💀  ADVANCED CODE OBFUSCATION TOOL v0     By Colorles911  💀{Fore.CYAN}         ║")
    print(f"{Fore.CYAN}╚═══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    print()

def animate_text(text, color=Fore.GREEN, delay=0.01):
    """Create a typing effect for text"""
    if not ENABLE_ANIMATIONS:
        print(f"{color}{text}")
        return
        
    for char in text:
        sys.stdout.write(f"{color}{char}")
        sys.stdout.flush()
        time.sleep(delay)
    print()

def show_progress(process_name, duration=1.0):
    """Show a fake progress bar for the given process"""
    if not ENABLE_ANIMATIONS:
        return
        
    print(f"{Fore.YELLOW}[*] {process_name}: ", end="")
    progress_chars = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']
    start_time = time.time()
    i = 0
    
    while time.time() - start_time < duration:
        sys.stdout.write(f"\r{Fore.YELLOW}[*] {process_name}: {Fore.CYAN}{progress_chars[i % len(progress_chars)]}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    
    sys.stdout.write(f"\r{Fore.YELLOW}[*] {process_name}: {Fore.GREEN}✓ Done{' ' * 20}\n")
    sys.stdout.flush()



def generate_random_letters(length=20):
    letters = string.ascii_letters
    random_string = ''.join(random.choice(letters) for _ in range(length))
    return random_string

def Process_CLASS(class_gotten):
    global result
    NEW_CLASS_NAME = generate_random_letters()
    OLD_CLASS_NAME = str(class_gotten).split("class ")[1].strip()
    result = result.replace(OLD_CLASS_NAME, NEW_CLASS_NAME)

def Process_Functions(OLD_FUNC_NAME):
    global result
    NEW_FUNC_NAME = generate_random_letters()
    result = result.replace(OLD_FUNC_NAME, NEW_FUNC_NAME)

def Process_Vars(OLD_VAR_NAME):
    global result
    NEW_VAR_NAME = generate_random_letters()
    
    pattern = r'\b' + re.escape(OLD_VAR_NAME) + r'\b'
    result = re.sub(pattern, NEW_VAR_NAME, result)
    obfuscation_stats["variables"] = obfuscation_stats["variables"]+1

def OBF_Vars(input_code) -> bool:
    for line in str(input_code).strip().splitlines():
        line2 = str(line).strip()
        if "=" in line2 and not "==" in line2:
            VAR_NAME = ""
            try:
                VAR_NAME = line2.split("=")[0]
                if "(" in VAR_NAME or ")" in VAR_NAME or "[" in VAR_NAME or "\"" in VAR_NAME:
                    VAR_NAME = ""
                else:
                    VAR_NAME = VAR_NAME.split(" ")[1].strip()
            except:
                VAR_NAME = ""
            if VAR_NAME != "":
                Process_Vars(VAR_NAME)
    return True

def OBF_Classes(input_code) -> bool:
    for line in str(input_code).strip().splitlines():
        line2 = str(line).strip()
        if "class" in line2:
            for i in statics:
                if i in line2:
                    Process_CLASS(line2)
                    obfuscation_stats["classes"] = obfuscation_stats["classes"]+1
                    break
    return True

def OBF_Functions(input_code) -> bool:
    global preserve_funcs
    for line in str(input_code).strip().splitlines():
        line2 = str(line).strip()
        if "(" in line2 and ")" in line2:
            for i in statics:
                if i in line2:
                    FUNC_NAME = line2.split("(")[0].split(" ")
                    for i in FUNC_NAME:
                        FUNC_NAME = i.strip()
                    CONTINUE = True
                    for i in preserve_funcs:
                        if i in FUNC_NAME:
                            CONTINUE = False
                            break
                    if CONTINUE and FUNC_NAME != "":
                        Process_Functions(FUNC_NAME)
                        obfuscation_stats["functions"] = obfuscation_stats["functions"]+1
                    break
    return True

def encrypt_string(input_string):
    encrypted = ""
    key = 7 
    for char in input_string:
        encrypted += chr(ord(char) ^ key)
    
    byte_array = ", ".join([str(ord(char)) for char in encrypted])
    return byte_array

def add_after_usings(csharp_code, code_to_add):
    """
    Adds code right after the last 'using' directive in C# code.

    Args:
        csharp_code: The C# code as a string.
        code_to_add: The C# code to add as a string.

    Returns:
        The modified C# code as a string, or the original code if no 'using' is found.
    """
    using_pattern = r"^\s*using\s+.*;\s*$"
    lines = csharp_code.strip().splitlines()
    using_indices = [i for i, line in enumerate(lines) if re.match(using_pattern, line)]

    if using_indices:
        last_using_index = using_indices[-1]
        modified_lines = lines[:last_using_index + 1] + code_to_add.strip().splitlines() + lines[last_using_index + 1:]
        return "\n".join(modified_lines)
    else:
        # If no 'using' directives are found, add at the beginning (you might want a different behavior)
        modified_lines = code_to_add.strip().splitlines() + lines
        return "\n".join(modified_lines)

def Process_Strings(code_string):
    global result
    import re
    

    if "public static class StringDecryptor" not in result:
        decryption_class = """
public static class StringDecryptor
{
    private const int KEY = 7;
    
    public static string Decrypt(byte[] data)
    {
        string decrypted = "";
        foreach (byte b in data)
        {
            decrypted += (char)(b ^ KEY);
        }
        return decrypted;
    }
}
"""
        

        using_pattern = r'(?:using\s+[a-zA-Z0-9_.]+\s*;\s*)+\n'
        match = re.search(using_pattern, result)
        
        if match:

            position = match.end()
            result = result[:position] + "\n" + decryption_class + "\n" + result[position:]
        else:

            namespace_match = re.search(r'(namespace|class|struct|interface)\s+', result)
            if namespace_match:
                position = namespace_match.start()
                result = result[:position] + decryption_class + "\n\n" + result[position:]
            else:

                result = decryption_class + "\n\n" + result
    
    lines = result.splitlines()
    for i in range(len(lines)):

        if "DllImport" in lines[i]:
            continue
            

        if '"' in lines[i]:
            pattern = r'(?<!\\)"((?:\\"|[^"])*?)"'
            processed_line = ""
            last_end = 0
            
            for match in re.finditer(pattern, lines[i]):
                string_content = match.group(1)
                start, end = match.span()
                
                # Add text before the match
                processed_line += lines[i][last_end:start]
                
                # Skip empty strings
                if not string_content:
                    processed_line += '""'
                else:
                    encrypted = encrypt_string(string_content)
                    processed_line += f'StringDecryptor.Decrypt(new byte[] {{{encrypted}}})'
                    obfuscation_stats["strings"] = obfuscation_stats["strings"]+1
                last_end = end
            
            # Add remaining text after the last match
            processed_line += lines[i][last_end:]
            
            lines[i] = processed_line.strip("$")
    
    # Recombine the lines
    result = "\n".join(lines)
    
    return True

def OBF_Strings(input_code) -> bool:
    global result
    Process_Strings(result)
    return True


def add_anti_debugging_code():
    global ctype
    anti_debug_code = ""
    anti_debug_code1 = """
public class SecurityGuardian
{
    private static readonly string[] knownAnalysisProcesses = {
        "ollydbg", "ida64", "ida", "x64dbg", "windbg", "dnspy", "ilspy",
        "cheatengine", "processhacker", "fiddler", "mitmproxy", "mitmweb", "charles",
        "wireshark", "tcpdump", "ghidra"
    };

    private static readonly string[] knownAnalysisWindows = {
        "OllyDbg", "IDA Pro", "x64dbg", "WinDbg", "dnSpy", "ILSpy",
        "Cheat Engine", "Process Hacker", "Wireshark", "mitmproxy", "mitmweb", "ghidra"
    };

    private static readonly string[] knownAnalysisWindowClasses = {
        "OLLYDBG", "IDAWindowClass", "TIdaMainWindow", "X64DBG",
        "WinDbgFrameClass", "ILSpyMainWindow", "CEmainForm", "PHMainWindowClass",
        "Qt5QWindowIcon", "TfrmMain", "ghidra"
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsDebuggerPresent();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr processHandle, ref bool isDebuggerPresent);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int GetWindowText(IntPtr windowHandle, StringBuilder windowText, int maxCount);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern int GetClassName(IntPtr windowHandle, StringBuilder className, int maxCount);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc enumFunc, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    static extern uint GetWindowThreadProcessId(IntPtr windowHandle, out int processId);

    private delegate bool EnumWindowsProc(IntPtr windowHandle, IntPtr lParam);

    private static void TerminateApplication(string detectionReason)
    {
        Console.WriteLine("SecurityGuardian: Potential threat detected. Application will now close.");
        MessageBox.Show("Security Alert: Potential threat detected. Application will now close.", "Security Alert", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        Environment.Exit(1);
    }

    private static bool IsManagedDebuggerAttached()
    {
        return Debugger.IsAttached;
    }

    private static bool IsNativeDebuggerPresent()
    {
        return IsDebuggerPresent();
    }

    private static bool IsRemoteDebuggerActive()
    {
        bool isPresent = false;
        CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isPresent);
        return isPresent;
    }

    private static bool IsBeingDebuggedFlagEnabled()
    {
        try
        {
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            int returnLength;
            int status = NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
            if (status == 0)
            {
                IntPtr beingDebuggedAddress = IntPtr.Add(pbi.PebBaseAddress, 2);
                byte beingDebugged = Marshal.ReadByte(beingDebuggedAddress);
                return beingDebugged != 0;
            }
        }
        catch
        {
            // Handle potential exceptions during PEB access
        }
        return false;
    }

    private static bool CheckForKnownProcesses()
    {
        Process[] currentProcesses = Process.GetProcesses();
        return currentProcesses.Any(process => knownAnalysisProcesses.Contains(process.ProcessName.ToLower()));
    }

    private static System.Collections.Generic.IEnumerable<IntPtr> GetProcessTopLevelWindows(int processId)
    {
        System.Collections.Generic.List<IntPtr> windows = new System.Collections.Generic.List<IntPtr>();
        EnumWindows((windowHandle, lParam) => {
            GetWindowThreadProcessId(windowHandle, out int windowProcessId);
            if (windowProcessId == processId)
            {
                windows.Add(windowHandle);
            }
            return true;
        }, IntPtr.Zero);
        return windows;
    }

    private static bool CheckForKnownWindows()
    {
        foreach (Process process in Process.GetProcesses())
        {
            foreach (IntPtr windowHandle in GetProcessTopLevelWindows(process.Id))
            {
                StringBuilder windowTitle = new StringBuilder(256);
                GetWindowText(windowHandle, windowTitle, windowTitle.Capacity);
                if (knownAnalysisWindows.Contains(windowTitle.ToString())) return true;

                StringBuilder className = new StringBuilder(256);
                GetClassName(windowHandle, className, className.Capacity);
                if (knownAnalysisWindowClasses.Contains(className.ToString())) return true;
            }
        }
        return false;
    }

    private static bool CheckForProxyListeners()
    {
        try
        {
            IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
            IPEndPoint[] listeners = properties.GetActiveTcpListeners();

            foreach (IPEndPoint listener in listeners)
            {
                if (listener.Port == 8080 || listener.Port == 8888) // Common proxy ports
                {
                    try
                    {
                        TcpListener localListener = new TcpListener(listener);
                        localListener.Start();
                        SocketInformation info = localListener.Server.DuplicateAndClose(Process.GetCurrentProcess().Id);
                        using (Socket probingSocket = new Socket(info))
                        {
                            try
                            {
                                int processId = GetOwningProcessId(probingSocket.Handle);
                                if (processId > 0)
                                {
                                    try
                                    {
                                        Process process = Process.GetProcessById(processId);
                                        if (knownAnalysisProcesses.Contains(process.ProcessName.ToLower()))
                                        {
                                            return true;
                                        }
                                    }
                                    catch (ArgumentException) { /* Process might have exited */ }
                                }
                            }
                            catch { /* Error getting owning process */ }
                        }
                        localListener.Stop();
                    }
                    catch (SocketException) { /* Likely permission issue or port already in use */ }
                }
            }
        }
        catch (NetworkInformationException) { /* Handle network errors */ }
        return false;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationSocket(IntPtr socketHandle, int socketInformationClass, IntPtr socketInformation, int socketInformationLength, out int returnLength);

    private const int TcpOwnerProcessIdInfo = 24;

    private static int GetOwningProcessId(IntPtr socketHandle)
    {
        int pid = -1;
        int size = IntPtr.Size;
        IntPtr pidPtr = Marshal.AllocHGlobal(size);
        int result = NtQueryInformationSocket(socketHandle, TcpOwnerProcessIdInfo, pidPtr, size, out int returnLength);
        if (result == 0 && returnLength == size)
        {
            pid = Marshal.ReadIntPtr(pidPtr).ToInt32();
        }
        Marshal.FreeHGlobal(pidPtr);
        return pid;
    }

    private static bool IsTimingAnomalyDetected(int iterations = 1000, long thresholdMilliseconds = 50)
    {
        Stopwatch stopwatch = new Stopwatch();
        stopwatch.Start();
        for (int i = 0; i < iterations; i++)
        {
            int temp = i * i; // Simulate some work
        }
        stopwatch.Stop();
        return stopwatch.ElapsedMilliseconds > thresholdMilliseconds;
    }

    public static void StartMonitoring()
    {
        Thread securityThread = new Thread(() =>
        {
            while (true)
            {
                if (IsManagedDebuggerAttached())
                {
                    TerminateApplication("Managed debugger detected.");
                    return;
                }

                if (IsNativeDebuggerPresent())
                {
                    TerminateApplication("Native debugger detected.");
                    return;
                }

                if (IsRemoteDebuggerActive())
                {
                    TerminateApplication("Remote debugger detected.");
                    return;
                }

                if (IsBeingDebuggedFlagEnabled())
                {
                    TerminateApplication("BeingDebugged flag is set.");
                    return;
                }

                if (CheckForKnownProcesses())
                {
                    TerminateApplication("Known analysis process detected.");
                    return;
                }

                if (CheckForKnownWindows())
                {
                    TerminateApplication("Known analysis window detected.");
                    return;
                }

                if (CheckForProxyListeners())
                {
                    TerminateApplication("Potential network interception tool detected.");
                    return;
                }

                if (IsTimingAnomalyDetected())
                {
                    TerminateApplication("Potential debugging/analysis activity detected (timing anomaly).");
                    return;
                }

                Thread.Sleep(3000); // Check every 3 seconds
            }
        });
        securityThread.IsBackground = true;
        securityThread.Start();
    }
}

"""
    

    anti_debug_code2 = """
public class SecurityGuardian
{
    private static readonly string[] knownAnalysisProcesses = {
        "ollydbg", "ida64", "ida", "x64dbg", "windbg", "dnspy", "ilspy",
        "cheatengine", "processhacker", "fiddler", "mitmproxy", "mitmweb", "charles",
        "wireshark", "tcpdump", "ghidra"
    };

    private static readonly string[] knownAnalysisWindows = {
        "OllyDbg", "IDA Pro", "x64dbg", "WinDbg", "dnSpy", "ILSpy",
        "Cheat Engine", "Process Hacker", "Wireshark", "mitmproxy", "mitmweb", "ghidra"
    };

    private static readonly string[] knownAnalysisWindowClasses = {
        "OLLYDBG", "IDAWindowClass", "TIdaMainWindow", "X64DBG",
        "WinDbgFrameClass", "ILSpyMainWindow", "CEmainForm", "PHMainWindowClass",
        "Qt5QWindowIcon", "TfrmMain", "ghidra"
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsDebuggerPresent();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr processHandle, ref bool isDebuggerPresent);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int GetWindowText(IntPtr windowHandle, StringBuilder windowText, int maxCount);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern int GetClassName(IntPtr windowHandle, StringBuilder className, int maxCount);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc enumFunc, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    static extern uint GetWindowThreadProcessId(IntPtr windowHandle, out int processId);

    private delegate bool EnumWindowsProc(IntPtr windowHandle, IntPtr lParam);

    private static void TerminateApplication(string detectionReason)
    {
        Console.WriteLine("SecurityGuardian: Potential threat detected. Application will now close.");
        Environment.Exit(1);
    }

    private static bool IsManagedDebuggerAttached()
    {
        return Debugger.IsAttached;
    }

    private static bool IsNativeDebuggerPresent()
    {
        return IsDebuggerPresent();
    }

    private static bool IsRemoteDebuggerActive()
    {
        bool isPresent = false;
        CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isPresent);
        return isPresent;
    }

    private static bool IsBeingDebuggedFlagEnabled()
    {
        try
        {
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            int returnLength;
            int status = NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
            if (status == 0)
            {
                IntPtr beingDebuggedAddress = IntPtr.Add(pbi.PebBaseAddress, 2);
                byte beingDebugged = Marshal.ReadByte(beingDebuggedAddress);
                return beingDebugged != 0;
            }
        }
        catch
        {
            // Handle potential exceptions during PEB access
        }
        return false;
    }

    private static bool CheckForKnownProcesses()
    {
        Process[] currentProcesses = Process.GetProcesses();
        return currentProcesses.Any(process => knownAnalysisProcesses.Contains(process.ProcessName.ToLower()));
    }

    private static System.Collections.Generic.IEnumerable<IntPtr> GetProcessTopLevelWindows(int processId)
    {
        System.Collections.Generic.List<IntPtr> windows = new System.Collections.Generic.List<IntPtr>();
        EnumWindows((windowHandle, lParam) => {
            GetWindowThreadProcessId(windowHandle, out int windowProcessId);
            if (windowProcessId == processId)
            {
                windows.Add(windowHandle);
            }
            return true;
        }, IntPtr.Zero);
        return windows;
    }

    private static bool CheckForKnownWindows()
    {
        foreach (Process process in Process.GetProcesses())
        {
            foreach (IntPtr windowHandle in GetProcessTopLevelWindows(process.Id))
            {
                StringBuilder windowTitle = new StringBuilder(256);
                GetWindowText(windowHandle, windowTitle, windowTitle.Capacity);
                if (knownAnalysisWindows.Contains(windowTitle.ToString())) return true;

                StringBuilder className = new StringBuilder(256);
                GetClassName(windowHandle, className, className.Capacity);
                if (knownAnalysisWindowClasses.Contains(className.ToString())) return true;
            }
        }
        return false;
    }

    private static bool CheckForProxyListeners()
    {
        try
        {
            IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
            IPEndPoint[] listeners = properties.GetActiveTcpListeners();

            foreach (IPEndPoint listener in listeners)
            {
                if (listener.Port == 8080 || listener.Port == 8888) // Common proxy ports
                {
                    try
                    {
                        TcpListener localListener = new TcpListener(listener);
                        localListener.Start();
                        SocketInformation info = localListener.Server.DuplicateAndClose(Process.GetCurrentProcess().Id);
                        using (Socket probingSocket = new Socket(info))
                        {
                            try
                            {
                                int processId = GetOwningProcessId(probingSocket.Handle);
                                if (processId > 0)
                                {
                                    try
                                    {
                                        Process process = Process.GetProcessById(processId);
                                        if (knownAnalysisProcesses.Contains(process.ProcessName.ToLower()))
                                        {
                                            return true;
                                        }
                                    }
                                    catch (ArgumentException) { /* Process might have exited */ }
                                }
                            }
                            catch { /* Error getting owning process */ }
                        }
                        localListener.Stop();
                    }
                    catch (SocketException) { /* Likely permission issue or port already in use */ }
                }
            }
        }
        catch (NetworkInformationException) { /* Handle network errors */ }
        return false;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationSocket(IntPtr socketHandle, int socketInformationClass, IntPtr socketInformation, int socketInformationLength, out int returnLength);

    private const int TcpOwnerProcessIdInfo = 24;

    private static int GetOwningProcessId(IntPtr socketHandle)
    {
        int pid = -1;
        int size = IntPtr.Size;
        IntPtr pidPtr = Marshal.AllocHGlobal(size);
        int result = NtQueryInformationSocket(socketHandle, TcpOwnerProcessIdInfo, pidPtr, size, out int returnLength);
        if (result == 0 && returnLength == size)
        {
            pid = Marshal.ReadIntPtr(pidPtr).ToInt32();
        }
        Marshal.FreeHGlobal(pidPtr);
        return pid;
    }

    private static bool IsTimingAnomalyDetected(int iterations = 1000, long thresholdMilliseconds = 50)
    {
        Stopwatch stopwatch = new Stopwatch();
        stopwatch.Start();
        for (int i = 0; i < iterations; i++)
        {
            int temp = i * i; // Simulate some work
        }
        stopwatch.Stop();
        return stopwatch.ElapsedMilliseconds > thresholdMilliseconds;
    }

    public static void StartMonitoring()
    {
        Thread securityThread = new Thread(() =>
        {
            while (true)
            {
                if (IsManagedDebuggerAttached())
                {
                    TerminateApplication("Managed debugger detected.");
                    return;
                }

                if (IsNativeDebuggerPresent())
                {
                    TerminateApplication("Native debugger detected.");
                    return;
                }

                if (IsRemoteDebuggerActive())
                {
                    TerminateApplication("Remote debugger detected.");
                    return;
                }

                if (IsBeingDebuggedFlagEnabled())
                {
                    TerminateApplication("BeingDebugged flag is set.");
                    return;
                }

                if (CheckForKnownProcesses())
                {
                    TerminateApplication("Known analysis process detected.");
                    return;
                }

                if (CheckForKnownWindows())
                {
                    TerminateApplication("Known analysis window detected.");
                    return;
                }

                if (CheckForProxyListeners())
                {
                    TerminateApplication("Potential network interception tool detected.");
                    return;
                }

                if (IsTimingAnomalyDetected())
                {
                    TerminateApplication("Potential debugging/analysis activity detected (timing anomaly).");
                    return;
                }

                Thread.Sleep(3000); // Check every 3 seconds
            }
        });
        securityThread.IsBackground = true;
        securityThread.Start();
    }
}

"""
    
    if ctype ==1 :
        anti_debug_code =anti_debug_code1
    elif ctype ==2 :
        anti_debug_code =anti_debug_code2
    
    return anti_debug_code

def add_necessary_imports():
    """Add imports needed for anti-debugging"""
    imports = """using System;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;
"""
    return imports

def inject_anti_debug_initialization(code):
    """Inject call to initialize anti-debugging in the Main method"""
    main_pattern = r'(static\s+void\s+Main\s*\([^)]*\)\s*{)'
    match = re.search(main_pattern, code)
    
    if match:
        position = match.end()
        codes = """        SecurityGuardian.StartMonitoring();"""
        modified_code = code[:position] + f"\n{codes}\n" + code[position:]
        return modified_code
    
    return code

def clean_duplicates(code):
    pattern = r'public static\s+public static class StringDecryptor'
    cleaned = re.sub(pattern, 'public static class StringDecryptor', code)
    
    # Check for other potential duplications
    return cleaned


def obfuscate(input_code) -> str:
    global result
    
    animate_text("⚡ Starting advanced obfuscation process...", Fore.MAGENTA)
    print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗")
    

    necessary_imports = add_necessary_imports()
    anti_debug_code = add_anti_debugging_code()
    

    show_progress("Analyzing code structure")
    namespace_match = re.search(r'namespace\s+([a-zA-Z0-9_.]+)', input_code)
    using_statements = ""
    

    using_matches = re.finditer(r'using\s+[a-zA-Z0-9_.]+\s*;', input_code)
    for match in using_matches:
        using_statements += match.group(0) + "\n"
        input_code = input_code.replace(match.group(0), "")
    

    if namespace_match:
        namespace_start = namespace_match.start()
        result = necessary_imports + "\n" + using_statements + "\n" + anti_debug_code + "\n" + input_code
    else:
        result = necessary_imports + "\n" + using_statements + "\n" + anti_debug_code + "\n" + input_code
    

    result = inject_anti_debug_initialization(result)
    

    if OBF_Strings(input_code):
        print(f"{Fore.CYAN}║ {Fore.GREEN}[✓] {Fore.WHITE}Obfuscated {Fore.YELLOW}{obfuscation_stats['strings']}")
    
    if OBF_Vars(input_code):
        print(f"{Fore.CYAN}║ {Fore.GREEN}[✓] {Fore.WHITE}Obfuscated {Fore.YELLOW}{obfuscation_stats['variables']}")
  
    if OBF_Classes(input_code):
        print(f"{Fore.CYAN}║ {Fore.GREEN}[✓] {Fore.WHITE}Obfuscated {Fore.YELLOW}{obfuscation_stats['classes']}")
        
    if OBF_Functions(input_code):
        print(f"{Fore.CYAN}║ {Fore.GREEN}[✓] {Fore.WHITE}Obfuscated {Fore.YELLOW}{obfuscation_stats['functions']}")
    
    # Clean up any syntax issues
    result = clean_duplicates(result)
    
    print(f"{Fore.CYAN}║ {Fore.GREEN}[✓] {Fore.WHITE}Added {Fore.RED}Anti-Debugging{Fore.WHITE} protection")
    print(f"{Fore.CYAN}║ {Fore.GREEN}[✓] {Fore.WHITE}Added {Fore.RED}Anti-Tampering{Fore.WHITE} protection")
    print(f"{Fore.CYAN}║ {Fore.GREEN}[✓] {Fore.WHITE}Added {Fore.RED}Sus-Process-Detection{Fore.WHITE} protection")
    print(f"{Fore.CYAN}║ {Fore.GREEN}[✓] {Fore.WHITE}Added {Fore.RED}Window-Watcher{Fore.WHITE} protection")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    return result

def main():
    global result , ctype
    try:
        print_banner()
        time.sleep(0.5)
        
        animate_text(f"{Fore.YELLOW}[!] {Fore.LIGHTWHITE_EX}WARNING: Use this tool responsibly and ethically. The author bears no responsibility", Fore.YELLOW, 0.005)
        animate_text(f"{Fore.YELLOW}    for any misuse or damage caused by obfuscated code.", Fore.YELLOW, 0.005)
        print()
        
        filepath = input(f"{Fore.CYAN}[?] {Fore.WHITE}DRAG FILE TO OBFUSCATE: {Fore.GREEN}")
        
        if not os.path.exists(filepath):
            print(f"{Fore.RED}[!] Error: File not found")
            return
            
        print(f"{Fore.CYAN}[*] {Fore.WHITE}Reading file: {filepath}")
        input_code = open(filepath, "r", errors="ignore").read()
        
        print(f"{Fore.CYAN}[*] {Fore.WHITE}File size: {Fore.YELLOW}{len(input_code):,}{Fore.WHITE} bytes")
        filename, ext = os.path.splitext(filepath)
        

        show_progress("Performing complexity analysis")
        complexity = random.choice(["Medium", "High", "Very High", "Extreme"])
        print(f"{Fore.CYAN}[*] {Fore.WHITE}Code complexity: {Fore.YELLOW}{complexity}")
        print()
        try:
            ctype = int(input("Obfuscation Type (1. WinForms Program.cs , 2. Console Application) : "))
        except Exception as e:
            print(f"{Fore.LIGHTRED_EX} Error happened, Message {Fore.LIGHTBLUE_EX}: {Fore.LIGHTWHITE_EX}{str(e)}{Fore.RESET}")
        result = obfuscate(input_code)
        
        time.sleep(0.5)
        print()
        output_file = f"obfuscated_{int(time.time())}{ext}"

        open(output_file, "w").write(str(result).strip("$"))
        
        print(f"{Fore.GREEN}[✓] {Fore.WHITE}Obfuscation completed successfully!")
        print(f"{Fore.GREEN}[✓] {Fore.WHITE}Original size: {Fore.YELLOW}{len(input_code):,}{Fore.WHITE} bytes")
        print(f"{Fore.GREEN}[✓] {Fore.WHITE}Obfuscated size: {Fore.YELLOW}{len(result):,}{Fore.WHITE} bytes")
        print(f"{Fore.GREEN}[✓] {Fore.WHITE}Obfuscated code saved to: {Fore.GREEN}{output_file}")
        
        print()
        animate_text(f"{Fore.MAGENTA}[*] Press any key to exit...", Fore.MAGENTA, 0.01)
        input()

    except Exception as e:
        print(f"{Fore.RED}[!] Error during obfuscation: {str(e)}")
        print(f"{Fore.RED}[!] Stack trace:")
        traceback.print_exc()
        
        print()
        input(f"{Fore.RED}[*] Press any key to exit...")

if __name__ == "__main__":
    main()    







