using System;
using System.Security.Principal;
using System.Windows;

namespace KernelFileManager
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            if (!IsRunningAsAdmin())
            {
                MessageBox.Show("Bu uygulama SYSTEM level işlemler için YÖNETİCİ yetkileri gerektirir.",
                              "YÖNETİCİ GEREKLİ", MessageBoxButton.OK, MessageBoxImage.Warning);
                Shutdown();
            }
            base.OnStartup(e);
        }
        
        private bool IsRunningAsAdmin()
        {
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }
}