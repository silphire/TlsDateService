using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Timers;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace TlsDateService
{
    public partial class Service : ServiceBase
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct SystemTime
        {
            public ushort wYear;
            public ushort wMonth;
            public ushort wDayOfWeek;
            public ushort wDay;
            public ushort wHour;
            public ushort wMinute;
            public ushort wSecond;
            public ushort wMilliSeconds;
        }

        private static const uint TOKEN_QUERY = 0x0008;
        private static const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private static const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;
        private static const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
        private static const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct TOKEN_PRIVILEGES
        {
            public UInt32 privilegeCount;
            public LUID luid;
            public UInt32 attributes;
        }

        enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            MaxTokenInfoClass
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetLocalTime(ref SystemTime systemTime);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool LookupPrivilegeValue(string systemName, string name, out LUID luid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool LookupPrivilegeDisplayName(string systemName, string name, StringBuilder displayName, ref uint displayNameLength, ref uint languageId);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges, ref TOKEN_PRIVILEGES newState, int bufferLength, IntPtr previousState, IntPtr returnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);


        protected static void SetDateTime(DateTime dateTime)
        {
            SystemTime systemTime = new SystemTime();
            systemTime.wYear = (ushort)dateTime.Year;
            systemTime.wMonth = (ushort)dateTime.Month;
            systemTime.wDay = (ushort)dateTime.Day;
            systemTime.wHour = (ushort)dateTime.Hour;
            systemTime.wMinute = (ushort)dateTime.Minute;
            systemTime.wSecond = (ushort)dateTime.Second;
            systemTime.wMilliSeconds = (ushort)dateTime.Millisecond;

            // needs SE_SYSTEMTIME_NAME priviledge
            SetLocalTime(ref systemTime);
        }

        public static bool AcquirePrivilege()
        {
            bool isAcquired = false;
            IntPtr tokenHandle;

            if(OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tokenHandle))
            {
                LUID luid;

                if(LookupPrivilegeValue(null, "SeSystemtimePrivilege", out luid))
                {
                    TOKEN_PRIVILEGES tokenPrivileges;
                    tokenPrivileges.privilegeCount = 1;
                    tokenPrivileges.luid = luid;
                    tokenPrivileges.attributes = SE_PRIVILEGE_ENABLED;

                    AdjustTokenPrivileges(tokenHandle, false, ref tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero);
                    isAcquired = Marshal.GetLastWin32Error() == 0;  // 0 == ERROR_SUCCESS
                }

                CloseHandle(tokenHandle);
            }

            return isAcquired;
        }

        public Service()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            AcquirePriviledge();
        }

        protected void AcquirePriviledge()
        {

        }

        protected override void OnStop()
        {
        }

        protected void AdjustTime()
        {
            TlsDate.TlsDate tlsdate = new TlsDate.TlsDate();
            uint unixTime = tlsdate.GetCurrentDateFromServer();
            SetDateTime(new DateTime((long)unixTime * 10000));
        }

        private void timer_Elapsed(object sender, ElapsedEventArgs e)
        {
            ;
        }
    }
}
