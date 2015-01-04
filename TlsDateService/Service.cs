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
        protected struct SystemTime
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

        [DllImport("kernel32.dll")]
        protected static extern bool SetLocalTime(ref SystemTime systemTime);

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
