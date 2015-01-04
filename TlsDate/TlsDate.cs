using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net.Security;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace TlsDate
{
    public class TlsDate
    {
        public string certificate { get; set; }
        public string serverName { get; set; }
        public int serverPort { get; set; }
        public bool validCredential { get; set; }
        protected uint unixTime;
        protected long rtt;
        protected Stopwatch stopWatch;

        public TlsDate()
        {
            serverName = null;
            serverPort = 443;
            certificate = null;

            unixTime = 0;
            rtt = 0;
            validCredential = false;
            stopWatch = null;
        }

        /// <summary>
        /// 現在の時刻をサーバーに問い合わせ、得られた時刻を返します。
        /// </summary>
        /// <returns>現在の時刻をUNIX時間で表した値</returns>
        public uint GetCurrentDateFromServer()
        {
            TcpClient tcpClient = new TcpClient(serverName, serverPort);
            TapStream tcpStream = new TapStream(tcpClient.GetStream());
            
            // tcpStream.DoTapRead += DumpRead;
            // tcpStream.DoTapWrite += DumpWrite;
            tcpStream.DoTapRead += SniffServerHello;

            stopWatch = new Stopwatch();
            stopWatch.Start();
            SslStream sslStream = new SslStream(tcpStream, false, UserCertificateValidationCallback);
            sslStream.AuthenticateAsClient(serverName);

            return unixTime;
        }

        protected List<byte> sniffBuffer;
        protected int SniffServerHello(byte[] buffer, int offset, int count)
        {
            if(sniffBuffer == null)
            {
                sniffBuffer = new List<byte>();
                unixTime = 0;
                rtt = 0;
                validCredential = false;
            }
            for (int i = 0; i < count; ++i)
            {
                sniffBuffer.Add(buffer[offset + i]);
            }

            ParsePacket();

            return 0;
        }

        protected void ParsePacket()
        {
            // TLS packet format is refered from
            //   http://tools.ietf.org/html/rfc5246#appendix-A

            if (sniffBuffer.Count < 4)
            {
                return;
            }

            int length = (int)sniffBuffer[3] * 0x100 + (int)sniffBuffer[4];

            if (sniffBuffer.Count < length + 4)
            {
                return;
            }

            if( sniffBuffer[5] == 2)
            {
                // ServerHello message
                unixTime = (uint)sniffBuffer[11] * 0x1000000 + (uint)sniffBuffer[12] * 0x10000 + (uint)sniffBuffer[13] * 0x100 + (uint)sniffBuffer[14];
                stopWatch.Stop();
                rtt = stopWatch.ElapsedMilliseconds;
                unixTime -= (uint)(rtt / 1000 / 2);
                //Console.Out.WriteLine("Time:{0} RTT:{1}ms", unixTime, rtt);
            }

            // パケットを削除
            List<byte> newSniffBuffer = new List<byte>();
            for(int i = length + 4; i < sniffBuffer.Count; ++i)
            {
                newSniffBuffer.Add(sniffBuffer[i]);
            }
            sniffBuffer = newSniffBuffer;
        }

        protected bool UserCertificateValidationCallback(Object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if(sslPolicyErrors == SslPolicyErrors.None)
            {
                validCredential = true;
                return true;
            }

            validCredential = false;
            return false;
        }

        protected int DumpRead(byte[] buffer, int offset, int count)
        {
            Console.Out.WriteLine("READ");
            for (int i = 0; i < count; ++i)
            {
                Console.Out.Write("{0} ", buffer[offset + i].ToString("X2"));
                if(i % 0x10 == 0x0F)
                {
                    Console.WriteLine();
                }
            }
            Console.WriteLine();
            return 0;
        }

        protected void DumpWrite(byte[] buffer, int offset, int count)
        {
            Console.Out.WriteLine("WRITE");
            for (int i = 0; i < count; ++i)
            {
                Console.Out.Write("{0} ", buffer[offset + i].ToString("X2"));
                if(i % 0x10 == 0x0F)
                {
                    Console.WriteLine();
                }
            }
            Console.WriteLine();
        }
    }

    public class TapStream : Stream
    {
        public delegate int DoTapReadDelegate(byte[] buffer, int offset, int count);
        public DoTapReadDelegate DoTapRead;
        public delegate void DoTapWriteDelegate(byte[] buffer, int offset, int count);
        public DoTapWriteDelegate DoTapWrite;

        public Stream sourceStream { get; set; }

        public TapStream(Stream stream)
        {
            sourceStream = stream;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int result = sourceStream.Read(buffer, offset, count);
            if(DoTapRead != null)
            {
                DoTapRead(buffer, offset, count);
            }
            return result;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if(DoTapWrite != null)
            {
                DoTapWrite(buffer, offset, count);
            }
            sourceStream.Write(buffer, offset, count);
        }

        public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
        {
            return sourceStream.BeginRead(buffer, offset, count, callback, state);
        }

        public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
        {
            return sourceStream.BeginWrite(buffer, offset, count, callback, state);
        }

        public override void Close()
        {
            sourceStream.Close();
        }

        public override void SetLength(long value)
        {
            sourceStream.SetLength(value);
        }

        public override void Flush()
        {
            sourceStream.Flush();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return sourceStream.Seek(offset, origin);
        }

        public override bool CanRead
        {
            get { return sourceStream.CanRead; }
        }

        public override bool CanWrite
        {
            get { return sourceStream.CanWrite; }
        }

        public override bool CanSeek
        {
            get { return sourceStream.CanSeek; }
        }

        public override bool CanTimeout
        {
            get { return sourceStream.CanTimeout; }
        }

        public override long Position
        {
            get
            {
                return sourceStream.Position;
            }
            set
            {
                sourceStream.Position = Position;
            }
        }

        public override long Length
        {
            get { return sourceStream.Length; }
        }
    }
}
