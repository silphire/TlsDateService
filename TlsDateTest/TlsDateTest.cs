using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace TlsDateTest
{
    [TestClass]
    public class TlsDateTest
    {
        [TestMethod]
        public void TestGenerateInstance()
        {
            Assert.IsNotNull(new TlsDate.TlsDate());
        }

        [TestMethod]
        public void TestTlsConnect()
        {
            TlsDate.TlsDate tlsDate = new TlsDate.TlsDate();
            tlsDate.serverName = "www.google.com";
            Assert.AreNotEqual(0u, tlsDate.GetCurrentDateFromServer());
            Assert.IsTrue(tlsDate.validCredential);
        }
    }
}
