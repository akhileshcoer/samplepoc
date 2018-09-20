using Newtonsoft.Json;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace CertVerifyChain
{
    public class Data
    {
        public string CACertName { get; set; }
        public string CertToBeInstalled { get; set; }
        public string Password { get; set; }
    }

    class Program
    {
        static void PrintInfo(string s)
        {
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine(s);
            Console.ResetColor();
        }

        static void PrintLog(string s)
        {
            Console.ResetColor();
            Console.WriteLine(s);
        }

        static void PrintError(string s)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(s);
            Console.ResetColor();
        }


        static bool VerifyCAInstalled(string commonName)
        {
            using (var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
                var certificates = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, commonName, false);
                store.Close();

                return certificates.Count > 0;
            }
        }

        static void Main(string[] args)
        {
            PrintInfo($"Welcome {Environment.UserName}");

            PrintInfo("Start process");

            try
            {
                if (!File.Exists("Data.json"))
                {
                    PrintError("Data.json doesn't exists");
                    return;
                }

                var data = File.ReadAllText("Data.json");
                if (string.IsNullOrWhiteSpace(data))
                {
                    PrintError("File has no content");
                    return;
                }

                Data certData = null;
                try
                {
                    certData = JsonConvert.DeserializeObject<Data>(data);
                    if (string.IsNullOrWhiteSpace(certData.CACertName) || string.IsNullOrWhiteSpace(certData.CertToBeInstalled))
                    {
                        PrintError($"Both {nameof(certData.CACertName)} and {nameof(certData.CertToBeInstalled)} is required.");
                        return;
                    }

                    PrintLog("Checking if CA is installed on the box.");
                    if (!VerifyCAInstalled(certData.CACertName))
                    {
                        PrintLog("CA is not installed on the box. Please install CA.");
                        return;
                    }

                    var x509Certificate2 = GetCertToInstall(certData.CertToBeInstalled, certData.Password);

                    if (x509Certificate2 != null)
                    {
                        PrintLog("Importing certificate");
                        ImportCertificate(x509Certificate2);
                        PrintLog("Import done.");
                    }
                }
                catch (Exception e)
                {
                    PrintError("Error occured.");
                    PrintError(e.ToString());
                }
            }

            finally
            {
                PrintInfo("End process");
                Console.ReadKey();
            }
        }

        private static void ImportCertificate(X509Certificate2 x509Certificate2)
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
                store.Add(x509Certificate2);                
                store.Close();
            }
        }

        private static X509Certificate2 GetCertToInstall(string certToBeInstalled, string password)
        {
            PrintLog($"Reading certificate file @ {certToBeInstalled} with password:{password}");
            var newCert = new X509Certificate2(certToBeInstalled, password);
            PrintLog($"Reading certificate success");

            PrintLog($"Performing chain valiation");
            using (X509Chain chainVerify = new X509Chain())
            {
                chainVerify.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chainVerify.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;

                if (chainVerify.Build(newCert))
                {
                    PrintInfo("Certificate valiation Success.");
                    return newCert;
                }
            }

            PrintError("Certificate validation failed.");
            return null;
        }
    }
}
