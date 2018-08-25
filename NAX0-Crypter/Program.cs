using System;
using System.IO;

namespace NAX0_Crypter
{
    class Program
    {
        static void Main(string[] args)
        {
            var Usage = "\nUsage: NAX0-Crypter.exe <-d to decrypt, -e to encrypt> <SD Seed> <Relative Path> <Input NCA> <Output NCA>";
            var Error = "\nFatal error: missing keys.txt file.\nMake sure you have a file named \"keys.txt\" in this directory with the following keys present:\n\nsd_card_kek_source\nsd_card_nca_key_source\naes_kek_generation_source\naes_key_generation_source\nmaster_key_00";
            var Done = "\nDone!";

            if (File.Exists("keys.txt"))
            {
                if (args.Length == 5)
                {
                    if (args[0] == "-d")
                    {
                        Crypto.DecryptNAX0(args[1], args[2], args[3], args[4]);
                        Console.WriteLine(Done);
                    }
                    else if (args[0] == "-e")
                    {
                        Crypto.EncryptNAX0(args[1], args[2], args[3], args[4]);
                        Console.WriteLine(Done);
                    }
                    else
                    {
                        Console.WriteLine(Usage);
                    }
                }
                else
                {
                    Console.WriteLine(Usage);
                }
            }
            else
            {
                Console.WriteLine(Error);
            }
        }
    }
}
