using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using static NAX0_Crypter.Xts;

namespace NAX0_Crypter
{
    internal class Crypto
    {
        public static string[] Keys = File.ReadAllLines("keys.txt");

        public static byte[] SDKEK = B(Keys.FirstOrDefault(T => T.StartsWith("sd_card_kek_source")).Split(Convert.ToChar("="))[1].Trim());
        public static byte[] SDKey = B(Keys.FirstOrDefault(T => T.StartsWith("sd_card_nca_key_source")).Split(Convert.ToChar("="))[1].Trim());
        public static byte[] AESKEK = B(Keys.FirstOrDefault(T => T.StartsWith("aes_kek_generation_source")).Split(Convert.ToChar("="))[1].Trim());
        public static byte[] AESKey = B(Keys.FirstOrDefault(T => T.StartsWith("aes_key_generation_source")).Split(Convert.ToChar("="))[1].Trim());
        public static byte[] Masterkey = B(Keys.FirstOrDefault(T => T.StartsWith("master_key_00")).Split(Convert.ToChar("="))[1].Trim());

        public static byte[] Pad(int Count)
        {
            return Enumerable.Repeat((byte)0x00, Count).ToArray();
        }

        public static byte[] GenerateRandomKey(int Length)
        {
            byte[] RandomKey = new byte[Length];
            var RNG = new RNGCryptoServiceProvider();
            RNG.GetBytes(RandomKey);
            return RandomKey;
        }

        public static byte[] Align(ref byte[] Input, int Pad)
        {
            int Length = (Input.Length + Pad - 1) / Pad * Pad;
            Array.Resize(ref Input, Length);
            return Input;
        }

        public static byte[] B(string Hex)
        {
            return Enumerable.Range(0, Hex.Length)
                  .Where(x => x % 2 == 0)
                  .Select(x => Convert.ToByte(Hex.Substring(x, 2), 16))
                  .ToArray();
        }

        public static string X(byte[] Hex)
        {
            return BitConverter.ToString(Hex).Replace("-", "");
        }

        public static byte[] GenerateSHA256HMAC(byte[] Data, byte[] Key)
        {
            return new HMACSHA256(Key).ComputeHash(Data);
        }

        public static byte[] ECB(byte[] Data, byte[] Key, bool Encrypt)
        {
            RijndaelManaged Unwrap = new RijndaelManaged
            {
                Mode = CipherMode.ECB,
                Key = Key,
                Padding = PaddingMode.None
            };
            ICryptoTransform Transform;
            if (Encrypt)
            {
                Transform = Unwrap.CreateEncryptor();
            }
            else
            {
                Transform = Unwrap.CreateDecryptor();
            }
            return Transform.TransformFinalBlock(Data, 0, Data.Length);
        }

        public static byte[] XTS(byte[] Key1, byte[] Key2, int SectorSize, byte[] Data, ulong Sector, bool Encrypt)
        {
            byte[] TransformedBytes, BlockData;
            Xts XTS128 = XtsAes128.Create(Key1, Key2);
            int Blocks;
            var MemStrm = new MemoryStream();
            var Writer = new BinaryWriter(MemStrm);
            XtsCryptoTransform CryptoTransform;
            if (Encrypt)
            {
                CryptoTransform = XTS128.CreateEncryptor();
            }
            else
            {
                CryptoTransform = XTS128.CreateDecryptor();
            }
            BlockData = new byte[SectorSize];
            Blocks = Data.Length / SectorSize;
            for (int i = 0; i < Blocks; i++)
            {
                CryptoTransform.TransformBlock(Data, i * SectorSize, SectorSize, BlockData, 0, Sector++);
                Writer.Write(BlockData);
            }
            TransformedBytes = MemStrm.ToArray();
            return TransformedBytes;
        }

        public static void DecryptNAX0(string Seed, string Path, string File, string Output)
        {
            var EncryptedFile = System.IO.File.OpenRead(File);

            var Rd = new BinaryReader(EncryptedFile);

            byte[] Hash = Rd.ReadBytes(0x20);

            byte[] Header = Rd.ReadBytes(0x60);

            if (Encoding.ASCII.GetString(Header.Take(0x4).ToArray()) != "NAX0")
            {
                throw new Exception("Invalid NAX0 magic.");
            }

            Rd.ReadBytes(0x3F80);

            int Size = BitConverter.ToInt32(Header, 0x28);

            byte[] SDKeySrc = new byte[0x20];

            byte[] KEK = ECB(AESKEK, Masterkey, false);
            byte[] Source = ECB(SDKEK, KEK, false);
            byte[] SDKEKTrue = ECB(AESKey, Source, false);

            for (int i = 0; i < 0x20; i++)
            {
                SDKeySrc[i] = (byte)(SDKey[i] ^ B(Seed)[i & 0xF]);
            }

            byte[] SdUniqueKey = ECB(SDKeySrc, SDKEKTrue, false);

            byte[] SpecificKey0 = SdUniqueKey.Take(0x10).ToArray();
            byte[] SpecificKey1 = SdUniqueKey.Skip(0x10).ToArray();

            byte[] MAC = GenerateSHA256HMAC(Encoding.ASCII.GetBytes(Path), SpecificKey0);

            byte[] NAXKek0 = MAC.Take(0x10).ToArray();
            byte[] NAXKek1 = MAC.Skip(0x10).ToArray();

            byte[] EncryptedKey0 = Header.Skip(0x8).Take(0x10).ToArray();
            byte[] EncryptedKey1 = Header.Skip(0x18).Take(0x10).ToArray();

            byte[] NAXKey0 = ECB(EncryptedKey0, NAXKek0, false);
            byte[] NAXKey1 = ECB(EncryptedKey1, NAXKek1, false);

            byte[] Data = Header.Take(0x8).Concat(NAXKey0.Concat(NAXKey1.Concat(Header.Skip(0x28)))).ToArray();

            if (X(Hash) != X(GenerateSHA256HMAC(SpecificKey1, Data)))
            {
                throw new Exception("Invalid HMAC.");
            }

            var OutputFile = System.IO.File.OpenWrite(Output);

            var Writer = new BinaryWriter(OutputFile);

            byte[] Buf = new byte[0x4000];

            foreach (int i in Enumerable.Range(0, ((int)Math.Ceiling((double)Size / 0x4000) * 0x4000) / 0x4000))
            {
                Array.Clear(Buf, 0, 0x4000);
                EncryptedFile.Read(Buf, 0, 0x4000);
                Writer.Write(XTS(NAXKey0, NAXKey1, 0x4000, Buf, (ulong)i, false));
            }

            OutputFile.SetLength(Size);

            EncryptedFile.Dispose();

            Writer.Dispose();

            OutputFile.Dispose();
        }

        public static void EncryptNAX0(string Seed, string Path, string File, string Output)
        {
            var InputFile = System.IO.File.OpenRead(File);
            var Out = System.IO.File.OpenWrite(Output);
            var OutputFile = new BinaryWriter(Out);

            byte[] Key1 = GenerateRandomKey(0x10);
            byte[] Key2 = GenerateRandomKey(0x10);

            int Magic = 0x3058414e;
            long Size = InputFile.Length;

            var Strm = new MemoryStream();
            var Header = new BinaryWriter(Strm);
            Header.Write(Magic);
            Header.Write(0);
            Header.Write(Key1);
            Header.Write(Key2);
            Header.Write(Size);
            Header.Write(Pad(0x30));
            Header.Dispose();
            byte[] FinalHeader = Strm.ToArray();
            Strm.Dispose();

            byte[] SDKeySrc = new byte[0x20];

            byte[] KEK = ECB(AESKEK, Masterkey, false);
            byte[] Source = ECB(SDKEK, KEK, false);
            byte[] SDKEKTrue = ECB(AESKey, Source, false);

            for (int i = 0; i < 0x20; i++)
            {
                SDKeySrc[i] = (byte)(SDKey[i] ^ B(Seed)[i & 0xF]);
            }

            byte[] SdUniqueKey = ECB(SDKeySrc, SDKEKTrue, false);

            byte[] SpecificKey0 = SdUniqueKey.Take(0x10).ToArray();
            byte[] SpecificKey1 = SdUniqueKey.Skip(0x10).ToArray();

            byte[] Hash = GenerateSHA256HMAC(SpecificKey1, FinalHeader);

            byte[] MAC = GenerateSHA256HMAC(Encoding.ASCII.GetBytes(Path), SpecificKey0);

            byte[] NAXKek0 = MAC.Take(0x10).ToArray();
            byte[] NAXKek1 = MAC.Skip(0x10).ToArray();

            byte[] NAXKey0 = ECB(Key1, NAXKek0, true);
            byte[] NAXKey1 = ECB(Key2, NAXKek1, true);

            byte[] Data = FinalHeader.Take(0x8).Concat(NAXKey0.Concat(NAXKey1.Concat(FinalHeader.Skip(0x28)))).ToArray();

            OutputFile.Write(Hash);
            OutputFile.Write(Data);
            OutputFile.Write(GenerateRandomKey(0x3F80));

            byte[] Buf = new byte[0x4000];

            foreach (int i in Enumerable.Range(0, ((int)Math.Ceiling((double)Size / 0x4000) * 0x4000) / 0x4000))
            {
                Array.Clear(Buf, 0, 0x4000);
                InputFile.Read(Buf, 0, 0x4000);
                OutputFile.Write(XTS(Key1, Key2, 0x4000, Buf, (ulong)i, true));
            }

            Out.SetLength(Size + 0x4000);

            InputFile.Dispose();

            Out.Dispose();

            OutputFile.Dispose();
        }
    }
}