using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        DESCryptoServiceProvider desServerProvider = new DESCryptoServiceProvider();

        byte[] hexToByte(string hexStr)
        {
            byte[] byteArray = new byte[hexStr.Length / 2];
            for (int i = 0; i < hexStr.Length; i += 2)
                byteArray[i / 2] = Convert.ToByte(hexStr.Substring(i, 2), 16);

            return byteArray;
        }

        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            byte[] cipherBytes, keyBytes, decryptedBytes;
            cipherBytes = hexToByte(cipherText.Substring(2));
            keyBytes = hexToByte(key.Substring(2));
            using (desServerProvider)
            {
                desServerProvider.Key = keyBytes;
                desServerProvider.Mode = CipherMode.ECB;
                desServerProvider.Padding = PaddingMode.Zeros;

                ICryptoTransform decryptor = desServerProvider.CreateDecryptor();
                decryptedBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                StringBuilder hexBuilder = new StringBuilder(decryptedBytes.Length * 2);
                foreach (byte b in decryptedBytes)
                    hexBuilder.Append(b.ToString("X2"));
                return "0x" + hexBuilder.ToString();
            }

        }

        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            byte[] PT_Bytes, keyBytes, cipherBytes;
            PT_Bytes = hexToByte(plainText.Substring(2));
            keyBytes = hexToByte(key.Substring(2));
            using (desServerProvider)
            {
                desServerProvider.Key = keyBytes;
                desServerProvider.Mode = CipherMode.ECB;
                desServerProvider.Padding = PaddingMode.Zeros;
                ICryptoTransform encryptor = desServerProvider.CreateEncryptor();
                cipherBytes = encryptor.TransformFinalBlock(PT_Bytes, 0, PT_Bytes.Length);

                StringBuilder hexBuilder = new StringBuilder(cipherBytes.Length * 2);
                foreach (byte b in cipherBytes)
                    hexBuilder.Append(b.ToString("X2"));
                return "0x" + hexBuilder.ToString();
            }
        }
    }
}
