using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        String alpha = "abcdefghijklmnopqrstuvwxyz";

        public string Analyse(string plainText, string cipherText)
        {
            return GetKey(plainText, cipherText);
        }

        private string GetKey(string plainText, string cipherText)
        {
            StringBuilder key = new StringBuilder();
            string keywordSubstring = "";

            for (int i = 0; i < plainText.Length; i++)

            {
                Char PT = plainText[i], CT = cipherText.ToLower()[i];

                if (alpha.IndexOf(CT) - alpha.IndexOf(PT) < 0)
                    key.Append(alpha[(alpha.IndexOf(CT) - alpha.IndexOf(PT)) + 26]);
                else
                    key.Append(alpha[alpha.IndexOf(CT) - alpha.IndexOf(PT)]);
            }
            for (int i = 0; i < key.Length; i++)
            {
                string subStr = "";
                for (int j = i; j < key.Length; j++)
                    subStr += key[j];

                if (plainText.Contains(subStr))
                    break;
                else
                    keywordSubstring += key[i];
            }
            return keywordSubstring;
        }

        private string GenerateExtendedKey(string plainText, string key)
        {
            // Extend the key to match the length of the plaintext
            string extendedKey = key;
            while (extendedKey.Length < plainText.Length)
            {
                extendedKey += plainText.Substring(0, plainText.Length - extendedKey.Length);
            }
            extendedKey = extendedKey.Substring(0, plainText.Length); // Trim to match plaintext length
            return extendedKey;
        }

        public string Decrypt(string cipherText, string key)
        {
            StringBuilder decryptedText = new StringBuilder();
            string ct = cipherText.ToLower();
            for (int i = 0; i < ct.Length; i++)
            {
                //get index of cipher
                int c = (alpha.IndexOf(ct[i]) - alpha.IndexOf(key[i]) % 26);
                //chek negative
                if (c < 0) c += 26;
                //complete key with rest of plain text
                key += alpha[c];

                decryptedText.Append(alpha[c]);
            }
            return decryptedText.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            // Extend the key to match the length of the plaintext
            string extendedKey = GenerateExtendedKey(plainText, key);
            StringBuilder encryptedText = new StringBuilder();

            for (int i = 0; i < plainText.Length; i++)
            {
                encryptedText.Append(alpha[(alpha.IndexOf(extendedKey[i]) + alpha.IndexOf(plainText[i])) % 26]);
            }

            return encryptedText.ToString();

        }
    }
}
