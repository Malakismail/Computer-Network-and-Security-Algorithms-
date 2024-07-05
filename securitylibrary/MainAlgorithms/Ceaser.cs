using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            string encryptedChars = "";

            for (int i = 0; i < plainText.Length; i++)
            {
                char c = plainText[i];

                if (char.IsLetter(c))
                {
                    char basechar;
                    if (char.IsUpper(c))
                    {
                        basechar = 'A';
                    }
                    else
                    {
                        basechar = 'a';
                    }
                    char encryptedChar = (char)((((c + key) - basechar + 26) % 26) + basechar);
                    encryptedChars += encryptedChar;
                }
                else
                {
                    encryptedChars += c;
                }
            }

            return encryptedChars;

        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            string decryptedText = "";

            foreach (char c in cipherText)
            {
                if (char.IsLetter(c))
                {
                    char basechar;
                    if (char.IsUpper(c))
                    {
                        basechar = 'A';
                    }
                    else
                    {
                        basechar = 'a';
                    }
                    char decryptedChar = (char)((((c - key) - basechar + 26) % 26) + basechar);
                    decryptedText += decryptedChar;
                }
                else
                {
                    decryptedText += c;
                }
            }

            return decryptedText;

        }

        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            for (int key = 0; key < 26; key++)
            {
                string cryptedText = Encrypt(plainText, key);
                if (cryptedText.ToLower().Equals(cipherText.ToLower()))
                {

                    return key;
                }
            }

            // If no matching key is found
            return -1;

        }
    }
}
