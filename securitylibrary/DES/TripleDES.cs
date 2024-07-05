using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        DES des = new DES();
        public string Decrypt(string cipherText, List<string> key)
        {
            //throw new NotImplementedException();
            string PT = des.Decrypt(cipherText, key[1]);
            PT = des.Encrypt(PT, key[0]);
            PT = des.Decrypt(PT, key[1]);
            return PT;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            //throw new NotImplementedException();
            string CT = des.Encrypt(plainText, key[0]);
            CT = des.Decrypt(CT, key[1]);
            CT = des.Encrypt(CT, key[0]);
            return CT;
        }

        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
