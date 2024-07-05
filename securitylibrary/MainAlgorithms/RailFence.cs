using System;
using System.Collections.Generic;
using System.Text;


namespace SecurityLibrary
{

    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            HashSet<int> possibleKeys = new HashSet<int>();
            cipherText = cipherText.ToLower();
            char firstChar = cipherText[1];
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == firstChar)
                {
                    possibleKeys.Add(i);
                }
            }
            foreach (int key in possibleKeys)
            {
                string encryptedText = Encrypt(plainText, key).ToLower();
                if (String.Equals(cipherText, encryptedText))
                {
                    return key;
                }
            }
            return 0;

        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();

            //operation reverse
            //ceiling part to get the key
            int plain_len = cipherText.Length / key;
            if (cipherText.Length % key != 0)
            {
                plain_len++;
            }
            string result = Encrypt(cipherText, plain_len).ToLower();
            return result;
        }

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();

            // Create a list of lists to represent the rail fence pattern
            List<List<char>> pattern_table = new List<List<char>>();
            //ceiling part   -----> Calc num of chars per rail
            int num_per_rail = plainText.Length / key;
            if (plainText.Length % key != 0)
            {
                num_per_rail++;
            }

            for (int i = 0; i < key; i++)
            {
                pattern_table.Add(new List<char>());
            }
            // fill the rail pattern with chars from the plaintext
            int count = 0;
            for (int i = 0; i < num_per_rail; i++)
            {
                for (int j = 0; j < key && count < plainText.Length; j++)
                {
                    pattern_table[j].Add(plainText[count++]);
                }
            }

            // Construct the cipher text 
            StringBuilder cipherText = new StringBuilder();
            foreach (List<char> rail in pattern_table)
            {
                foreach (char c in rail)
                {
                    cipherText.Append(c);
                }
            }
            string result = cipherText.ToString().ToUpper();
            return result;
        }
    }
}
