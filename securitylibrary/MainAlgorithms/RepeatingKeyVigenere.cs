using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            // Initialize a StringBuilder to store the found key
            StringBuilder key = new StringBuilder();
            string pt = plainText.ToUpper();
            // Loop through the length of the ciphertext
            for (int i = 0; i < cipherText.Length; i++)
            {

                // Calculate the difference between the corresponding characters in the plaintext and ciphertext
                int shift = (cipherText[i] - pt[i] + 26) % 26;

                // Append the character representing the difference to the key
                key.Append((char)(shift + 'A'));
            }
            string keyword = key.ToString().ToLower();
            Encrypt(plainText, keyword);
            Decrypt(cipherText, keyword);

            int keywordLength = DetermineKeywordLength(keyword);
            string keywordSubstring = keyword.Substring(0, keywordLength);
            // Return the found key
            return keywordSubstring;

        }

        public int DetermineKeywordLength(string ciphertext)
        {
            if (string.IsNullOrEmpty(ciphertext))
            {
                throw new ArgumentException("Ciphertext must not be empty.");
            }

            double[] icValues = new double[ciphertext.Length / 2];

            for (int i = 1; i < ciphertext.Length / 2; i++)
            {
                List<string> substrings = new List<string>();

                for (int j = 0; j < i; j++)
                {
                    substrings.Add(string.Join("", ciphertext.Where((c, index) => index % i == j)));
                }

                double sumIC = 0.0;
                foreach (var substring in substrings)
                {
                    Dictionary<char, int> frequencies = new Dictionary<char, int>();
                    int totalChars = 0;

                    foreach (char c in substring)
                    {
                        if (!char.IsLetter(c))
                            continue;

                        totalChars++;
                        if (frequencies.ContainsKey(c))
                            frequencies[c]++;
                        else
                            frequencies[c] = 1;
                    }

                    double ic = 0.0;
                    foreach (var frequency in frequencies)
                    {
                        ic += frequency.Value * (frequency.Value - 1);
                    }

                    if (totalChars > 1)
                    {
                        ic /= (totalChars * (totalChars - 1));
                        sumIC += ic;
                    }
                }

                icValues[i] = sumIC / i;
            }

            // Find the index with the highest IC value
            int keywordLength = Array.IndexOf(icValues, icValues.Max());
            return keywordLength;
        }

        public string Decrypt(string cipherText, string key)
        {
            StringBuilder decryptedText = new StringBuilder();
            string ct = cipherText.ToLower();
            for (int i = 0; i < ct.Length; i++)
            {
                int c = (ct[i] - key[i % key.Length] + 26) % 26;
                decryptedText.Append((char)(c + 'a'));
            }

            return decryptedText.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            StringBuilder encryptedText = new StringBuilder();


            for (int i = 0; i < plainText.Length; i++)
            {
                int c = (plainText[i] + key[i % key.Length] - 2 * 'a') % 26;
                encryptedText.Append((char)(c + 'a'));
            }

            return encryptedText.ToString();
        }
    }
}
