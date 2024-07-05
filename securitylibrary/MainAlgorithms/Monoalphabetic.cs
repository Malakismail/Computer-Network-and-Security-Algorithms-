using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        private const string Alphabet = "abcdefghijklmnopqrstuvwxyz";

        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();

            // key
            SortedDictionary<string, string> keydic = new SortedDictionary<string, string>();

            cipherText = cipherText.ToLower();
            List<string> cipher_text = cipherText.Select(c => c.ToString()).ToList();

            List<string> missing = new List<string>();

            var key = new StringBuilder();
            keydic = Key_Dic(cipher_text, plainText, keydic);

            for (char c = 'a'; c <= 'z'; c++)
            {
                if (!keydic.ContainsKey(c.ToString()))
                {
                    missing.Add(c.ToString());
                }
            }

            int counter = 0;
            if (missing.Count != 0)
            {
                for (char c = 'a'; c <= 'z'; c++)
                {
                    if (!keydic.ContainsValue(c.ToString()) && counter < missing.Count)
                    {
                        keydic.Add(missing[counter], c.ToString());
                        counter++;
                    }
                }
            }

            for (char c = 'a'; c <= 'z'; c++)
            {
                key.Append(keydic[c.ToString()]);
            }

            return key.ToString();

        }

        public SortedDictionary<string, string> Key_Dic(List<string> cipherTex, string plainText, SortedDictionary<string, string> keydic)
        {
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i].Equals('a') && !keydic.ContainsKey("a"))
                    keydic.Add("a", cipherTex[i]);
                if (plainText[i].Equals('b') && !keydic.ContainsKey("b"))
                    keydic.Add("b", cipherTex[i]);
                if (plainText[i].Equals('c') && !keydic.ContainsKey("c"))
                    keydic.Add("c", cipherTex[i]);
                if (plainText[i].Equals('d') && !keydic.ContainsKey("d"))
                    keydic.Add("d", cipherTex[i]);
                if (plainText[i].Equals('e') && !keydic.ContainsKey("e"))
                    keydic.Add("e", cipherTex[i]);
                if (plainText[i].Equals('f') && !keydic.ContainsKey("f"))
                    keydic.Add("f", cipherTex[i]);
                if (plainText[i].Equals('g') && !keydic.ContainsKey("g"))
                    keydic.Add("g", cipherTex[i]);
                if (plainText[i].Equals('h') && !keydic.ContainsKey("h"))
                    keydic.Add("h", cipherTex[i]);
                if (plainText[i].Equals('i') && !keydic.ContainsKey("i"))
                    keydic.Add("i", cipherTex[i]);
                if (plainText[i].Equals('j') && !keydic.ContainsKey("j"))
                    keydic.Add("j", cipherTex[i]);
                if (plainText[i].Equals('k') && !keydic.ContainsKey("k"))
                    keydic.Add("k", cipherTex[i]);
                if (plainText[i].Equals('l') && !keydic.ContainsKey("l"))
                    keydic.Add("l", cipherTex[i]);
                if (plainText[i].Equals('m') && !keydic.ContainsKey("m"))
                    keydic.Add("m", cipherTex[i]);
                if (plainText[i].Equals('n') && !keydic.ContainsKey("n"))
                    keydic.Add("n", cipherTex[i]);
                if (plainText[i].Equals('o') && !keydic.ContainsKey("o"))
                    keydic.Add("o", cipherTex[i]);
                if (plainText[i].Equals('p') && !keydic.ContainsKey("p"))
                    keydic.Add("p", cipherTex[i]);
                if (plainText[i].Equals('q') && !keydic.ContainsKey("q"))
                    keydic.Add("q", cipherTex[i]);
                if (plainText[i].Equals('r') && !keydic.ContainsKey("r"))
                    keydic.Add("r", cipherTex[i]);
                if (plainText[i].Equals('s') && !keydic.ContainsKey("s"))
                    keydic.Add("s", cipherTex[i]);
                if (plainText[i].Equals('t') && !keydic.ContainsKey("t"))
                    keydic.Add("t", cipherTex[i]);
                if (plainText[i].Equals('u') && !keydic.ContainsKey("u"))
                    keydic.Add("u", cipherTex[i]);
                if (plainText[i].Equals('v') && !keydic.ContainsKey("v"))
                    keydic.Add("v", cipherTex[i]);
                if (plainText[i].Equals('w') && !keydic.ContainsKey("w"))
                    keydic.Add("w", cipherTex[i]);
                if (plainText[i].Equals('x') && !keydic.ContainsKey("x"))
                    keydic.Add("x", cipherTex[i]);
                if (plainText[i].Equals('y') && !keydic.ContainsKey("y"))
                    keydic.Add("y", cipherTex[i]);
                if (plainText[i].Equals('z') && !keydic.ContainsKey("z"))
                    keydic.Add("z", cipherTex[i]);
            }
            return keydic;
        }

        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            // Build the decryption dictionary from the key
            Dictionary<char, char> decryptionDictionary = new Dictionary<char, char>();
            for (int i = 0; i < Alphabet.Length; i++)
            {
                decryptionDictionary[key[i]] = Alphabet[i];
            }

            // Decrypt the cipher text
            StringBuilder plainTextBuilder = new StringBuilder();
            foreach (char c in cipherText)
            {
                char decryptedChar = char.IsLower(c) ? char.ToLower(decryptionDictionary[c]) : char.ToUpper(decryptionDictionary[char.ToLower(c)]);
                plainTextBuilder.Append(decryptedChar);
            }

            return plainTextBuilder.ToString();

        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            // Build the encryption dictionary from the key
            Dictionary<char, char> encryptionDictionary = new Dictionary<char, char>();
            for (int i = 0; i < Alphabet.Length; i++)
            {
                encryptionDictionary[Alphabet[i]] = key[i];
            }

            // Encrypt the plain text
            StringBuilder cipherTextBuilder = new StringBuilder();
            foreach (char c in plainText)
            {
                char encryptedChar = char.IsLower(c) ? char.ToLower(encryptionDictionary[c]) : char.ToUpper(encryptionDictionary[char.ToLower(c)]);
                cipherTextBuilder.Append(encryptedChar);
            }

            return cipherTextBuilder.ToString();

        }


        /// Frequency table:
        /// E: 12.51% , T:	9.25 , A: 8.04 , O: 7.60 , I: 7.26 , N: 7.09 , S: 6.54 , R:	6.12 , H: 5.49 , L: 4.14 , D: 3.99
        /// C: 3.06 , U: 2.71 , M: 2.53 , F: 2.30 , P: 2.00 , G: 1.96 , W: 1.92 , Y: 1.73 , B:	1.54 , V: 0.99 , K:	0.67
        /// X:	0.19 , J: 0.16 , Q: 0.11 , Z: 0.09


        public string AnalyseUsingCharFrequency(string cipher)
        {
            Dictionary<char, float> FreqDict = new Dictionary<char, float>()
            {
                {'e', 12.51f}, {'t', 9.25f}, {'a', 8.04f}, {'o', 7.60f}, {'i', 7.26f},
                {'n', 7.09f}, {'s', 6.54f}, {'r', 6.12f}, {'h', 5.49f}, {'l', 4.14f},
                {'d', 3.99f}, {'c', 3.06f}, {'u', 2.71f}, {'m', 2.53f}, {'f', 2.30f},
                {'p', 2.00f}, {'g', 1.96f}, {'w', 1.92f}, {'y', 1.73f}, {'b', 1.54f},
                {'v', 0.99f}, {'k', 0.67f}, {'x', 0.19f}, {'j', 0.16f}, {'q', 0.11f},
                {'z', 0.09f}
            };
            Dictionary<char, float> charCount = new Dictionary<char, float>();

            cipher = cipher.ToLower();
            StringBuilder decryptedText = new StringBuilder();
            char[] key = new char[26];
            foreach (var c in cipher)
            {
                if (char.IsLetter(c))
                {
                    if (charCount.ContainsKey(c))
                        charCount[c]++;
                    else
                        charCount[c] = 1;
                }
                decryptedText.Append(c);
            }

            var sortedDict = charCount.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value).Keys.ToList();

            for (int i = 0; i < FreqDict.Count; i++)
            {
                int position = Alphabet.IndexOf(FreqDict.Keys.ElementAt(i));
                key[position] = sortedDict[i];
            }

            for (int i = 0; i < decryptedText.Length; i++)
            {
                char c = decryptedText[i];
                if (char.IsLetter(c))
                {
                    int index = Array.IndexOf(key, c);
                    decryptedText[i] = Alphabet[index];
                }
            }

            return decryptedText.ToString();

        }
    }
}
