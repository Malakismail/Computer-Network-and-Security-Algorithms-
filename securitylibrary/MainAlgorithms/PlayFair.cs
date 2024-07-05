using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            char[,] Matrix = new char[5, 5];

            char ch;
            int index_char = 0;
            //build the alphabets
            char[] alphabets = new char[26];

            for (int ind = 0; ind < 26; ind++)
            {
                alphabets[ind] = (char)('A' + ind);
            }
            //build the matrix matrix 5*5
            int i = 0;
            int j = 0;
            while (i < 5)
            {
                j = 0;

                while (j < 5)
                {
                    if (index_char < key.Length)
                    {
                        ch = Char.ToUpper(key[index_char]);

                    }
                    else
                    {


                        ch = chooseSuitableetter(alphabets, Matrix);

                    }
                    if (!checkIsCotain(ch, Matrix))
                    {
                        if (ch == 'j' || ch == 'J')
                        {
                            index_char++;
                            continue;
                        }
                        Matrix[i, j] = Char.ToUpper(ch);

                        j++;
                    }

                    index_char++;

                }

                i++;


            }

            // Decrypting the Ciphertext
            string decryptedText = "";
            bool tmp = false;
            for (int itr = 0; itr < cipherText.Length; itr += 2)
            {
                char firstChar = cipherText[itr];
                char secondChar = cipherText[itr + 1];


                int[] firstCharIndices = GetIndices(Matrix, Char.ToUpper(firstChar));
                int[] secondCharIndices = GetIndices(Matrix, Char.ToUpper(secondChar));

                string decryptedPair = "";
                if (firstCharIndices[0] == secondCharIndices[0])
                {
                    decryptedPair += Matrix[firstCharIndices[0], (firstCharIndices[1] + 4) % 5]; // + 4 to get the previous character
                    decryptedPair += Matrix[secondCharIndices[0], (secondCharIndices[1] + 4) % 5];
                }
                else if (firstCharIndices[1] == secondCharIndices[1])
                {
                    decryptedPair += Matrix[(firstCharIndices[0] + 4) % 5, firstCharIndices[1]];
                    decryptedPair += Matrix[(secondCharIndices[0] + 4) % 5, secondCharIndices[1]];
                }
                else
                {
                    decryptedPair += Matrix[firstCharIndices[0], secondCharIndices[1]];
                    decryptedPair += Matrix[secondCharIndices[0], firstCharIndices[1]];
                }

                if (decryptedText.Length >= 2)
                {
                    if (decryptedPair[0] == Char.ToUpper(decryptedText[decryptedText.Length - 2]) && decryptedText[decryptedText.Length - 1] == 'X')
                    {
                        decryptedText = decryptedText.Remove(decryptedText.Length - 1);
                        tmp = true;
                    }

                }


                decryptedText += decryptedPair;

            }
            if (decryptedText[decryptedText.Length - 1] == 'X')
                decryptedText = decryptedText.Remove(decryptedText.Length - 1);

            return decryptedText.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            char[,] Matrix = new char[5, 5];

            char ch;
            int index_char = 0;
            //build the alphabets
            char[] alphabets = new char[26];

            for (int ind = 0; ind < 26; ind++)
            {
                alphabets[ind] = (char)('A' + ind);
            }
            //build the matrix matrix 5*5
            int i = 0;
            int j = 0;
            while (i < 5)
            {
                j = 0;

                while (j < 5)
                {
                    if (index_char < key.Length)
                    {
                        ch = Char.ToUpper(key[index_char]);

                    }
                    else
                    {


                        ch = chooseSuitableetter(alphabets, Matrix);

                    }
                    if (!checkIsCotain(ch, Matrix))
                    {
                        if (ch == 'j' || ch == 'J')
                        {
                            index_char++;
                            continue;
                        }
                        Matrix[i, j] = Char.ToUpper(ch);

                        j++;
                    }

                    index_char++;

                }

                i++;


            }
            // Encrypt the plaintext using the matrix
            string encryptedText = "";
            for (int itr = 0; itr < plainText.Length; itr += 2)
            {
                char firstChar = plainText[itr];
                char secondChar;

                if (itr + 1 < plainText.Length && plainText[itr] != plainText[itr + 1])
                {
                    secondChar = plainText[itr + 1];
                }
                else
                {
                    secondChar = 'X';
                    itr--; // Repeat current iteration with the second character as 'X'
                }

                int[] firstCharIndices = GetIndices(Matrix, Char.ToUpper(firstChar));
                int[] secondCharIndices = GetIndices(Matrix, Char.ToUpper(secondChar));

                string encryptedPair = "";
                //same row 
                if (firstCharIndices[0] == secondCharIndices[0])
                {
                    encryptedPair += Matrix[firstCharIndices[0], (firstCharIndices[1] + 1) % 5];
                    encryptedPair += Matrix[secondCharIndices[0], (secondCharIndices[1] + 1) % 5];
                }
                //same column
                else if (firstCharIndices[1] == secondCharIndices[1])
                {
                    encryptedPair += Matrix[(firstCharIndices[0] + 1) % 5, firstCharIndices[1]];
                    encryptedPair += Matrix[(secondCharIndices[0] + 1) % 5, secondCharIndices[1]];
                }
                //diagonal 
                else
                {
                    encryptedPair += Matrix[firstCharIndices[0], secondCharIndices[1]];
                    encryptedPair += Matrix[secondCharIndices[0], firstCharIndices[1]];
                }

                encryptedText += encryptedPair;
            }

            return encryptedText;
        }
        public bool checkIsCotain(char target, char[,] Matrix)
        {

            bool found = false;

            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (Matrix[i, j] == target)
                    {
                        found = true;
                        break;
                    }
                }
                if (found)
                {
                    break;
                }
            }

            return found;




        }
        public char chooseSuitableetter(char[] alphabets, char[,] Matrix)
        {
            char target = ' ';

            for (int i = 0; i < alphabets.Length; i++)
            {
                target = alphabets[i];
                if (target == 'j' || target == 'J')
                    continue;
                if (!checkIsCotain(target, Matrix))
                {

                    break;
                }
            }

            return target;
        }
        private int[] GetIndices(char[,] matrix, char target)
        {
            int[] indices = new int[2];

            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (matrix[i, j] == target)
                    {
                        indices[0] = i;
                        indices[1] = j;
                        return indices;
                    }
                }
            }

            return indices;
        }

    }
}
