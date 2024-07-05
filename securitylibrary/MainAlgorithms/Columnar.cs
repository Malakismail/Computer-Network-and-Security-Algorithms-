using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            List<int> key = new List<int>();

            // Find the best columnar key
            key = FindColumnarKey(plainText, cipherText);

            return key;

        }

        private List<int> FindColumnarKey(string plainText, string cipherText)
        {
            List<int> key = new List<int>();

            for (int i = 2; i < 100; i++)
            {
                int depth = i;
                int width = (int)Math.Ceiling((double)((double)plainText.Length / depth));
                char[,] table = DivideStringIntoColumns(plainText, depth);

                if (CheckColumnsExistInString(table, cipherText))
                {
                    for (int j = 0; j < width; j++)
                    {
                        var col = new StringBuilder();

                        for (int k = 0; k < depth; k++)
                        {
                            if (table[k, j] != '\0')
                            {
                                col.Append(table[k, j]);
                            }
                        }

                        key.Add(cipherText.IndexOf(col.ToString()) / depth + 1);
                    }

                    break;
                }
            }

            return key;
        }

        private char[,] DivideStringIntoColumns(string text, int number_of_cols)
        {
            int depth = number_of_cols;
            int width = (int)Math.Ceiling((double)((double)text.Length / depth));

            char[,] table = new char[depth, width];

            int row = 0;
            int col = 0;

            for (int i = 0; i < text.Length; i++)
            {
                table[row, col] = text[i];

                col++;
                if (col == width)
                {
                    col = 0;
                    row = (row + 1) % depth;
                }
            }

            return table;
        }

        private bool CheckColumnsExistInString(char[,] columns, string cipher)
        {
            int width = columns.GetLength(0);
            int depth = columns.GetLength(1);

            for (int j = 0; j < depth; j++)
            {
                var col = new StringBuilder();

                for (int i = 0; i < width; i++)
                {
                    if (columns[i, j] != '\0')
                    {
                        col.Append(columns[i, j]);
                    }
                }

                if (!cipher.Contains(col.ToString()))
                {
                    return false;
                }
            }

            return true;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            int width = key.Count;
            int depth = (int)Math.Ceiling((double)((double)cipherText.Length / width));

            char[,] table = new char[depth, width];

            // Populate the table with the cipher text
            PopulateTable(cipherText, false, table, width, depth);

            List<int> decryption_key = new List<int>();
            for (int i = 0; i < key.Count; i++)
            {
                decryption_key.Add(-1);
            }

            // Create the decryption key
            for (int i = 0; i < key.Count; i++)
            {
                decryption_key[key[i] - 1] = i;
            }

            char[,] plainTable = new char[depth, width];

            // Rearrange the table based on the key
            for (int i = 0; i < key.Count; i++)
            {
                int col_number = decryption_key.IndexOf(i);

                for (int j = 0; j < depth; j++)
                {
                    plainTable[j, i] = table[j, col_number];

                }
            }

            var plain = new StringBuilder();

            // Extract the plain text from the rearranged table
            for (int i = 0; i < depth; i++)
            {
                for (int j = 0; j < width; j++)
                {
                    plain.Append(plainTable[i, j]);
                }
            }

            return plain.ToString();

        }

        public string Encrypt(string plainText, List<int> key)
        {
            //throw new NotImplementedException();
            int width = key.Count;
            int depth = (int)Math.Ceiling((double)((double)plainText.Length / width));

            char[,] table = new char[depth, width];

            // Populate the table with the plain text
            PopulateTable(plainText, true, table, width, depth);

            var cipher = new StringBuilder();

            // Read the cipher text from the table based on the key
            for (int i = 0; i < key.Count; i++)
            {
                int col_number = key.IndexOf(i + 1);

                for (int j = 0; j < depth; j++)
                {
                    cipher.Append(table[j, col_number]);
                }
            }

            return cipher.ToString();

        }

        private void PopulateTable(string Text, bool flag, char[,] table, int width, int depth)
        {
            int row = 0;
            int col = 0;

            // plain text
            if (flag == true)
            {
                for (int i = 0; i < Text.Length; i++)
                {
                    table[row, col] = Text[i];

                    col++;
                    if (col == width)
                    {
                        col = 0;
                        row = (row + 1) % depth;
                    }
                }
            }
            else
            {
                // cipher text
                for (int i = 0; i < Text.Length; i++)
                {
                    table[row, col] = Text[i];

                    row++;
                    if (row == depth)
                    {
                        col = (col + 1) % width;
                        row = 0;
                    }
                }
            }
        }
    }
}
