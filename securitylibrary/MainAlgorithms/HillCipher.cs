using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        //done
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<List<int>> CT2 = new List<List<int>>();
            List<List<int>> PT2 = new List<List<int>>();

            int m = plainText.Count / 2;

            for (int i = 0; i < plainText.Count; i += 2)
            {
                List<int> CTcolumns = new List<int>
                {
                    cipherText[i],
                    cipherText[i + 1]
                };
                CT2.Add(CTcolumns);

                List<int> PTcolumns = new List<int>
                {
                    plainText[i],
                    plainText[i + 1]
                };
                PT2.Add(PTcolumns);
            }
            List<List<int>> CTrow = new List<List<int>>();
            List<List<int>> PTrow = new List<List<int>>();

            for (int i = 0; i < m - 1; i++) // two times
            {
                for (int j = i + 1; j < m; j++)
                {
                    List<int> CTcolumns = new List<int>
                    {
                        CT2[i][0],
                        CT2[i][1],
                        CT2[j][0],
                        CT2[j][1]
                    };
                    CTrow.Add(CTcolumns);

                    List<int> PTcolumns = new List<int>
                    {
                        PT2[i][0],
                        PT2[i][1],
                        PT2[j][0],
                        PT2[j][1]
                    };
                    PTrow.Add(PTcolumns);
                }
            }

            for (int i = 0; i < PTrow.Count; i++)
            {
                List<int> detcorrection = new List<int>(4);
                for (int j = 0; j < 4; j++)
                {
                    int correctedValue = PTrow[i][j] % 26;
                    if (correctedValue < 0)
                        correctedValue += 26;
                    detcorrection.Add(correctedValue);
                }

                int A = (detcorrection[0] * detcorrection[3]) - (detcorrection[1] * detcorrection[2]);
                int DetConstant = (A != 1 && A != -1) ? CalculateDetConstant(A) : A;

                List<int> PlainInversion = new List<int>
                {
                    detcorrection[3] * DetConstant,
                    detcorrection[1] * DetConstant * -1,
                    detcorrection[2] * DetConstant * -1,
                    detcorrection[0] * DetConstant
                };

                List<int> keytwomultwo = new List<int>
                {
                    (CTrow[i][0] * PlainInversion[0]) + (CTrow[i][2] * PlainInversion[1]),
                    (CTrow[i][0] * PlainInversion[2]) + (CTrow[i][2] * PlainInversion[3]),
                    (CTrow[i][1] * PlainInversion[0]) + (CTrow[i][3] * PlainInversion[1]),
                    (CTrow[i][1] * PlainInversion[2]) + (CTrow[i][3] * PlainInversion[3])
                };

                List<int> correctkey = new List<int>(4);
                for (int j = 0; j < 4; j++)
                {
                    int correctedValue = keytwomultwo[j] % 26;
                    if (correctedValue < 0)
                        correctedValue += 26;
                    correctkey.Add(correctedValue);
                }

                List<int> ReturnedCipher = Encrypt(plainText, correctkey);
                if (ReturnedCipher.SequenceEqual(cipherText))
                {
                    return correctkey;
                }
            }

            throw new InvalidAnlysisException();
        }

        // Helper method to calculate the determinant constant using the extended Euclidean algorithm
        private static int CalculateDetConstant(int A)
        {
            int a = A;
            int b = 26;
            int x0 = 1, x1 = 0, xn = 1;
            int y0 = 0, y1 = 1, yn;

            int modulus = a % b;

            while (modulus > 0)
            {
                int div = a / b;
                yn = y0 - div * y1;
                xn = x0 - div * x1;

                x0 = x1; y0 = y1; x1 = xn; y1 = yn;
                a = b; b = modulus; modulus = a % b;
            }

            int DetConstant = xn;
            if (DetConstant < 0)
            {
                DetConstant += 26;
            }

            return DetConstant;
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            //throw new NotImplementedException();

            int num = 26;
            List<int> keycorrection = new List<int>();
            int keyLength = key.Count;
            for (int i = 0; i < keyLength; i++)
            {
                if (key[i] >= num)
                {
                    keycorrection.Insert(i, (key[i] % num));
                }
                else if (key[i] < 0)
                {
                    keycorrection.Insert(i, (key[i] % num) + num);
                }

                else
                    keycorrection.Insert(i, key[i]);
            }
            int m = 4;
            List<int> keyInversion = new List<int>();
            int KeyCounter = keycorrection.Count;
            int keynum = key.Count;
            if (KeyCounter == m)
            {
                int InitDeterminant = (key[0] * key[3]) - (key[1] * key[2]);
                if ((InitDeterminant % 2) == 0 || InitDeterminant == 0 || (InitDeterminant % num) == 0)
                {
                    throw new InvalidAnlysisException();
                }
                int A;
                int DetConstant;
                int firstHalf = (keycorrection[0] * keycorrection[3]);
                int secondHalf = (keycorrection[1] * keycorrection[2]);
                A = (firstHalf - secondHalf);

                if (A != 1 && A != -1)
                {
                    int a = A;
                    int b = num;

                    int x0 = 1, x1 = 0, xn = 1;
                    int y0 = 0, y1 = 1, yn;

                    int modulus = a % b;

                    while (modulus > 0)
                    {
                        int div = a / b;
                        yn = y0 - div * y1;
                        xn = x0 - div * x1;


                        x0 = x1; x1 = xn;
                        y0 = y1; y1 = yn;
                        a = b; b = modulus; modulus = a % b;
                    }
                    DetConstant = xn;
                    if (DetConstant < 0)
                    {
                        DetConstant += num;
                    }
                }
                else
                {
                    DetConstant = A;
                }
                keyInversion.Insert(0, keycorrection[3] * DetConstant);
                keyInversion.Insert(1, keycorrection[1] * DetConstant * -1);
                keyInversion.Insert(2, keycorrection[2] * DetConstant * -1);
                keyInversion.Insert(3, keycorrection[0] * DetConstant);
            }
            else if (keynum > m)
            {
                int RuleOne = 0;
                int cofactors1 = (keycorrection[4] * keycorrection[8] - keycorrection[5] * keycorrection[7]);
                int cofactors2 = (keycorrection[3] * keycorrection[8] - keycorrection[5] * keycorrection[6]);
                int cofactors3 = (keycorrection[3] * keycorrection[7] - keycorrection[4] * keycorrection[6]);
                int Det3mul3 = ((keycorrection[0] * cofactors1) - (keycorrection[1] * cofactors2) + (keycorrection[2] * cofactors3));
                if ((Det3mul3 % 2) == 0 || Det3mul3 == 0 || (Det3mul3 % num) == 0)
                {
                    throw new InvalidAnlysisException();
                }

                if (Det3mul3 >= num)
                {
                    RuleOne = num;

                }
                else if (Det3mul3 < num)
                {
                    RuleOne = Det3mul3;
                }
                int count = 2;
                for (int j = RuleOne; j >= count; j--)
                {
                    if (num % j == 0 && Det3mul3 % j == 0)
                    {
                        //gcd checking
                        throw new InvalidAnlysisException();
                    }
                }
                int modifiedDet;
                modifiedDet = Det3mul3 % num;
                if (modifiedDet < 0)
                {
                    modifiedDet += num;
                }
                int y;
                int Count = 0;

                while (true)
                {
                    float c = ((float)((float)(Count * num) + 1) / (float)(num - modifiedDet));
                    if (c == (int)c)
                    {
                        y = (int)c;
                        break;
                    }
                    else
                    {
                        Count++;
                    }
                }
                int b = num - y;
                List<int> keyInversionbefTrans = new List<int>();
                //matrices of cofactors
                keyInversionbefTrans.Insert(0, b * cofactors1);
                keyInversionbefTrans.Insert(1, -1 * b * cofactors2);
                keyInversionbefTrans.Insert(2, b * cofactors3);
                int cofactors4 = (keycorrection[1] * keycorrection[8] - keycorrection[2] * keycorrection[7]);
                keyInversionbefTrans.Insert(3, -1 * b * cofactors4);
                int cofactors5 = (keycorrection[0] * keycorrection[8] - keycorrection[2] * keycorrection[6]);
                keyInversionbefTrans.Insert(4, b * cofactors5);
                int cofactors6 = (keycorrection[0] * keycorrection[7] - keycorrection[1] * keycorrection[6]);
                keyInversionbefTrans.Insert(5, -1 * b * cofactors6);
                int cofactors7 = (keycorrection[1] * keycorrection[5] - keycorrection[2] * keycorrection[4]);
                keyInversionbefTrans.Insert(6, b * cofactors7);
                int cofactors8 = (keycorrection[0] * keycorrection[5] - keycorrection[2] * keycorrection[3]);
                keyInversionbefTrans.Insert(7, -1 * b * cofactors8);
                int cofactors9 = (keycorrection[0] * keycorrection[4] - keycorrection[1] * keycorrection[3]);
                keyInversionbefTrans.Insert(8, b * cofactors9);

                //inverse of key after transpose
                keyInversion.Insert(0, keyInversionbefTrans[0]);
                keyInversion.Insert(1, keyInversionbefTrans[3]);
                keyInversion.Insert(2, keyInversionbefTrans[6]);
                keyInversion.Insert(3, keyInversionbefTrans[1]);
                keyInversion.Insert(4, keyInversionbefTrans[4]);
                keyInversion.Insert(5, keyInversionbefTrans[7]);
                keyInversion.Insert(6, keyInversionbefTrans[2]);
                keyInversion.Insert(7, keyInversionbefTrans[5]);
                keyInversion.Insert(8, keyInversionbefTrans[8]);
            }
            List<int> DecryptionText = new List<int>();
            int CTLen = cipherText.Count;
            int squareKey = (int)(Math.Sqrt(key.Count));
            //int len = 26;
            for (int i = 0; i < CTLen; i++)
            {
                DecryptionText.Insert(i, 0);
            }
            int RowIndecies = 0;
            int matrixId = 0;
            for (int i = 0; i < CTLen; i++)
            {
                for (int j = 0; j < squareKey; j++)
                {
                    if ((i % (squareKey)) == 0)
                    {
                        matrixId = i;
                    }
                    else
                    {
                        int k = i;
                        while (k >= 0)
                        {
                            if ((k % (squareKey)) == 0)
                            {
                                matrixId = k;
                                break;
                            }
                            k--;
                        }
                    }
                    DecryptionText[i] += keyInversion[j + (RowIndecies * squareKey)] * cipherText[matrixId + j];
                }
                DecryptionText[i] = DecryptionText[i] % num;
                if (RowIndecies == (squareKey - 1))
                {
                    RowIndecies = 0;
                }
                else
                {
                    RowIndecies++;
                }
            }

            int DTlen = DecryptionText.Count;
            for (int i = 0; i < DTlen; i++)
            {
                if (DecryptionText[i] >= num)
                {
                    DecryptionText[i] = DecryptionText[i] % num;

                }
                else if (DecryptionText[i] < 0)
                {
                    DecryptionText[i] = DecryptionText[i] % num;
                    DecryptionText[i] += num;
                }

            }
            return DecryptionText;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        //done
        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int keyLength = key.Count;
            int plaintextLength = plainText.Count;

            // Determine the size of the square key matrix
            int matrixSize = (int)Math.Sqrt(keyLength);

            // Initialize the key matrix
            int[,] keyMatrix = new int[matrixSize, matrixSize];
            int keyIndex = 0;
            for (int i = 0; i < matrixSize; i++)
            {
                for (int j = 0; j < matrixSize; j++)
                {
                    keyMatrix[i, j] = key[keyIndex++];
                }
            }

            // Calculate the number of rows needed in the plaintext matrix
            int numRows = plaintextLength / matrixSize;
            if (plaintextLength % matrixSize != 0)
            {
                numRows++;
            }

            // Initialize the plaintext matrix
            int[,] plaintextMatrix = new int[matrixSize, numRows];
            keyIndex = 0;
            for (int i = 0; i < numRows; i++)
            {
                for (int j = 0; j < matrixSize; j++)
                {
                    if (keyIndex < plaintextLength)
                    {
                        plaintextMatrix[j, i] = plainText[keyIndex++];
                    }
                    else
                    {
                        // If the plaintext is not a multiple of the key size, pad with zeroes
                        plaintextMatrix[j, i] = 0;
                    }
                }
            }

            // Perform matrix multiplication to get the cipher matrix
            int[,] cipherMatrix = new int[matrixSize, numRows];
            for (int i = 0; i < matrixSize; i++)
            {
                for (int j = 0; j < numRows; j++)
                {
                    int totalSum = 0;
                    for (int c = 0; c < matrixSize; c++)
                    {
                        totalSum += keyMatrix[i, c] * plaintextMatrix[c, j];
                    }
                    cipherMatrix[i, j] = totalSum % 26;
                }
            }

            // Flatten the cipher matrix into a list
            List<int> finalCipher = new List<int>();
            for (int i = 0; i < numRows; i++)
            {
                for (int j = 0; j < matrixSize; j++)
                {
                    finalCipher.Add(cipherMatrix[j, i]);
                }
            }

            return finalCipher;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            // throw new NotImplementedException();

            List<List<int>> CT2 = new List<List<int>>();
            List<List<int>> PT2 = new List<List<int>>();

            int m = (plain3.Count / 3);
            for (int i = 0; i < plain3.Count; i += 3)
            {
                List<int> CTcolumns = new List<int>
                {
                    cipher3[i],
                    cipher3[i + 1],
                    cipher3[i + 2]
                };
                CT2.Add(CTcolumns);

                List<int> PTcolumns = new List<int>
                {
                    plain3[i],
                    plain3[i + 1],
                    plain3[i + 2]
                };
                PT2.Add(PTcolumns);

            }

            List<List<int>> CTrow = new List<List<int>>();
            List<List<int>> PTrow = new List<List<int>>();
            for (int i = 0; i < m - 1; i++)
            {
                for (int j = i + 1; j < m; j++)
                {
                    for (int k = j + 1; k < m; k++)
                    {
                        List<int> CTcolumns = new List<int>
                        {
                            CT2[i][0],
                            CT2[i][1],
                            CT2[i][2],
                            CT2[j][0],
                            CT2[j][1],
                            CT2[j][2],
                            CT2[k][0],
                            CT2[k][1],
                            CT2[k][2]
                        };
                        CTrow.Add(CTcolumns);
                        List<int> PTcolumns = new List<int>
                        {
                            PT2[i][0],
                            PT2[i][1],
                            PT2[i][2],
                            PT2[j][0],
                            PT2[j][1],
                            PT2[j][2],
                            PT2[k][0],
                            PT2[k][1],
                            PT2[k][2]
                        };
                        PTrow.Add(PTcolumns);
                    }
                }
            }

            for (int i = 0; i < PTrow.Count; i++)
            {
                List<int> detCorrection = new List<int>();
                for (int j = 0; j < PTrow[i].Count; j++)
                {
                    if (PTrow[i].ElementAt(j) >= 26)
                    {
                        detCorrection.Insert(j, (PTrow[i][j] % 26));
                    }
                    else if (PTrow[i].ElementAt(j) < 0)
                    {
                        detCorrection.Insert(j, (PTrow[i][j] % 26) + 26);
                    }

                    else
                        detCorrection.Insert(j, PTrow[i][j]);
                }
                int cofactors1 = (detCorrection[4] * detCorrection[8] - detCorrection[5] * detCorrection[7]);
                int cofactors2 = (detCorrection[3] * detCorrection[8] - detCorrection[5] * detCorrection[6]);
                int cofactors3 = (detCorrection[3] * detCorrection[7] - detCorrection[4] * detCorrection[6]);

                int A = (detCorrection[0] * cofactors1) - (detCorrection[1] * cofactors2) + (detCorrection[2] * cofactors3);

                A %= 26;

                if (A == 0)
                    throw new InvalidAnlysisException();

                int InitialRule = A < 26 ? A : 26;

                int modDet = A < 0 ? A + 26 : A;
                for (int l = InitialRule; l >= 2; l--)
                {
                    if (26 % l == 0 && modDet % l == 0)
                        throw new InvalidAnlysisException();
                }

                int y;
                int Count = 0;

                while (true)
                {
                    float c = ((float)((float)(Count * 26) + 1) / (float)(26 - modDet));

                    if ((c == (int)c))
                    {
                        y = (int)c;
                        break;
                    }
                    else
                    {
                        Count++;
                    }
                }

                int b = 26 - y;
                List<int> KeyInversionbefTrans = new List<int>();

                KeyInversionbefTrans.Insert(0, b * cofactors1);
                KeyInversionbefTrans.Insert(1, -1 * b * cofactors2);
                KeyInversionbefTrans.Insert(2, b * cofactors3);
                int cofactors4 = (detCorrection[1] * detCorrection[8] - detCorrection[2] * detCorrection[7]);
                KeyInversionbefTrans.Insert(3, -1 * b * cofactors4);
                int cofactors5 = (detCorrection[0] * detCorrection[8] - detCorrection[2] * detCorrection[6]);
                KeyInversionbefTrans.Insert(4, b * cofactors5);
                int cofactors6 = (detCorrection[0] * detCorrection[7] - detCorrection[1] * detCorrection[6]);
                KeyInversionbefTrans.Insert(5, -1 * b * cofactors6);
                int cofactors7 = (detCorrection[1] * detCorrection[5] - detCorrection[2] * detCorrection[4]);
                KeyInversionbefTrans.Insert(6, b * cofactors7);
                int cofactors8 = (detCorrection[0] * detCorrection[5] - detCorrection[2] * detCorrection[3]);
                KeyInversionbefTrans.Insert(7, -1 * b * cofactors8);
                int cofactors9 = (detCorrection[0] * detCorrection[4] - detCorrection[1] * detCorrection[3]);
                KeyInversionbefTrans.Insert(8, b * cofactors9);
                List<int> PTInversion = new List<int>
                {
                    KeyInversionbefTrans[0],KeyInversionbefTrans[3],KeyInversionbefTrans[6],KeyInversionbefTrans[1],
                    KeyInversionbefTrans[4],KeyInversionbefTrans[7],KeyInversionbefTrans[2],KeyInversionbefTrans[5],
                    KeyInversionbefTrans[8]

                };

                for (int j = 0; j < PTInversion.Count; j++)
                {
                    if (PTInversion[j] >= 26)
                    {
                        PTInversion[j] = PTInversion[j] % 26;

                    }
                    else if (PTInversion[j] < 0)
                    {
                        PTInversion[j] = PTInversion[j] % 26;
                        PTInversion[j] += 26;
                    }
                }
                List<int> DecryptionText = new List<int>();
                int RowIndecies = 0;
                int num = 9;
                for (int k = 0; k < num; k++)
                {
                    DecryptionText.Insert(k, 0);
                }
                List<int> TransCT = new List<int> {
                    CTrow[i][0],CTrow[i][3],CTrow[i][6],CTrow[i][1],CTrow[i][4],
                    CTrow[i][7],CTrow[i][2],CTrow[i][5],CTrow[i][8]
                };

                int MatrixID = 0;
                for (int q = 0; q < num; q++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        int modq = q % (3);
                        if (modq == 0)
                        {
                            MatrixID = q;
                        }
                        else
                        {
                            for (int d = q; d >= 0; d--)
                            {
                                int modd = d % (3);
                                if (modd == 0)
                                {
                                    MatrixID = d;
                                    break;
                                }
                            }

                        }
                        DecryptionText[q] += TransCT[j + (RowIndecies * 3)] * PTInversion[MatrixID + j];
                    }

                    if (RowIndecies == 2)
                    {
                        RowIndecies = 0;
                    }
                    else
                    {
                        RowIndecies++;
                    }
                    DecryptionText[q] = DecryptionText[q] % 26;
                }
                List<int> ThreeMultKey = new List<int> {
                    DecryptionText[0],DecryptionText[3],DecryptionText[6],DecryptionText[1],DecryptionText[4],
                    DecryptionText[7],DecryptionText[2],DecryptionText[5],DecryptionText[8]
                };
                List<int> DecText;

                DecText = Encrypt(plain3, ThreeMultKey);
                if (DecText.SequenceEqual(cipher3))
                {
                    return ThreeMultKey;
                }
            }
            throw new InvalidAnlysisException();
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
