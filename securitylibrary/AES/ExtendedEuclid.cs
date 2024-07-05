using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="base_N"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int base_N)
        {
            // throw new NotImplementedException();

            int previous_X = 1, x = 0, previous_Y = 0, y = 1;
            int previous_R = base_N, r = number;

            while (r != 0)
            {
                int quotient = previous_R / r;

                int tempX = x;
                x = previous_X - quotient * x;
                previous_X = tempX;

                int tempY = y;
                y = previous_Y - quotient * y;
                previous_Y = tempY;

                int tempR = r;
                r = previous_R - quotient * r;
                previous_R = tempR;
            }
            if (previous_R > 1)
            {
                return -1; // No multiplicative inverse exists
            }
            else
            {
                return ((previous_Y % base_N) + base_N) % base_N;
            }
        }
    }
}
