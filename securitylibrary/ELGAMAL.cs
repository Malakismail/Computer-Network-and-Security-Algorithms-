using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {

            long c1 = mod(alpha, k, q);
            long K = mod(y, k, q);
            long c2 = (K * m) % q;

            return new List<long> { c1, c2 };


        }

        public int Decrypt(int c1, int c2, int x, int q)
        {

            long c1PowXModQ = mod(c1, x, q);
            long inverseC1PowXModQ = invMOD(c1PowXModQ, q);
            int decryptedMessage = (int)((c2 * inverseC1PowXModQ) % q);
            return decryptedMessage;

        }
        private long mod(long value, long exponent, long modulus)
        {
            if (exponent == 0)
                return 1;
            if (exponent == 1)
                return value % modulus;

            long halfExponent = mod(value, exponent / 2, modulus);
            long result = (halfExponent * halfExponent) % modulus;

            if (exponent % 2 == 1)
                result = (result * value) % modulus;

            return result;
        }
        private long invMOD(long a, long n)
        {
            long i = n, v = 0, d = 1;
            while (a > 0)
            {
                long t = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if (v < 0) v = (v + n) % n;
            return v;
        }
    }
}
