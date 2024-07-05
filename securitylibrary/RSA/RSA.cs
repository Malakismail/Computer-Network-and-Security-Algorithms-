using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            Tuple<int, int> result = Phay_N(p, q);
            int n = result.Item1;
            int phay_n = result.Item2;

            return Enc(M, n, e);
        }

        public int Enc(int M, int n, int e)
        {
            int cc = 1;
            cc = M % n; // cipher = m (power e) % n

            for (int i = 1; i < e; i++)
            {
                cc = (cc * M) % n;
            }

            return cc;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            Tuple<int, int> result = Phay_N(p, q);
            int n = result.Item1;
            int phay_n = result.Item2;

            return Dec(n, e, phay_n, C);
        }

        public int Dec(int n, int e, int phay_n, int C)
        {
            int d; // private key

            for (d = 0; d < n; d++)
                if ((d * e % phay_n) == 1)
                    break;

            int M = 1;
            M = C % n;  // m = c (power d) % n
            for (int i = 1; i < d; i++)
            {
                M = (M * C) % n;
            }
            return M;
        }

        public Tuple<int, int> Phay_N(int p, int q)
        {
            int n = p * q;
            int phay = (p - 1) * (q - 1);

            return Tuple.Create(n, phay);
        }
    }
}
