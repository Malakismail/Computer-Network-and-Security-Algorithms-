using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> keys = new List<int>();

            int ya = getKey(alpha, xa, q);
            int yb = getKey(alpha, xb, q);
            int a_sec = getKey(yb, xa, q);
            int b_sec = getKey(ya, xb, q);
            keys.Add(a_sec);
            keys.Add(b_sec);
            keys.Add(ya);
            keys.Add(yb);
            return keys;
        }
        private int getKey(int x, int y, int p)
        {
            int ans = 1;

            x = x % p;
            for (int i = y; i > 0; i = y)
            {
                if ((y % 2) != 0)
                    ans = (ans * x) % p;
                y = y / 2;
                x = (x * x) % p;

            }
            return ans;
        }
    }
}
