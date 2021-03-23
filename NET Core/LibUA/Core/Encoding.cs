
// Type: LibUA.Core.ArrayHelper



using System;

namespace LibUA.Core
{
    public static class ArrayHelper
    {
        public static T[] SubArray<T>(this T[] Data, int Offset, int Length)
        {
            T[] objArray = new T[Length];
            Array.Copy(Data, Offset, objArray, 0, Length);
            return objArray;
        }

        public static void Memset<T>(this T[] Data, T Value)
        {
            int val1 = 32;
            int dstOffset = 0;
            int num = Math.Min(val1, Data.Length);
            while (dstOffset < num)
            {
                Data[dstOffset++] = Value;
            }

            int length = Data.Length;
            while (dstOffset < length)
            {
                Buffer.BlockCopy(Data, 0, Data, dstOffset, Math.Min(val1, length - dstOffset));
                dstOffset += val1;
                val1 *= 2;
            }
        }
    }
}
