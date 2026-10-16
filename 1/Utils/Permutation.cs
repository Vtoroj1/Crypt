using System;

namespace Crypt
{
    public enum BitOrder
    {
        LsbFirst, // От младшего к старшему
        MsbFirst  // От старшего к младшему
    }

    public class Permutation
    {
        public static byte[] Permute(byte[] input, int[] pBlock, BitOrder bitOrder, int startIndex)
        {
            if (input == null || input.Length == 0)
                throw new ArgumentException("Входной массив не может быть пустым");
            if (pBlock == null || pBlock.Length == 0)
                throw new ArgumentException("P-блок не может быть пустым");
            if (startIndex != 0 && startIndex != 1)
                throw new ArgumentException("Начальный индекс должен быть 0 или 1");

            int outBitLen = pBlock.Length;
            int outByteLen = (outBitLen + 7) / 8;
            byte[] output = new byte[outByteLen];

            for (int i = 0; i < pBlock.Length; i++)
            {
                int pIndex = pBlock[i] - startIndex;

                int inputBits = input.Length * 8;
                if (pIndex < 0 || pIndex >= inputBits)
                {
                    throw new ArgumentOutOfRangeException($"Индекс {pBlock[i]} в P-блоке выходит за границы входного массива");
                }

                bool bitValue = GetBit(input, pIndex, bitOrder);

                SetBit(output, i, bitValue, bitOrder);
            }

            return output;
        }

        public static bool GetBit(byte[] data, int bitIndex, BitOrder bitOrder)
        {
            int byteIndex = bitIndex / 8;
            int bitInByte;

            if (bitOrder == BitOrder.LsbFirst) bitInByte = bitIndex % 8;
            else bitInByte = 7 - (bitIndex % 8);

            return (data[byteIndex] & (byte)(1 << bitInByte)) != 0;
        }

        public static void SetBit(byte[] data, int bitIndex, bool value, BitOrder bitOrder)
        {
            int byteIndex = bitIndex / 8;
            int bitInByte;

            if (bitOrder == BitOrder.LsbFirst) bitInByte = bitIndex % 8;
            else bitInByte = 7 - (bitIndex % 8);

            if (value) data[byteIndex] |= (byte)(1 << bitInByte);
            else data[byteIndex] &= (byte)~(1 << bitInByte);
        }


        public static bool[] ToBoolArray(byte[] data, BitOrder order)
        {
            bool[] bits = new bool[data.Length * 8];
            for (int i = 0; i < bits.Length; i++)
                bits[i] = GetBit(data, i, order);
            return bits;
        }

        public static byte[] FromBoolArray(bool[] bits, BitOrder order)
        {
            int byteCount = (bits.Length + 7) / 8;
            byte[] result = new byte[byteCount];
            for (int i = 0; i < bits.Length; i++)
                SetBit(result, i, bits[i], order);
            return result;
        }

        public static bool[] PermuteBool(bool[] input, int[] pBox, int startIndex)
        {
            if (input == null || pBox == null)
                throw new ArgumentNullException();
            
            bool[] output = new bool[pBox.Length];
            for (int i = 0; i < pBox.Length; i++)
            {
                int sourceIndex = pBox[i] - startIndex;
                if (sourceIndex < 0 || sourceIndex >= input.Length)
                    throw new ArgumentOutOfRangeException(
                        $"Индекс {pBox[i]} в P-блоке выходит за границы");
                output[i] = input[sourceIndex];
            }
            return output;
        }

        public static bool[] LeftRotate(bool[] bits, int shift)
        {
            int n = bits.Length;
            bool[] result = new bool[n];
            for (int i = 0; i < n; i++)
                result[i] = bits[(i + shift) % n];
            return result;
        }
    }
}