using System;
using Crypt.Enums;
using Crypt.Interfaces;
using Crypt.Utils;

namespace Crypt.Algorithms.DES
{
    public class DesKeyExpander : IKeyExpander
    {
        private const int DesKeySizeBytes = 8;
        private const int HalfKeyBits = 28;
        private const int RoundKeyBits = 48;
        private const int Rounds = 16;

        public byte[][] ExpandKey(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key), "Ключ не может быть null");

            if (key.Length != DesKeySizeBytes)
                throw new ArgumentException( $"Ключ не соответствует необходимому размеру - {DesKeySizeBytes} байт", nameof(key));

            byte[] key56 = Permutation.Permute(
                key,
                DES_Tables.PC1,
                BitOrder.MsbFirst,
                startIndex: 1);

            bool[] keyBits = Permutation.ToBoolArray(key56, BitOrder.MsbFirst);

            bool[] c = new bool[HalfKeyBits];
            bool[] d = new bool[HalfKeyBits];
            Array.Copy(keyBits, 0, c, 0, HalfKeyBits);
            Array.Copy(keyBits, HalfKeyBits, d, 0, HalfKeyBits);

            byte[][] roundKeys = new byte[Rounds][];

            for (int i = 0; i < Rounds; i++)
            {
                c = Permutation.LeftRotate(c, DES_Tables.Shifts[i]);
                d = Permutation.LeftRotate(d, DES_Tables.Shifts[i]);

                bool[] cd = new bool[HalfKeyBits * 2];
                Array.Copy(c, 0, cd, 0, HalfKeyBits);
                Array.Copy(d, 0, cd, HalfKeyBits, HalfKeyBits);

                bool[] roundKeyBits = Permutation.PermuteBool(
                    cd,
                    DES_Tables.PC2,
                    startIndex: 1);

                roundKeys[i] = Permutation.FromBoolArray(roundKeyBits, BitOrder.MsbFirst);
            }

            return roundKeys;
        }
    }
}