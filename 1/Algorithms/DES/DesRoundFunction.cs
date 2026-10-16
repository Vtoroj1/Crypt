using System;
using Crypt.Enums;
using Crypt.Interfaces;
using Crypt.Utils;

namespace Crypt.Algorithms.DES
{
    public class DesRoundFunction : IBlockCipher
    {
        private const int InputBits   = 32;
        private const int ExpandedBits = 48;
        private const int OutputBits  = 32;

        public byte[] Transform(byte[] inputBlock, byte[] roundKey)
        {
            if (inputBlock == null)
                throw new ArgumentNullException(nameof(inputBlock));
            if (roundKey == null)
                throw new ArgumentNullException(nameof(roundKey));
            if (inputBlock.Length != InputBits / 8)
                throw new ArgumentException($"Ожидается 4 байта, получено {inputBlock.Length}", nameof(inputBlock));
            if (roundKey.Length != ExpandedBits / 8)
                throw new ArgumentException($"Раундовый ключ DES должен быть 6 байт, получено {roundKey.Length}", nameof(roundKey));

            byte[] expanded = Permutation.Permute(
                inputBlock,
                DES_Tables.E,
                BitOrder.MsbFirst,
                startIndex: 1);

            byte[] xored = new byte[expanded.Length];
            for (int i = 0; i < expanded.Length; i++)
                xored[i] = (byte)(expanded[i] ^ roundKey[i]);

            bool[] inputBits = Permutation.ToBoolArray(xored, BitOrder.MsbFirst);
            bool[] outputBits = new bool[OutputBits];

            for (int s = 0; s < 8; s++)
            {
                int offset = s * 6;

                int row = (inputBits[offset] ? 2 : 0) + (inputBits[offset + 5] ? 1 : 0);

                int col = (inputBits[offset + 1] ? 8 : 0)
                        + (inputBits[offset + 2] ? 4 : 0)
                        + (inputBits[offset + 3] ? 2 : 0)
                        + (inputBits[offset + 4] ? 1 : 0);

                int value = DES_Tables.SBoxes[s][row, col];

                outputBits[s * 4] = (value & 8) != 0;
                outputBits[s * 4 + 1] = (value & 4) != 0;
                outputBits[s * 4 + 2] = (value & 2) != 0;
                outputBits[s * 4 + 3] = (value & 1) != 0;
            }

            byte[] sboxOutput = Permutation.FromBoolArray(outputBits, BitOrder.MsbFirst);

            byte[] result = Permutation.Permute(
                sboxOutput,
                DES_Tables.P,
                BitOrder.MsbFirst,
                startIndex: 1);

            return result;
        }
    }
}