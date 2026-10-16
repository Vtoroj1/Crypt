using System;
using Crypt.Algorithms.DES;
using Crypt.Interfaces;

namespace Crypt.Algorithms.DEAL
{
    public class DealKeyExpander : IKeyExpander
    {
        private const int RoundKeySize = 8;
        private const int Key128Size = 16;
        private const int Key192Size = 24;
        private const int Key256Size = 32;

        private static readonly byte[] ChainConstant = {
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        private readonly ISymmetricAlgorithm _des;

        public DealKeyExpander()
        {
            _des = new DesAlgorithm();
        }

        public byte[][] ExpandKey(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            int keyParts;
            int rounds;

            switch (key.Length)
            {
                case Key128Size: keyParts = 2; rounds = 6; break;
                case Key192Size: keyParts = 3; rounds = 8; break;
                case Key256Size: keyParts = 4; rounds = 8; break;
                default:
                    throw new ArgumentException($"Ключ DEAL должен быть 16, 24 или 32 байта, получено {key.Length}", nameof(key));
            }

            byte[][] parts = new byte[keyParts][];
            for (int i = 0; i < keyParts; i++)
            {
                parts[i] = new byte[RoundKeySize];
                Array.Copy(key, i * RoundKeySize, parts[i], 0, RoundKeySize);
            }

            byte[][] roundKeys = new byte[rounds][];

            for (int i = 0; i < rounds; i++)
            {
                int keyIdx = i % keyParts;
                byte[] input;

                if (i < keyParts - 1) input = parts[i + 1];
                else input = XorWithConstant(roundKeys[i - 1]);

                _des.SetKey(parts[keyIdx]);
                roundKeys[i] = _des.Encrypt(input);
            }

            return roundKeys;
        }


        private static byte[] XorWithConstant(byte[] block)
        {
            byte[] result = new byte[block.Length];
            for (int i = 0; i < block.Length; i++)
                result[i] = (byte)(block[i] ^ ChainConstant[i]);
            return result;
        }
    }
}