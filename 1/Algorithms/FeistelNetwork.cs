using System;
using Crypt.Interfaces;

namespace Crypt.Algorithms
{
    public class FeistelNetwork : ISymmetricAlgorithm
    {
        private readonly IKeyExpander _keyExpander;
        private readonly IBlockCipher _roundFunction;

        private byte[][] _roundKeys;

        public FeistelNetwork(IKeyExpander keyExpander, IBlockCipher roundFunction)
        {
            _keyExpander = keyExpander ?? throw new ArgumentNullException(
                nameof(keyExpander), "Генератор ключей не может быть null");
            _roundFunction = roundFunction ?? throw new ArgumentNullException(
                nameof(roundFunction), "Раундовая функция не может быть null");
        }

        public void SetKey(byte[] key)
        {
            if (key == null || key.Length == 0)
                throw new ArgumentException("Ключ не может быть пустым", nameof(key));

            _roundKeys = _keyExpander.ExpandKey(key);

            if (_roundKeys == null || _roundKeys.Length == 0)
                throw new InvalidOperationException(
                    "Генератор ключей вернул пустой массив раундовых ключей");
        }

        public byte[] Encrypt(byte[] block)
        {
            return RunFeistel(block, reverseKeys: false);
        }

        public byte[] Decrypt(byte[] block)
        {
            return RunFeistel(block, reverseKeys: true);
        }
    

        private byte[] RunFeistel(byte[] block, bool reverseKeys)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block), "Блок не может быть null");
            if (_roundKeys == null)
                throw new InvalidOperationException(
                    "Ключ не установлен");
            if (block.Length % 2 != 0)
                throw new ArgumentException(
                    $"Размер блока ({block.Length}) должен быть четным", nameof(block));

            int halfSize = block.Length / 2;

            byte[] left  = new byte[halfSize];
            byte[] right = new byte[halfSize];
            Array.Copy(block, 0, left, 0, halfSize);
            Array.Copy(block, halfSize, right, 0, halfSize);

            int rounds = _roundKeys.Length;
            for (int i = 0; i < rounds; i++)
            {
                int keyIndex = reverseKeys ? (rounds - 1 - i) : i;
                byte[] roundKey = _roundKeys[keyIndex];

                byte[] fResult = _roundFunction.Transform(right, roundKey);

                byte[] newRight = XorBytes(left, fResult);

                left  = right;
                right = newRight;
            }

            byte[] result = new byte[block.Length];
            Array.Copy(right, 0, result, 0, halfSize);
            Array.Copy(left, 0, result, halfSize, halfSize);

            return result;
        }

        private static byte[] XorBytes(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                throw new ArgumentException(
                    $"Длины массивов не совпадают: {a.Length} != {b.Length}");

            byte[] result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                result[i] = (byte)(a[i] ^ b[i]);
            return result;
        }
    }
}