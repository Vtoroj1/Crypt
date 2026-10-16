using System;
using Crypt.Algorithms;
using Crypt.Interfaces;

namespace Crypt.Algorithms.DEAL
{
    public class DealAlgorithm : ISymmetricAlgorithm
    {
        public const int BlockSizeBytes = 16;

        private readonly FeistelNetwork _feistel;

        public DealAlgorithm()
        {
            _feistel = new FeistelNetwork(
                new DealKeyExpander(),
                new DesRoundFunctionAdapter());
        }

        public void SetKey(byte[] key)
        {
            _feistel.SetKey(key);
        }

        public byte[] Encrypt(byte[] block)
        {
            ValidateBlock(block);
            return _feistel.Encrypt(block);
        }

        public byte[] Decrypt(byte[] block)
        {
            ValidateBlock(block);
            return _feistel.Decrypt(block);
        }

        private static void ValidateBlock(byte[] block)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));
            if (block.Length != BlockSizeBytes)
                throw new ArgumentException(
                    $"DEAL шифрует блоки по {BlockSizeBytes} байт, получено {block.Length}", nameof(block));
        }
    }
}