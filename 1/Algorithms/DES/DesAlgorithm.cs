using System;
using Crypt.Algorithms;
using Crypt.Enums;
using Crypt.Interfaces;
using Crypt.Utils;

namespace Crypt.Algorithms.DES
{
    public class DesAlgorithm : ISymmetricAlgorithm
    {
        private const int BlockSize = 8;

        private readonly FeistelNetwork _feistel;

        public DesAlgorithm()
        {
            _feistel = new FeistelNetwork(
                new DesKeyExpander(),
                new DesRoundFunction());
        }

        public void SetKey(byte[] key)
        {
            _feistel.SetKey(key);
        }

        public byte[] Encrypt(byte[] block)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));
            if (block.Length != BlockSize)
                throw new ArgumentException( $"DES шифрует блоки по {BlockSize} байт, получено {block.Length}", nameof(block));

            byte[] ipBlock = Permutation.Permute(
                block,
                DES_Tables.IP,
                BitOrder.MsbFirst,
                startIndex: 1);

            byte[] feistelOut = _feistel.Encrypt(ipBlock);

            byte[] result = Permutation.Permute(
                feistelOut,
                DES_Tables.FP,
                BitOrder.MsbFirst,
                startIndex: 1);

            return result;
        }

        public byte[] Decrypt(byte[] block)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));
            if (block.Length != BlockSize)
                throw new ArgumentException( $"DES шифрует блоки по {BlockSize} байт, получено {block.Length}", nameof(block));

            byte[] ipBlock = Permutation.Permute(
                block,
                DES_Tables.IP,
                BitOrder.MsbFirst,
                startIndex: 1);

            byte[] feistelOut = _feistel.Decrypt(ipBlock);

            byte[] result = Permutation.Permute(
                feistelOut,
                DES_Tables.FP,
                BitOrder.MsbFirst,
                startIndex: 1);

            return result;
        }
    }
}