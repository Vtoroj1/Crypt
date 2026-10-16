using System;
using Crypt.Algorithms.DES;
using Crypt.Interfaces;

namespace Crypt.Algorithms.DEAL
{
    public class DesRoundFunctionAdapter : IBlockCipher
    {
        private const int ExpectedInputBytes = 8;
        private const int ExpectedKeyBytes = 8;

        private readonly ISymmetricAlgorithm _des;
        private byte[] _lastKey;

        public DesRoundFunctionAdapter()
        {
            _des = new DesAlgorithm();
        }

        public byte[] Transform(byte[] inputBlock, byte[] roundKey)
        {
            if (inputBlock == null)
                throw new ArgumentNullException(nameof(inputBlock));
            if (roundKey == null)
                throw new ArgumentNullException(nameof(roundKey));

            if (inputBlock.Length != ExpectedInputBytes)
                throw new ArgumentException(
                    $"Адаптер DES ожидает блок {ExpectedInputBytes} байт, получено {inputBlock.Length}", nameof(inputBlock));

            if (roundKey.Length != ExpectedKeyBytes)
                throw new ArgumentException(
                    $"Раундовый ключ DEAL должен быть {ExpectedKeyBytes} байт, получено {roundKey.Length}", nameof(roundKey));

            if (_lastKey == null || !KeysEqual(_lastKey, roundKey))
            {
                _des.SetKey(roundKey);
                _lastKey = (byte[])roundKey.Clone();
            }

            return _des.Encrypt(inputBlock);
        }

        private static bool KeysEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }
    }
}