using System;
using Crypt.Enums;
using Crypt.Interfaces;

namespace Crypt.Utils
{
    public class CipherModeProcessor
    {
        private readonly ISymmetricAlgorithm _algorithm;
        private readonly CipherMode _mode;
        private readonly int _blockSize;
        private readonly int _delta;

        private byte[] _state;

        public CipherModeProcessor(
            ISymmetricAlgorithm algorithm,
            CipherMode mode,
            byte[] iv,
            int blockSize,
            object[] additionalParams)
        {
            _algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            _mode = mode;
            _blockSize = blockSize;
            _delta = ExtractDelta(additionalParams);

            switch (mode)
            {
                case CipherMode.ECB:
                    _state = null;
                    break;

                case CipherMode.CBC:
                case CipherMode.PCBC:
                case CipherMode.CFB:
                case CipherMode.OFB:
                case CipherMode.CTR:
                case CipherMode.RandomDelta:
                    if (iv == null)
                        throw new ArgumentException($"Режим {mode} требует IV");
                    if (iv.Length != blockSize)
                        throw new ArgumentException($"Длина IV ({iv.Length}) должна совпадать с размером блока ({blockSize})");
                    _state = (byte[])iv.Clone();
                    break;

                default:
                    throw new ArgumentException($"Неизвестный режим: {mode}");
            }
        }


        public byte[] EncryptBlock(byte[] block)
        {
            EnsureBlockSize(block);

            switch (_mode)
            {
                case CipherMode.ECB:
                    return _algorithm.Encrypt(block);

                case CipherMode.CBC:
                {
                    byte[] xored = Xor(block, _state);
                    byte[] encrypted = _algorithm.Encrypt(xored);
                    _state = (byte[])encrypted.Clone();
                    return encrypted;
                }

                case CipherMode.PCBC:
                {
                    byte[] xored = Xor(block, _state);
                    byte[] encrypted = _algorithm.Encrypt(xored);
                    _state = Xor(block, encrypted);
                    return encrypted;
                }

                case CipherMode.CFB:
                {
                    byte[] gamma = _algorithm.Encrypt(_state);
                    byte[] cipher = Xor(block, gamma);
                    _state = (byte[])cipher.Clone();
                    return cipher;
                }

                case CipherMode.OFB:
                {
                    _state = _algorithm.Encrypt(_state);
                    return Xor(block, _state);
                }

                case CipherMode.CTR:
                case CipherMode.RandomDelta:
                {
                    byte[] gamma = _algorithm.Encrypt(_state);
                    byte[] cipher = Xor(block, gamma);
                    IncrementCounter(_state, _delta);
                    return cipher;
                }

                default:
                    throw new InvalidOperationException($"Режим {_mode} не поддерживается");
            }
        }

        public byte[] DecryptBlock(byte[] block)
        {
            EnsureBlockSize(block);

            switch (_mode)
            {
                case CipherMode.ECB:
                    return _algorithm.Decrypt(block);

                case CipherMode.CBC:
                {
                    byte[] decrypted = _algorithm.Decrypt(block);
                    byte[] plain = Xor(decrypted, _state);
                    _state = (byte[])block.Clone();
                    return plain;
                }

                case CipherMode.PCBC:
                {
                    byte[] decrypted = _algorithm.Decrypt(block);
                    byte[] plain = Xor(decrypted, _state);
                    _state = Xor(plain, block);
                    return plain;
                }

                case CipherMode.CFB:
                {
                    byte[] gamma = _algorithm.Encrypt(_state);
                    byte[] plain = Xor(block, gamma);
                    _state = (byte[])block.Clone();
                    return plain;
                }

                case CipherMode.OFB:
                {
                    _state = _algorithm.Encrypt(_state);
                    return Xor(block, _state);
                }

                case CipherMode.CTR:
                case CipherMode.RandomDelta:
                {
                    byte[] gamma = _algorithm.Encrypt(_state);
                    byte[] plain = Xor(block, gamma);
                    IncrementCounter(_state, _delta);
                    return plain;
                }

                default:
                    throw new InvalidOperationException($"Режим {_mode} не поддерживается.");
            }
        }


        private void EnsureBlockSize(byte[] block)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));
            if (block.Length != _blockSize)
                throw new ArgumentException($"Ожидается блок {_blockSize} байт, получено {block.Length}");
        }

        private static byte[] Xor(byte[] a, byte[] b)
        {
            byte[] r = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                r[i] = (byte)(a[i] ^ b[i]);
            return r;
        }

        private static void IncrementCounter(byte[] counter, int delta)
        {
            int carry = delta;
            for (int i = counter.Length - 1; i >= 0 && carry > 0; i--)
            {
                int sum = counter[i] + (carry & 0xFF);
                counter[i] = (byte)(sum & 0xFF);
                carry = (carry >> 8) + (sum >> 8);
            }
        }

        private static int ExtractDelta(object[] p)
        {
            if (p != null && p.Length > 0 && p[0] is int d && d > 0)
                return d;
            return 1;
        }
    }
}