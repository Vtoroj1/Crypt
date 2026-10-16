using System;
using Crypt.Enums;
using Crypt.Interfaces;
using System.Threading.Tasks;

namespace Crypt.Utils
{
    public static class CipherModes
    {
        public static byte[] Encrypt(
            ISymmetricAlgorithm algorithm,
            byte[] data,
            CipherMode mode,
            byte[] iv,
            int blockSize,
            object[] additionalParams)
        {
            if (data.Length % blockSize != 0)
                throw new ArgumentException(
                    $"Длина данных ({data.Length}) должна быть кратна размеру блока ({blockSize})");

            return mode switch
            {
                CipherMode.ECB => EncryptECBParallel(algorithm, data, blockSize),
                CipherMode.CBC => EncryptCBC(algorithm, data, iv, blockSize),
                CipherMode.PCBC => EncryptPCBC(algorithm, data, iv, blockSize),
                CipherMode.CFB => EncryptCFB(algorithm, data, iv, blockSize),
                CipherMode.OFB => EncryptOFB(algorithm, data, iv, blockSize),
                CipherMode.CTR => EncryptCTRParallel(algorithm, data, iv, blockSize, 1),
                CipherMode.RandomDelta => EncryptCTRParallel(algorithm, data, iv, blockSize, ExtractDelta(additionalParams)),
                _ => throw new ArgumentException($"Неизвестный режим шифрования: {mode}")
            };
        }

        public static byte[] Decrypt(
            ISymmetricAlgorithm algorithm,
            byte[] data,
            CipherMode mode,
            byte[] iv,
            int blockSize,
            object[] additionalParams)
        {
            if (data.Length % blockSize != 0)
                throw new ArgumentException(
                    $"Длина данных ({data.Length}) должна быть кратна размеру блока ({blockSize})");

            return mode switch
            {
                CipherMode.ECB => DecryptECBParallel(algorithm, data, blockSize),
                CipherMode.CBC => DecryptCBCParallel(algorithm, data, iv, blockSize),
                CipherMode.PCBC => DecryptPCBC(algorithm, data, iv, blockSize),
                CipherMode.CFB => DecryptCFBParallel(algorithm, data, iv, blockSize),
                CipherMode.OFB => DecryptOFB(algorithm, data, iv, blockSize),
                CipherMode.CTR => DecryptCTRParallel(algorithm, data, iv, blockSize, 1),
                CipherMode.RandomDelta => DecryptCTRParallel(algorithm, data, iv, blockSize, ExtractDelta(additionalParams)),
                _ => throw new ArgumentException($"Неизвестный режим шифрования: {mode}")
            };
        }


        private static byte[] EncryptECB(ISymmetricAlgorithm alg, byte[] data, int blockSize)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i += blockSize)
            {
                byte[] block = ExtractBlock(data, i, blockSize);
                byte[] encrypted = alg.Encrypt(block);
                CopyBlock(encrypted, result, i);
            }
            return result;
        }

        private static byte[] DecryptECB(ISymmetricAlgorithm alg, byte[] data, int blockSize)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i += blockSize)
            {
                byte[] block = ExtractBlock(data, i, blockSize);
                byte[] decrypted = alg.Decrypt(block);
                CopyBlock(decrypted, result, i);
            }
            return result;
        }

        private static byte[] EncryptCBC(ISymmetricAlgorithm alg, byte[] data, byte[] iv, int blockSize)
        {
            byte[] result = new byte[data.Length];
            byte[] prev = (byte[])iv.Clone();

            for (int i = 0; i < data.Length; i += blockSize)
            {
                byte[] block = ExtractBlock(data, i, blockSize);
                byte[] xored = XorBlocks(block, prev);
                byte[] encrypted = alg.Encrypt(xored);
                CopyBlock(encrypted, result, i);
                prev = encrypted;
            }
            return result;
        }

        private static byte[] DecryptCBC(ISymmetricAlgorithm alg, byte[] data, byte[] iv, int blockSize)
        {
            byte[] result = new byte[data.Length];
            byte[] prev = (byte[])iv.Clone();

            for (int i = 0; i < data.Length; i += blockSize)
            {
                byte[] block = ExtractBlock(data, i, blockSize);
                byte[] decrypted = alg.Decrypt(block);
                byte[] xored = XorBlocks(decrypted, prev);
                CopyBlock(xored, result, i);
                prev = block;
            }
            return result;
        }

        private static byte[] EncryptPCBC(ISymmetricAlgorithm alg, byte[] data, byte[] iv, int blockSize)
        {
            byte[] result = new byte[data.Length];
            byte[] prev = (byte[])iv.Clone();

            for (int i = 0; i < data.Length; i += blockSize)
            {
                byte[] block = ExtractBlock(data, i, blockSize);
                byte[] xored = XorBlocks(block, prev);
                byte[] encrypted = alg.Encrypt(xored);
                CopyBlock(encrypted, result, i);
                prev = XorBlocks(block, encrypted);
            }
            return result;
        }

        private static byte[] DecryptPCBC(ISymmetricAlgorithm alg, byte[] data, byte[] iv, int blockSize)
        {
            byte[] result = new byte[data.Length];
            byte[] prev = (byte[])iv.Clone();

            for (int i = 0; i < data.Length; i += blockSize)
            {
                byte[] cipherBlock = ExtractBlock(data, i, blockSize);
                byte[] decrypted = alg.Decrypt(cipherBlock);
                byte[] plainBlock = XorBlocks(decrypted, prev);
                CopyBlock(plainBlock, result, i);
                prev = XorBlocks(plainBlock, cipherBlock);
            }
            return result;
        }

        private static byte[] EncryptCFB(ISymmetricAlgorithm alg, byte[] data, byte[] iv, int blockSize)
        {
            byte[] result = new byte[data.Length];
            byte[] prev = (byte[])iv.Clone();

            for (int i = 0; i < data.Length; i += blockSize)
            {
                byte[] block = ExtractBlock(data, i, blockSize);
                byte[] gamma = alg.Encrypt(prev);
                byte[] encrypted = XorBlocks(block, gamma);
                CopyBlock(encrypted, result, i);
                prev = encrypted;
            }
            return result;
        }

        private static byte[] DecryptCFB(ISymmetricAlgorithm alg, byte[] data, byte[] iv, int blockSize)
        {
            byte[] result = new byte[data.Length];
            byte[] prev = (byte[])iv.Clone();

            for (int i = 0; i < data.Length; i += blockSize)
            {
                byte[] cipherBlock = ExtractBlock(data, i, blockSize);
                byte[] gamma = alg.Encrypt(prev);
                byte[] decrypted = XorBlocks(cipherBlock, gamma);
                CopyBlock(decrypted, result, i);
                prev = cipherBlock;
            }
            return result;
        }

        private static byte[] EncryptOFB(ISymmetricAlgorithm alg, byte[] data, byte[] iv, int blockSize)
        {
            byte[] result = new byte[data.Length];
            byte[] gamma = (byte[])iv.Clone();

            for (int i = 0; i < data.Length; i += blockSize)
            {
                gamma = alg.Encrypt(gamma);
                byte[] block = ExtractBlock(data, i, blockSize);
                byte[] encrypted = XorBlocks(block, gamma);
                CopyBlock(encrypted, result, i);
            }
            return result;
        }

        private static byte[] DecryptOFB(ISymmetricAlgorithm alg, byte[] data, byte[] iv, int blockSize)
        {
            // OFB симметричен
            return EncryptOFB(alg, data, iv, blockSize);
        }

        private static byte[] EncryptCTR(ISymmetricAlgorithm alg, byte[] data, byte[] iv, int blockSize)
        {
            byte[] result = new byte[data.Length];
            byte[] counter = (byte[])iv.Clone();

            for (int i = 0; i < data.Length; i += blockSize)
            {
                byte[] gamma = alg.Encrypt(counter);
                byte[] block = ExtractBlock(data, i, blockSize);
                byte[] encrypted = XorBlocks(block, gamma);
                CopyBlock(encrypted, result, i);
                IncrementCounter(counter, 1);
            }
            return result;
        }

        private static byte[] DecryptCTR(ISymmetricAlgorithm alg, byte[] data, byte[] iv, int blockSize)
        {
            // CTR симметричен
            return EncryptCTR(alg, data, iv, blockSize);
        }

        private static byte[] EncryptRandomDelta(
            ISymmetricAlgorithm alg, byte[] data, byte[] iv, int blockSize, object[] additionalParams)
        {
            // Дельта берется из additionalParams[0], по умолчанию 1
            int delta = ExtractDelta(additionalParams);

            byte[] result = new byte[data.Length];
            byte[] counter = (byte[])iv.Clone();

            for (int i = 0; i < data.Length; i += blockSize)
            {
                byte[] gamma = alg.Encrypt(counter);
                byte[] block = ExtractBlock(data, i, blockSize);
                byte[] encrypted = XorBlocks(block, gamma);
                CopyBlock(encrypted, result, i);
                IncrementCounter(counter, delta);
            }
            return result;
        }

        private static byte[] DecryptRandomDelta(
            ISymmetricAlgorithm alg, byte[] data, byte[] iv, int blockSize, object[] additionalParams)
        {
            // Random Delta симметричен
            return EncryptRandomDelta(alg, data, iv, blockSize, additionalParams);
        }


        private static byte[] EncryptECBParallel(ISymmetricAlgorithm alg, byte[] data, int blockSize)
        {
            byte[] result = new byte[data.Length];
            int blockCount = data.Length / blockSize;

            Parallel.For(0, blockCount, i =>
            {
                int offset = i * blockSize;
                byte[] block = ExtractBlock(data, offset, blockSize);
                byte[] encrypted = alg.Encrypt(block);
                lock (result)
                {
                    CopyBlock(encrypted, result, offset);
                }
            });

            return result;
        }

        private static byte[] DecryptECBParallel(ISymmetricAlgorithm alg, byte[] data, int blockSize)
        {
            byte[] result = new byte[data.Length];
            int blockCount = data.Length / blockSize;

            Parallel.For(0, blockCount, i =>
            {
                int offset = i * blockSize;
                byte[] block = ExtractBlock(data, offset, blockSize);
                byte[] decrypted = alg.Decrypt(block);
                lock (result)
                {
                    CopyBlock(decrypted, result, offset);
                }
            });

            return result;
        }

        private static byte[] EncryptCTRParallel(ISymmetricAlgorithm alg, byte[] data, byte[] iv, int blockSize, int delta)
        {
            byte[] result = new byte[data.Length];
            int blockCount = data.Length / blockSize;

            Parallel.For(0, blockCount, i =>
            {
                byte[] counter = (byte[])iv.Clone();
                IncrementCounter(counter, i * delta);

                byte[] gamma = alg.Encrypt(counter);
                int offset = i * blockSize;
                byte[] block = ExtractBlock(data, offset, blockSize);
                byte[] encrypted = XorBlocks(block, gamma);

                lock (result)
                {
                    CopyBlock(encrypted, result, offset);
                }
            });

            return result;
        }

        private static byte[] DecryptCTRParallel(ISymmetricAlgorithm alg, byte[] data, byte[] iv, int blockSize, int delta)
        {
            // CTR симметричен
            return EncryptCTRParallel(alg, data, iv, blockSize, delta);
        }

        private static byte[] DecryptCBCParallel(ISymmetricAlgorithm alg, byte[] data, byte[] iv, int blockSize)
        {
            byte[] result = new byte[data.Length];
            int blockCount = data.Length / blockSize;

            Parallel.For(0, blockCount, i =>
            {
                int offset = i * blockSize;
                byte[] cipherBlock = ExtractBlock(data, offset, blockSize);
                byte[] decrypted = alg.Decrypt(cipherBlock);
                byte[] prev = (i == 0) ? iv : ExtractBlock(data, (i - 1) * blockSize, blockSize);
                byte[] plainBlock = XorBlocks(decrypted, prev);

                lock (result)
                {
                    CopyBlock(plainBlock, result, offset);
                }
            });

            return result;
        }

        private static byte[] DecryptCFBParallel(ISymmetricAlgorithm alg, byte[] data, byte[] iv, int blockSize)
        {
            byte[] result = new byte[data.Length];
            int blockCount = data.Length / blockSize;

            Parallel.For(0, blockCount, i =>
            {
                int offset = i * blockSize;
                byte[] cipherBlock = ExtractBlock(data, offset, blockSize);
                byte[] prev = (i == 0) ? iv : ExtractBlock(data, (i - 1) * blockSize, blockSize);
                byte[] gamma = alg.Encrypt(prev);
                byte[] plainBlock = XorBlocks(cipherBlock, gamma);

                lock (result)
                {
                    CopyBlock(plainBlock, result, offset);
                }
            });

            return result;
        }


        private static byte[] ExtractBlock(byte[] data, int offset, int blockSize)
        {
            byte[] block = new byte[blockSize];
            Array.Copy(data, offset, block, 0, blockSize);
            return block;
        }

        private static void CopyBlock(byte[] source, byte[] destination, int offset)
        {
            Array.Copy(source, 0, destination, offset, source.Length);
        }

        private static byte[] XorBlocks(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                throw new ArgumentException(
                    $"Длины блоков не совпадают: {a.Length} != {b.Length}");

            byte[] result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                result[i] = (byte)(a[i] ^ b[i]);
            return result;
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

        private static int ExtractDelta(object[] additionalParams)
        {
            if (additionalParams != null && additionalParams.Length > 0
                && additionalParams[0] is int delta && delta > 0)
            {
                return delta;
            }
            return 1; // Значение по умолчанию
        }
    }
}