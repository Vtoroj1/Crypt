using System;
using Crypt.Enums;
using Crypt.Interfaces;
using Crypt.Utils;
using System.Threading.Tasks;
using System.IO;

namespace Crypt.Context
{
    public class SymmetricAlgorithmContext
    {   
        private readonly ISymmetricAlgorithm _algorithm;
        
        private readonly byte[] _key;
        
        private readonly CipherMode _cipherMode;
        
        private readonly PaddingMode _paddingMode;
        
        private readonly byte[] _initializationVector;
        
        private readonly object[] _additionalParams;
        
        private readonly int _blockSize;

        public SymmetricAlgorithmContext(
            ISymmetricAlgorithm algorithm,
            byte[] key,
            CipherMode cipherMode,
            PaddingMode paddingMode,
            byte[] initializationVector = null,
            params object[] additionalParams)
        {
            _algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm), "Алгоритм шифрования не может быть null");
            
            if (key == null || key.Length == 0)
                throw new ArgumentException("Ключ шифрования не может быть пустым", nameof(key));

            _key = (byte[])key.Clone();
            _cipherMode = cipherMode;
            _paddingMode = paddingMode;
            _initializationVector = initializationVector != null ? (byte[])initializationVector.Clone() : null;
            _additionalParams = additionalParams ?? new object[0];
            
            _algorithm.SetKey(_key);
            _blockSize = DetermineBlockSize(_algorithm);
            
            ValidateInitializationVector();
        }

        public byte[] Encrypt(byte[] data)
        {
            return EncryptInternal(data);
        }

        public void Encrypt(byte[] data, out byte[] result)
        {
            result = EncryptInternal(data);
        }

        public byte[] Decrypt(byte[] data)
        {
            return DecryptInternal(data);
        }

        public void Decrypt(byte[] data, out byte[] result)
        {
            result = DecryptInternal(data);
        }


        private byte[] EncryptInternal(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data), "Данные не могут быть null");
            if (data.Length == 0)
                throw new ArgumentException("Данные не могут быть пустыми", nameof(data));

            byte[] paddedData = Paddings.AddPadding(data, _blockSize, _paddingMode);

            byte[] ciphertext = CipherModes.Encrypt(
                _algorithm,
                paddedData,
                _cipherMode,
                _initializationVector,
                _blockSize,
                _additionalParams);

            return ciphertext;
        }

        private byte[] DecryptInternal(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data), "Данные не могут быть null");
            if (data.Length == 0)
                throw new ArgumentException("Данные не могут быть пустыми", nameof(data));
            if (data.Length % _blockSize != 0)
                throw new ArgumentException(
                    $"Длина шифртекста ({data.Length}) должна быть кратна размеру блока ({_blockSize})",
                    nameof(data));

            byte[] paddedPlaintext = CipherModes.Decrypt(
                _algorithm,
                data,
                _cipherMode,
                _initializationVector,
                _blockSize,
                _additionalParams);

            byte[] plaintext = Paddings.RemovePadding(paddedPlaintext, _paddingMode);

            return plaintext;
        }


        public Task<byte[]> EncryptAsync(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            byte[] dataCopy = (byte[])data.Clone();

            return Task.Run(() => EncryptInternal(dataCopy));
        }

        public Task<byte[]> DecryptAsync(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            byte[] dataCopy = (byte[])data.Clone();

            return Task.Run(() => DecryptInternal(dataCopy));
        }

        public async Task EncryptAsync(byte[] data, Action<byte[]> onCompleted)
        {
            if (onCompleted == null)
                throw new ArgumentNullException(nameof(onCompleted));

            byte[] result = await EncryptAsync(data);
            onCompleted(result);
        }

        public async Task DecryptAsync(byte[] data, Action<byte[]> onCompleted)
        {
            if (onCompleted == null)
                throw new ArgumentNullException(nameof(onCompleted));

            byte[] result = await DecryptAsync(data);
            onCompleted(result);
        }


        public async Task EncryptFileAsync(string inputPath, string outputPath)
        {
            ValidateFilePaths(inputPath, outputPath);

            const int ChunkBlocks = 1024;
            int chunkBytes = ChunkBlocks * _blockSize;
            int streamBufferSize = Math.Max(chunkBytes, 4096);

            using var inputStream  = new FileStream(inputPath, FileMode.Open, FileAccess.Read,
                                                    FileShare.Read, streamBufferSize, useAsync: true);
            using var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write,
                                                    FileShare.None, streamBufferSize, useAsync: true);

            var processor = new CipherModeProcessor(
                _algorithm, _cipherMode, _initializationVector, _blockSize, _additionalParams);

            byte[] inputBuffer = new byte[chunkBytes];
            byte[] outputBuffer = new byte[chunkBytes];
            byte[] carryOver = new byte[_blockSize];
            int carryOverLength = 0;

            while (true)
            {
                int bytesRead = await inputStream.ReadAsync(inputBuffer.AsMemory(0, chunkBytes));
                if (bytesRead == 0) break;

                int totalAvailable = carryOverLength + bytesRead;
                byte[] working = new byte[totalAvailable];
                if (carryOverLength > 0)
                    Array.Copy(carryOver, 0, working, 0, carryOverLength);
                Array.Copy(inputBuffer, 0, working, carryOverLength, bytesRead);

                int fullBlocks = totalAvailable / _blockSize;
                int processedBytes = fullBlocks * _blockSize;

                for (int i = 0; i < fullBlocks; i++)
                {
                    byte[] block = new byte[_blockSize];
                    Array.Copy(working, i * _blockSize, block, 0, _blockSize);
                    byte[] cipherBlock = processor.EncryptBlock(block);
                    Array.Copy(cipherBlock, 0, outputBuffer, i * _blockSize, _blockSize);
                }

                if (fullBlocks > 0)
                    await outputStream.WriteAsync(outputBuffer.AsMemory(0, processedBytes));

                carryOverLength = totalAvailable - processedBytes;
                if (carryOverLength > 0)
                    Array.Copy(working, processedBytes, carryOver, 0, carryOverLength);
            }

            byte[] tail = new byte[carryOverLength];
            Array.Copy(carryOver, 0, tail, 0, carryOverLength);

            byte[] paddedTail = Paddings.AddPadding(tail, _blockSize, _paddingMode);

            for (int i = 0; i < paddedTail.Length; i += _blockSize)
            {
                byte[] block = new byte[_blockSize];
                Array.Copy(paddedTail, i, block, 0, _blockSize);
                byte[] cipherBlock = processor.EncryptBlock(block);
                await outputStream.WriteAsync(cipherBlock);
            }
        }

        public async Task DecryptFileAsync(string inputPath, string outputPath)
        {
            ValidateFilePaths(inputPath, outputPath);

            long fileSize = new FileInfo(inputPath).Length;
            if (fileSize % _blockSize != 0)
                throw new InvalidDataException(
                    $"Размер шифртекста ({fileSize}) не кратен размеру блока ({_blockSize})");

            const int ChunkBlocks = 1024;
            int chunkBytes = ChunkBlocks * _blockSize;
            int streamBufferSize = Math.Max(chunkBytes, 4096);

            using var inputStream  = new FileStream(inputPath, FileMode.Open, FileAccess.Read,
                                                    FileShare.Read, streamBufferSize, useAsync: true);
            using var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write,
                                                    FileShare.None, streamBufferSize, useAsync: true);

            var processor = new CipherModeProcessor(
                _algorithm, _cipherMode, _initializationVector, _blockSize, _additionalParams);

            byte[] inputBuffer  = new byte[chunkBytes];
            byte[] outputBuffer = new byte[chunkBytes];
            byte[] lastPlainBlock = null;

            while (true)
            {
                int bytesRead = await inputStream.ReadAsync(inputBuffer.AsMemory(0, chunkBytes));
                if (bytesRead == 0) break;

                int blockCount = bytesRead / _blockSize;
                int outputLength = 0;

                for (int i = 0; i < blockCount; i++)
                {
                    byte[] block = new byte[_blockSize];
                    Array.Copy(inputBuffer, i * _blockSize, block, 0, _blockSize);
                    byte[] plainBlock = processor.DecryptBlock(block);

                    if (lastPlainBlock != null)
                    {
                        Array.Copy(lastPlainBlock, 0, outputBuffer, outputLength, _blockSize);
                        outputLength += _blockSize;
                    }
                    lastPlainBlock = plainBlock;
                }

                if (outputLength > 0)
                    await outputStream.WriteAsync(outputBuffer.AsMemory(0, outputLength));
            }

            if (lastPlainBlock != null)
            {
                byte[] plain = Paddings.RemovePadding(lastPlainBlock, _paddingMode);
                if (plain.Length > 0)
                    await outputStream.WriteAsync(plain);
            }
        }

        private static void ValidateFilePaths(string inputPath, string outputPath)
        {
            if (string.IsNullOrWhiteSpace(inputPath))
                throw new ArgumentException("Путь к входному файлу пуст", nameof(inputPath));
            if (string.IsNullOrWhiteSpace(outputPath))
                throw new ArgumentException("Путь к выходному файлу пуст", nameof(outputPath));
            if (!File.Exists(inputPath))
                throw new FileNotFoundException("Входной файл не найден", inputPath);
        }

        private static int DetermineBlockSize(ISymmetricAlgorithm algorithm)
        {
            byte[] testBlock = new byte[16];
            try
            {
                byte[] result = algorithm.Encrypt(testBlock);
                return result.Length;
            }
            catch
            {
                byte[] smallBlock = new byte[8];
                return algorithm.Encrypt(smallBlock).Length;
            }
        }
        
        private void ValidateInitializationVector()
        {
            bool requiresIV = _cipherMode == CipherMode.CBC 
                           || _cipherMode == CipherMode.PCBC
                           || _cipherMode == CipherMode.CFB 
                           || _cipherMode == CipherMode.OFB;
            
            if (requiresIV && _initializationVector == null)
                throw new ArgumentException(
                    $"Режим {_cipherMode} требует IV");
            
            if (_initializationVector != null && _initializationVector.Length != _blockSize)
                throw new ArgumentException(
                    $"Длина IV ({_initializationVector.Length} байт) должна совпадать с размером блока ({_blockSize} байт)");
        }
    }
}