using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Crypt.Algorithms.DEAL;
using Crypt.Algorithms.DES;
using Crypt.Context;
using Crypt.Enums;
using Crypt.Interfaces;

namespace Crypt.Demo
{
    public static class DemoRunner
    {
        private static readonly CipherMode[] Modes = {
            CipherMode.ECB, CipherMode.CBC, CipherMode.PCBC,
            CipherMode.CFB, CipherMode.OFB, CipherMode.CTR, CipherMode.RandomDelta
        };

        private static readonly PaddingMode[] Paddings = {
            PaddingMode.PKCS7, PaddingMode.AnsiX923,
            PaddingMode.ISO10126, PaddingMode.Zeros
        };

        // ============================================================
        //                     ТОЧКА ВХОДА
        // ============================================================

        public static async Task RunAllAsync()
        {
            PrintBanner("ДЕМОНСТРАЦИЯ DES И DEAL");

            // === DES ===
            await RunForAlgorithmAsync(
                algorithmName: "DES",
                algorithmFactory: () => new DesAlgorithm(),
                key: HexToBytes("133457799BBCDFF1"),                        // 8 байт
                iv: HexToBytes("A1B2C3D4E5F60718"),                          // 8 байт
                blockSize: 8,
                sizeScale: 1.0);

            // === DEAL ===
            await RunForAlgorithmAsync(
                algorithmName: "DEAL-128",
                algorithmFactory: () => new DealAlgorithm(),
                key: HexToBytes("00112233445566778899AABBCCDDEEFF"),         // 16 байт
                iv: HexToBytes("A1B2C3D4E5F60718293A4B5C6D7E8F90"),         // 16 байт
                blockSize: 16,
                sizeScale: 0.2);  // DEAL медленнее — уменьшаем объёмы

            PrintBanner("ДЕМОНСТРАЦИЯ ЗАВЕРШЕНА");
        }

        // ============================================================
        //               ОБОБЩЁННЫЙ ПРОГОН ДЛЯ АЛГОРИТМА
        // ============================================================

        private static async Task RunForAlgorithmAsync(
            string algorithmName,
            Func<ISymmetricAlgorithm> algorithmFactory,
            byte[] key,
            byte[] iv,
            int blockSize,
            double sizeScale)
        {
            Console.WriteLine();
            Console.WriteLine("╔═══════════════════════════════════════════════════════════════════╗");
            Console.WriteLine($"║  АЛГОРИТМ: {algorithmName,-20}                                   ║");
            Console.WriteLine($"║  Ключ: {key.Length,3} байт  |  Блок: {blockSize,3} байт  |  IV: {iv.Length,3} байт        ║");
            Console.WriteLine("╚═══════════════════════════════════════════════════════════════════╝");

            await DemoRandomBytesAsync(algorithmName, algorithmFactory, key, iv, blockSize, sizeScale);
            await DemoFilesAsync(algorithmName, algorithmFactory, key, iv, blockSize, sizeScale);
        }

        // ============================================================
        //               СЕКЦИЯ 1: СЛУЧАЙНЫЕ БАЙТЫ
        // ============================================================

        private static async Task DemoRandomBytesAsync(
            string algorithmName, Func<ISymmetricAlgorithm> factory,
            byte[] key, byte[] iv, int blockSize, double sizeScale)
        {
            Console.WriteLine();
            Console.WriteLine("─── Секция 1: Псевдослучайные последовательности байтов ───");

            int[] baseSizes = { 16, 1024, 64 * 1024, 1024 * 1024 };
            string[] labels = { "16 Б", "1 КБ", "64 КБ", "1 МБ" };

            for (int s = 0; s < baseSizes.Length; s++)
            {
                int size = Math.Max(16, (int)(baseSizes[s] * sizeScale));
                byte[] data = GenerateRandomBytes(size);

                int pass = 0, total = 0;
                var sw = Stopwatch.StartNew();

                foreach (var mode in Modes)
                {
                    foreach (var padding in Paddings)
                    {
                        total++;
                        byte[] testData = (padding == PaddingMode.Zeros)
                            ? EnsureNoTrailingZeros(data)
                            : data;

                        bool ok = TestEncryptDecryptSync(
                            factory, key, iv, blockSize, testData, mode, padding);
                        if (ok) pass++;
                    }
                }

                sw.Stop();
                Console.WriteLine($"   [{labels[s],-6}] {pass,2}/{total} PASS   ({sw.ElapsedMilliseconds} мс)");
            }
        }

        private static bool TestEncryptDecryptSync(
            Func<ISymmetricAlgorithm> factory,
            byte[] key, byte[] iv, int blockSize,
            byte[] data, CipherMode mode, PaddingMode padding)
        {
            try
            {
                var ctx = new SymmetricAlgorithmContext(
                    factory(), key, mode, padding, iv);
                byte[] enc = ctx.Encrypt(data);
                byte[] dec = ctx.Decrypt(enc);
                return BytesEqual(data, dec);
            }
            catch
            {
                return false;
            }
        }

        // ============================================================
        //               СЕКЦИЯ 2: ФАЙЛЫ РАЗНЫХ ТИПОВ
        // ============================================================

        private static async Task DemoFilesAsync(
            string algorithmName, Func<ISymmetricAlgorithm> factory,
            byte[] key, byte[] iv, int blockSize, double sizeScale)
        {
            Console.WriteLine();
            Console.WriteLine("─── Секция 2: Файлы разных типов ───");

            string dir = "demo_files";
            Directory.CreateDirectory(dir);

            string textFile  = Path.Combine(dir, "sample.txt");
            string imageFile = Path.Combine(dir, "sample.bmp");
            string audioFile = Path.Combine(dir, "sample.wav");
            string codeFile  = Path.Combine(dir, "sample.cs");
            string videoFile = Path.Combine(dir, "sample.raw");

            GenerateTextFile(textFile, (int)(50 * 1024 * sizeScale));
            GenerateBmpImage(imageFile, (int)(300 * Math.Sqrt(sizeScale)), (int)(300 * Math.Sqrt(sizeScale)));
            GenerateWavAudio(audioFile, Math.Max(1, (int)(2 * sizeScale)));
            await GenerateCodeFileAsync(codeFile);
            GenerateRandomFile(videoFile, (int)(500 * 1024 * sizeScale));

            (string path, string name)[] files = {
                (textFile,  "Текст       "),
                (imageFile, "Изображение "),
                (audioFile, "Музыка      "),
                (codeFile,  "Исходный код"),
                (videoFile, "\"Видео\"     ")
            };

            foreach (var (path, name) in files)
            {
                long fileSize = new FileInfo(path).Length;
                Console.WriteLine();
                Console.WriteLine($"   ┌── {name} ({FormatSize(fileSize)}) ──┐");

                foreach (var mode in Modes)
                {
                    var (ok, encMs, decMs) = await TestFileAsync(
                        factory, key, iv, blockSize, path, mode, PaddingMode.PKCS7);

                    string mark = ok ? "✓" : "✗";
                    string info = ok
                        ? $"{encMs,5} мс / {decMs,5} мс"
                        : "ОШИБКА";
                    Console.WriteLine($"   │  {mark} {mode,-12} {info}");
                }

                Console.WriteLine($"   └─────────────────────────────────┘");
            }

            try { Directory.Delete(dir, recursive: true); } catch { }
        }

        private static async Task<(bool ok, long encMs, long decMs)> TestFileAsync(
            Func<ISymmetricAlgorithm> factory,
            byte[] key, byte[] iv, int blockSize,
            string inputPath, CipherMode mode, PaddingMode padding)
        {
            string encPath = inputPath + ".enc";
            string decPath = inputPath + ".dec";

            try
            {
                var ctx = new SymmetricAlgorithmContext(
                    factory(), key, mode, padding, iv);

                var sw = Stopwatch.StartNew();
                await ctx.EncryptFileAsync(inputPath, encPath);
                sw.Stop();
                long encMs = sw.ElapsedMilliseconds;

                sw.Restart();
                await ctx.DecryptFileAsync(encPath, decPath);
                sw.Stop();
                long decMs = sw.ElapsedMilliseconds;

                byte[] original = await File.ReadAllBytesAsync(inputPath);
                byte[] restored = await File.ReadAllBytesAsync(decPath);

                return (BytesEqual(original, restored), encMs, decMs);
            }
            catch
            {
                return (false, 0, 0);
            }
            finally
            {
                try { File.Delete(encPath); } catch { }
                try { File.Delete(decPath); } catch { }
            }
        }

        // ============================================================
        //              ГЕНЕРАЦИЯ ТЕСТОВЫХ ФАЙЛОВ
        // ============================================================

        private static void GenerateTextFile(string path, int approxBytes)
        {
            var sb = new StringBuilder();
            int i = 0;
            while (sb.Length < approxBytes)
            {
                sb.AppendLine($"Строка {i++}: Это тестовый текст для проверки DES и DEAL. " +
                              $"Символы: !@#$%^&*()_+ абвгдежзий");
            }
            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        }

        private static void GenerateBmpImage(string path, int width, int height)
        {
            width = Math.Max(20, width);
            height = Math.Max(20, height);

            int rowSize = (width * 3 + 3) & ~3;
            int pixelSize = rowSize * height;
            int fileSize = 54 + pixelSize;

            using var fs = new FileStream(path, FileMode.Create);
            using var bw = new BinaryWriter(fs);

            bw.Write((ushort)0x4D42);
            bw.Write(fileSize);
            bw.Write((ushort)0); bw.Write((ushort)0);
            bw.Write(54);

            bw.Write(40);
            bw.Write(width); bw.Write(height);
            bw.Write((ushort)1); bw.Write((ushort)24);
            bw.Write(0); bw.Write(pixelSize);
            bw.Write(2835); bw.Write(2835);
            bw.Write(0); bw.Write(0);

            for (int y = 0; y < height; y++)
            {
                for (int x = 0; x < width; x++)
                {
                    bw.Write((byte)(x * 255 / width));
                    bw.Write((byte)(y * 255 / height));
                    bw.Write((byte)128);
                }
                for (int p = width * 3; p < rowSize; p++)
                    bw.Write((byte)0);
            }
        }

        private static void GenerateWavAudio(string path, int seconds)
        {
            const int sampleRate = 44100;
            const short channels = 1;
            const short bitsPerSample = 16;
            int sampleCount = sampleRate * seconds;
            int dataSize = sampleCount * channels * (bitsPerSample / 8);

            using var fs = new FileStream(path, FileMode.Create);
            using var bw = new BinaryWriter(fs);

            bw.Write(Encoding.ASCII.GetBytes("RIFF"));
            bw.Write(36 + dataSize);
            bw.Write(Encoding.ASCII.GetBytes("WAVE"));

            bw.Write(Encoding.ASCII.GetBytes("fmt "));
            bw.Write(16);
            bw.Write((short)1);
            bw.Write(channels);
            bw.Write(sampleRate);
            bw.Write(sampleRate * channels * (bitsPerSample / 8));
            bw.Write((short)(channels * (bitsPerSample / 8)));
            bw.Write(bitsPerSample);

            bw.Write(Encoding.ASCII.GetBytes("data"));
            bw.Write(dataSize);

            for (int i = 0; i < sampleCount; i++)
            {
                double t = (double)i / sampleRate;
                double value = 0.5 * Math.Sin(2 * Math.PI * 440 * t)
                             + 0.3 * Math.Sin(2 * Math.PI * 880 * t);
                short sample = (short)(value * short.MaxValue * 0.9);
                bw.Write(sample);
            }
        }

        private static async Task GenerateCodeFileAsync(string path)
        {
            string sourceDir = Directory.GetCurrentDirectory();
            var sb = new StringBuilder();

            foreach (var file in Directory.EnumerateFiles(sourceDir, "*.cs", SearchOption.AllDirectories))
            {
                if (file.Contains("/obj/") || file.Contains("/bin/")) continue;
                try
                {
                    sb.AppendLine($"// === {Path.GetFileName(file)} ===");
                    sb.AppendLine(await File.ReadAllTextAsync(file));
                    sb.AppendLine();
                }
                catch { }
            }

            if (sb.Length == 0)
                sb.AppendLine("// Fallback: пустой файл");

            await File.WriteAllTextAsync(path, sb.ToString(), Encoding.UTF8);
        }

        private static void GenerateRandomFile(string path, int size)
        {
            size = Math.Max(16, size);
            byte[] data = new byte[size];
            new Random(123).NextBytes(data);
            File.WriteAllBytes(path, data);
        }

        // ============================================================
        //                    УТИЛИТЫ
        // ============================================================

        private static byte[] GenerateRandomBytes(int size)
        {
            byte[] data = new byte[size];
            new Random(42).NextBytes(data);
            return data;
        }

        private static byte[] EnsureNoTrailingZeros(byte[] data)
        {
            byte[] copy = (byte[])data.Clone();
            for (int i = copy.Length - 1; i >= 0 && copy[i] == 0; i--)
                copy[i] = 1;
            return copy;
        }

        private static byte[] HexToBytes(string hex)
        {
            if (hex.Length % 2 != 0)
                throw new ArgumentException($"Нечётная длина hex: {hex.Length}.");
            byte[] r = new byte[hex.Length / 2];
            for (int i = 0; i < r.Length; i++)
                r[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return r;
        }

        private static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }

        private static string FormatSize(long bytes)
        {
            if (bytes < 1024) return $"{bytes} Б";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} КБ";
            return $"{bytes / 1024.0 / 1024.0:F2} МБ";
        }

        private static void PrintBanner(string text)
        {
            Console.WriteLine();
            Console.WriteLine("╔═══════════════════════════════════════════════════════════════════╗");
            Console.WriteLine($"║  {text,-65}║");
            Console.WriteLine("╚═══════════════════════════════════════════════════════════════════╝");
        }
    }
}