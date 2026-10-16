using System;
using Crypt.Enums;

namespace Crypt.Utils
{
    public static class Paddings
    {
        public static byte[] AddPadding(byte[] data, int blockSize, PaddingMode paddingMode)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (blockSize <= 0)
                throw new ArgumentException("Размер блока должен быть положительным", nameof(blockSize));

            int padLength = blockSize - (data.Length % blockSize);

            byte[] result = new byte[data.Length + padLength];
            Array.Copy(data, result, data.Length);

            switch (paddingMode)
            {
                case PaddingMode.Zeros:
                    FillZeros(result, data.Length);
                    break;

                case PaddingMode.AnsiX923:
                    FillAnsiX923(result, data.Length, padLength);
                    break;

                case PaddingMode.PKCS7:
                    FillPKCS7(result, data.Length, padLength);
                    break;

                case PaddingMode.ISO10126:
                    FillISO10126(result, data.Length, padLength);
                    break;

                default:
                    throw new ArgumentException($"Неизвестный режим набивки: {paddingMode}");
            }

            return result;
        }

        public static byte[] RemovePadding(byte[] data, PaddingMode paddingMode)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (data.Length == 0)
                return data;

            int dataLength;

            switch (paddingMode)
            {
                case PaddingMode.Zeros:
                    dataLength = RemoveZeros(data);
                    break;

                case PaddingMode.AnsiX923:
                case PaddingMode.ISO10126:
                    dataLength = RemoveByLastByte(data);
                    break;

                case PaddingMode.PKCS7:
                    dataLength = RemoveByPkcs7(data);
                    break;

                default:
                    throw new ArgumentException($"Неизвестный режим набивки: {paddingMode}");
            }

            byte[] result = new byte[dataLength];
            Array.Copy(data, result, dataLength);
            return result;
        }

        private static void FillZeros(byte[] result, int offset)
        {
            // Уже заполнено нулями при создании массива
        }

        private static void FillAnsiX923(byte[] result, int offset, int padLength)
        {
            result[result.Length - 1] = (byte)padLength;
        }

        private static void FillPKCS7(byte[] result, int offset, int padLength)
        {
            for (int i = offset; i < result.Length; i++)
            {
                result[i] = (byte)padLength;
            }
        }

        private static void FillISO10126(byte[] result, int offset, int padLength)
        {
            Random random = new Random();
            for (int i = offset; i < result.Length - 1; i++)
            {
                result[i] = (byte)random.Next(0, 256);
            }
            result[result.Length - 1] = (byte)padLength;
        }


        private static int RemoveZeros(byte[] data)
        {
            int end = data.Length - 1;
            while (end >= 0 && data[end] == 0)
            {
                end--;
            }
            return end + 1;
        }

        private static int RemoveByLastByte(byte[] data)
        {
            byte padLength = data[data.Length - 1];

            if (padLength == 0 || padLength > data.Length)
                throw new InvalidOperationException(
                    $"Некорректная набивка: последний байт = {padLength}, длина данных = {data.Length}");

            return data.Length - padLength;
        }

        private static int RemoveByPkcs7(byte[] data)
        {
            byte padLength = data[data.Length - 1];

            if (padLength == 0 || padLength > data.Length)
                throw new InvalidOperationException(
                    $"Некорректная набивка PKCS7: последний байт = {padLength}");

            for (int i = data.Length - padLength; i < data.Length; i++)
            {
                if (data[i] != padLength)
                    throw new InvalidOperationException(
                        $"Некорректная набивка PKCS7: байт {i} = {data[i]}, ожидалось {padLength}");
            }

            return data.Length - padLength;
        }
    }
}