namespace Crypt.Interfaces
{
    public interface ISymmetricAlgorithm
    {
        void SetKey(byte[] key);

        byte[] Encrypt(byte[] block);

        byte[] Decrypt(byte[] block);
    }
}