namespace Crypt.Interfaces
{
    public interface IBlockCipher
    {
        byte[] Transform(byte[] inputBlock, byte[] roundKey);
    }
}