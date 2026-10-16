namespace Crypt.Interfaces
{
    public interface IKeyExpander
    {
        byte[][] ExpandKey(byte[] key);
    }
}