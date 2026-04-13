using LibUA.Core;

namespace LibUA.Tests
{
    public class MemoryBufferTests
    {
        private static MemoryBuffer CreateBufferWithUInt32(uint value)
        {
            var data = new byte[4];
            data[0] = (byte)(value & 0xFF);
            data[1] = (byte)((value >> 8) & 0xFF);
            data[2] = (byte)((value >> 16) & 0xFF);
            data[3] = (byte)((value >> 24) & 0xFF);
            return new MemoryBuffer(data);
        }

        [Fact]
        public void DecodeArraySize_Zero_ReturnsZero()
        {
            using var buffer = CreateBufferWithUInt32(0);
            var result = buffer.DecodeArraySize(out uint size);
            Assert.True(result);
            Assert.Equal(0u, size);
        }

        [Fact]
        public void DecodeArraySize_ValidSize_ReturnsSize()
        {
            using var buffer = CreateBufferWithUInt32(100);
            var result = buffer.DecodeArraySize(out uint size);
            Assert.True(result);
            Assert.Equal(100u, size);
        }

        [Fact]
        public void DecodeArraySize_MaxArraySize_ReturnsMax()
        {
            using var buffer = CreateBufferWithUInt32(MemoryBuffer.MaxArraySize);
            var result = buffer.DecodeArraySize(out uint size);
            Assert.True(result);
            Assert.Equal(MemoryBuffer.MaxArraySize, size);
        }

        [Fact]
        public void DecodeArraySize_SentinelValue_ReturnsZero()
        {
            using var buffer = CreateBufferWithUInt32(0xFFFFFFFF);
            var result = buffer.DecodeArraySize(out uint size);
            Assert.True(result);
            Assert.Equal(0u, size);
        }

        [Fact]
        public void DecodeArraySize_ExceedsMax_ReturnsFalse()
        {
            using var buffer = CreateBufferWithUInt32(MemoryBuffer.MaxArraySize + 1);
            var result = buffer.DecodeArraySize(out uint size);
            Assert.False(result);
        }

        [Fact]
        public void DecodeArraySize_OversizedValue_ReturnsFalse()
        {
            using var buffer = CreateBufferWithUInt32(0xFFFFFFFE);
            var result = buffer.DecodeArraySize(out uint size);
            Assert.False(result);
        }

        [Fact]
        public void DecodeArraySize_JustBelowMax_ReturnsTrue()
        {
            using var buffer = CreateBufferWithUInt32(MemoryBuffer.MaxArraySize - 1);
            var result = buffer.DecodeArraySize(out uint size);
            Assert.True(result);
            Assert.Equal(MemoryBuffer.MaxArraySize - 1, size);
        }

        [Fact]
        public void DecodeArraySize_JustAboveMax_ReturnsFalse()
        {
            using var buffer = CreateBufferWithUInt32(MemoryBuffer.MaxArraySize + 1);
            var result = buffer.DecodeArraySize(out uint size);
            Assert.False(result);
        }
    }
}