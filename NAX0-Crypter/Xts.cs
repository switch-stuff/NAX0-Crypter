// Copyright (c) 2010 Gareth Lennox (garethl@dwakn.com)
// All rights reserved.

// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:

//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright notice,
//       this list of conditions and the following disclaimer in the documentation
//       and/or other materials provided with the distribution.
//     * Neither the name of Gareth Lennox nor the names of its
//       contributors may be used to endorse or promote products derived from this
//       software without specific prior written permission.

// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

using System;
using System.IO;
using System.Security.Cryptography;

namespace NAX0_Crypter
{
    public class Xts
    {
        private readonly SymmetricAlgorithm _key1;
        private readonly SymmetricAlgorithm _key2;
        protected Xts(Func<SymmetricAlgorithm> create, byte[] key1, byte[] key2)
        {
            _key1 = create();
            _key2 = create();
            _key1.KeySize = key1.Length * 8;
            _key2.KeySize = key2.Length * 8;
            _key1.Key = key1;
            _key2.Key = key2;
            _key1.Mode = CipherMode.ECB;
            _key2.Mode = CipherMode.ECB;
            _key1.Padding = PaddingMode.None;
            _key2.Padding = PaddingMode.None;
            _key1.BlockSize = 16 * 8;
            _key2.BlockSize = 16 * 8;
        }
        public XtsCryptoTransform CreateEncryptor()
        {
            return new XtsCryptoTransform(_key1.CreateEncryptor(), _key2.CreateEncryptor(), false);
        }
        public XtsCryptoTransform CreateDecryptor()
        {
            return new XtsCryptoTransform(_key1.CreateDecryptor(), _key2.CreateEncryptor(), true);
        }
        protected static byte[] VerifyKey(int expectedSize, byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            if (key.Length * 8 != expectedSize)
                throw new ArgumentException(string.Format("Expected key length of {0} bits, got {1}", expectedSize, key.Length * 8));

            return key;
        }
        public class XtsAes128 : Xts
        {
            private const int KEY_LENGTH = 128;
            private const int KEY_BYTE_LENGTH = KEY_LENGTH / 8;
            protected XtsAes128(Func<SymmetricAlgorithm> create, byte[] key1, byte[] key2)
                : base(create, VerifyKey(KEY_LENGTH, key1), VerifyKey(KEY_LENGTH, key2))
            {
            }
            public static Xts Create(byte[] key1, byte[] key2)
            {
                VerifyKey(KEY_LENGTH, key1);
                VerifyKey(KEY_LENGTH, key2);

                return new XtsAes128(Aes.Create, key1, key2);
            }
        }
        public class XtsCryptoTransform : IDisposable
        {
            private readonly byte[] _cc = new byte[16];
            private readonly bool _decrypting;
            private readonly ICryptoTransform _key1;
            private readonly ICryptoTransform _key2;
            private readonly byte[] _pp = new byte[16];
            private readonly byte[] _t = new byte[16];
            private readonly byte[] _tweak = new byte[16];
            public XtsCryptoTransform(ICryptoTransform key1, ICryptoTransform key2, bool decrypting)
            {
                _key1 = key1;
                _key2 = key2;
                _decrypting = decrypting;
            }
            public void Dispose()
            {
                _key1.Dispose();
                _key2.Dispose();
            }
            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset, ulong sector)
            {
                FillArrayFromSectorLittleEndian(_tweak, sector);
                int lim;
                var m = inputCount >> 4;
                var mo = inputCount & 15;
                _key2.TransformBlock(_tweak, 0, _tweak.Length, _t, 0);
                if (mo == 0)
                    lim = m;
                else
                    lim = m - 1;
                for (var i = 0; i < lim; i++)
                {
                    TweakCrypt(inputBuffer, inputOffset, outputBuffer, outputOffset, _t);
                    inputOffset += 16;
                    outputOffset += 16;
                }
                if (mo > 0)
                {
                    if (_decrypting)
                    {
                        Buffer.BlockCopy(_t, 0, _cc, 0, 16);
                        MultiplyByX(_cc);
                        TweakCrypt(inputBuffer, inputOffset, _pp, 0, _cc);
                        int i;
                        for (i = 0; i < mo; i++)
                        {
                            _cc[i] = inputBuffer[16 + i + inputOffset];
                            outputBuffer[16 + i + outputOffset] = _pp[i];
                        }
                        for (; i < 16; i++)
                        {
                            _cc[i] = _pp[i];
                        }
                        TweakCrypt(_cc, 0, outputBuffer, outputOffset, _t);
                    }
                    else
                    {
                        TweakCrypt(inputBuffer, inputOffset, _cc, 0, _t);
                        int i;
                        for (i = 0; i < mo; i++)
                        {
                            _pp[i] = inputBuffer[16 + i + inputOffset];
                            outputBuffer[16 + i + outputOffset] = _cc[i];
                        }
                        for (; i < 16; i++)
                        {
                            _pp[i] = _cc[i];
                        }
                        TweakCrypt(_pp, 0, outputBuffer, outputOffset, _t);
                    }
                }

                return inputCount;
            }
            private static void FillArrayFromSectorLittleEndian(byte[] value, ulong sector)
            {
                value[0x8] = (byte)((sector >> 56) & 255);
                value[0x9] = (byte)((sector >> 48) & 255);
                value[0xA] = (byte)((sector >> 40) & 255);
                value[0xB] = (byte)((sector >> 32) & 255);
                value[0xC] = (byte)((sector >> 24) & 255);
                value[0xD] = (byte)((sector >> 16) & 255);
                value[0xE] = (byte)((sector >> 8) & 255);
                value[0xF] = (byte)(sector & 255);
            }
            private void TweakCrypt(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset, byte[] t)
            {
                for (var x = 0; x < 16; x++)
                {
                    outputBuffer[x + outputOffset] = (byte)(inputBuffer[x + inputOffset] ^ t[x]);
                }
                _key1.TransformBlock(outputBuffer, outputOffset, 16, outputBuffer, outputOffset);
                for (var x = 0; x < 16; x++)
                {
                    outputBuffer[x + outputOffset] = (byte)(outputBuffer[x + outputOffset] ^ t[x]);
                }
                MultiplyByX(t);
            }
            private static void MultiplyByX(byte[] i)
            {
                byte t = 0, tt = 0;
                for (var x = 0; x < 16; x++)
                {
                    tt = (byte)(i[x] >> 7);
                    i[x] = (byte)(((i[x] << 1) | t) & 0xFF);
                    t = tt;
                }
                if (tt > 0)
                    i[0] ^= 0x87;
            }
        }
        public class XtsSectorStream : SectorStream
        {
            public const int DEFAULT_SECTOR_SIZE = 512;
            private readonly byte[] _tempBuffer;
            private readonly Xts _xts;
            private XtsCryptoTransform _decryptor;
            private XtsCryptoTransform _encryptor;
            public XtsSectorStream(Stream baseStream, Xts xts)
                : this(baseStream, xts, DEFAULT_SECTOR_SIZE)
            {
            }
            public XtsSectorStream(Stream baseStream, Xts xts, int sectorSize)
                : this(baseStream, xts, sectorSize, 0)
            {
            }
            public XtsSectorStream(Stream baseStream, Xts xts, int sectorSize, long offset)
                : base(baseStream, sectorSize, offset)
            {
                _xts = xts;
                _tempBuffer = new byte[sectorSize];
            }
            protected override void Dispose(bool disposing)
            {
                base.Dispose(disposing);

                if (_encryptor != null)
                    _encryptor.Dispose();

                if (_decryptor != null)
                    _decryptor.Dispose();
            }
            public override void Write(byte[] buffer, int offset, int count)
            {
                ValidateSize(count);
                if (count == 0)
                    return;
                var currentSector = CurrentSector;

                if (_encryptor == null)
                    _encryptor = _xts.CreateEncryptor();
                int transformedCount = _encryptor.TransformBlock(buffer, offset, count, _tempBuffer, 0, currentSector);
                base.Write(_tempBuffer, 0, transformedCount);
            }
            public override int Read(byte[] buffer, int offset, int count)
            {
                ValidateSize(count);
                var currentSector = CurrentSector;
                var ret = base.Read(_tempBuffer, 0, count);
                if (ret == 0)
                    return 0;
                if (_decryptor == null)
                    _decryptor = _xts.CreateDecryptor();
                var retV = _decryptor.TransformBlock(_tempBuffer, 0, ret, buffer, offset, currentSector);
                return retV;
            }
        }

        public class XtsStream : RandomAccessSectorStream
        {
            public XtsStream(Stream baseStream, Xts xts)
                : this(baseStream, xts, XtsSectorStream.DEFAULT_SECTOR_SIZE)
            {
            }
            public XtsStream(Stream baseStream, Xts xts, int sectorSize)
                : base(new XtsSectorStream(baseStream, xts, sectorSize), true)
            {
            }
            public XtsStream(Stream baseStream, Xts xts, int sectorSize, long offset)
                : base(new XtsSectorStream(baseStream, xts, sectorSize, offset), true)
            {
            }
        }
        public class SectorStream : Stream
        {
            private readonly Stream _baseStream;
            private readonly long _offset;
            public SectorStream(Stream baseStream, int sectorSize)
                : this(baseStream, sectorSize, 0)
            {
            }
            public SectorStream(Stream baseStream, int sectorSize, long offset)
            {
                SectorSize = sectorSize;
                _baseStream = baseStream;
                _offset = offset;
            }
            public int SectorSize { get; private set; }
            public override bool CanRead
            {
                get { return _baseStream.CanRead; }
            }
            public override bool CanSeek
            {
                get { return _baseStream.CanSeek; }
            }
            public override bool CanWrite
            {
                get { return _baseStream.CanWrite; }
            }
            public override long Length
            {
                get { return _baseStream.Length - _offset; }
            }
            public override long Position
            {
                get { return _baseStream.Position - _offset; }
                set
                {
                    ValidateSizeMultiple(value);
                    _baseStream.Position = value + _offset;
                    CurrentSector = (ulong)(value / SectorSize);
                }
            }
            protected ulong CurrentSector { get; private set; }
            private void ValidateSizeMultiple(long value)
            {
                if (value % SectorSize != 0)
                    throw new ArgumentException(string.Format("Value needs to be a multiple of {0}", SectorSize));
            }
            protected void ValidateSize(long value)
            {
                if (value != SectorSize)
                    throw new ArgumentException(string.Format("Value needs to be {0}", SectorSize));
            }
            protected void ValidateSize(int value)
            {
                if (value != SectorSize)
                    throw new ArgumentException(string.Format("Value needs to be {0}", SectorSize));
            }
            public override void Flush()
            {
                _baseStream.Flush();
            }
            public override long Seek(long offset, SeekOrigin origin)
            {
                long newPosition;
                switch (origin)
                {
                    case SeekOrigin.Begin:
                        newPosition = offset;
                        break;

                    case SeekOrigin.End:
                        newPosition = Length - offset;
                        break;

                    default:
                        newPosition = Position + offset;
                        break;
                }

                Position = newPosition;

                return newPosition;
            }
            public override void SetLength(long value)
            {
                ValidateSizeMultiple(value);

                _baseStream.SetLength(value);
            }
            public override int Read(byte[] buffer, int offset, int count)
            {
                ValidateSize(count);

                var ret = _baseStream.Read(buffer, offset, count);
                CurrentSector++;
                return ret;
            }
            public override void Write(byte[] buffer, int offset, int count)
            {
                ValidateSize(count);

                _baseStream.Write(buffer, offset, count);
                CurrentSector++;
            }
        }
        public class RandomAccessSectorStream : Stream
        {
            private readonly byte[] _buffer;
            private readonly int _bufferSize;
            private readonly SectorStream _s;
            private readonly bool _isStreamOwned;
            private bool _bufferDirty;
            private bool _bufferLoaded;
            private int _bufferPos;
            public RandomAccessSectorStream(SectorStream s)
                : this(s, false)
            {
            }
            public RandomAccessSectorStream(SectorStream s, bool isStreamOwned)
            {
                _s = s;
                _isStreamOwned = isStreamOwned;
                _buffer = new byte[s.SectorSize];
                _bufferSize = s.SectorSize;
            }
            public override bool CanRead
            {
                get { return _s.CanRead; }
            }
            public override bool CanSeek
            {
                get { return _s.CanSeek; }
            }
            public override bool CanWrite
            {
                get { return _s.CanWrite; }
            }
            public override long Length
            {
                get { return _s.Length + _bufferPos; }
            }
            public override long Position
            {
                get { return _bufferLoaded ? (_s.Position - _bufferSize + _bufferPos) : _s.Position + _bufferPos; }
                set
                {
                    var sectorPosition = (value % _bufferSize);
                    var position = value - sectorPosition;
                    if (_bufferLoaded)
                    {
                        var basePosition = _s.Position - _bufferSize;
                        if (value > basePosition && value < basePosition + _bufferSize)
                        {
                            _bufferPos = (int)sectorPosition;
                            return;
                        }
                    }
                    if (_bufferDirty)
                        WriteSector();
                    _s.Position = position;
                    ReadSector();
                    _bufferPos = (int)sectorPosition;
                }
            }
            protected override void Dispose(bool disposing)
            {
                Flush();
                base.Dispose(disposing);
                if (_isStreamOwned)
                    _s.Dispose();
            }
            public override void Flush()
            {
                if (_bufferDirty)
                    WriteSector();
            }
            public override long Seek(long offset, SeekOrigin origin)
            {
                long newPosition;
                switch (origin)
                {
                    case SeekOrigin.Begin:
                        newPosition = offset;
                        break;
                    case SeekOrigin.End:
                        newPosition = Length - offset;
                        break;
                    default:
                        newPosition = Position + offset;
                        break;
                }
                Position = newPosition;
                return newPosition;
            }
            public override void SetLength(long value)
            {
                var remainder = value % _s.SectorSize;
                if (remainder > 0)
                {
                    value = (value - remainder) + _bufferSize;
                }
                _s.SetLength(value);
            }
            public override int Read(byte[] buffer, int offset, int count)
            {
                var position = Position;
                if (position + count > _s.Length)
                {
                    count = (int)(_s.Length - position);
                }
                if (!_bufferLoaded)
                    ReadSector();
                var totalBytesRead = 0;
                while (count > 0)
                {
                    var bytesToRead = Math.Min(count, _bufferSize - _bufferPos);
                    Buffer.BlockCopy(_buffer, _bufferPos, buffer, offset, bytesToRead);
                    offset += bytesToRead;
                    _bufferPos += bytesToRead;
                    count -= bytesToRead;
                    totalBytesRead += bytesToRead;
                    if (_bufferPos == _bufferSize)
                        ReadSector();
                }
                return totalBytesRead;
            }
            public override void Write(byte[] buffer, int offset, int count)
            {
                while (count > 0)
                {
                    if (!_bufferLoaded)
                        ReadSector();
                    var bytesToWrite = Math.Min(count, _bufferSize - _bufferPos);
                    Buffer.BlockCopy(buffer, offset, _buffer, _bufferPos, bytesToWrite);
                    offset += bytesToWrite;
                    _bufferPos += bytesToWrite;
                    count -= bytesToWrite;
                    _bufferDirty = true;
                    if (_bufferPos == _bufferSize)
                        WriteSector();
                }
            }
            private void ReadSector()
            {
                if (_bufferLoaded && _bufferDirty)
                {
                    WriteSector();
                }
                if (_s.Position == _s.Length)
                {
                    return;
                }
                var bytesRead = _s.Read(_buffer, 0, _buffer.Length);
                if (bytesRead != _bufferSize)
                    Array.Clear(_buffer, bytesRead, _buffer.Length - bytesRead);
                _bufferLoaded = true;
                _bufferPos = 0;
                _bufferDirty = false;
            }
            private void WriteSector()
            {
                if (_bufferLoaded)
                {
                    _s.Seek(-_bufferSize, SeekOrigin.Current);
                }
                _s.Write(_buffer, 0, _bufferSize);
                _bufferDirty = false;
                _bufferLoaded = false;
                _bufferPos = 0;
                Array.Clear(_buffer, 0, _bufferSize);
            }
        }
    }
}