
// Type: LibUA.UASecurity
using LibUA.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LibUA
{
    public static class UASecurity
    {
        public const int Sha1Size = 20;
        public const int Sha256Size = 32;
        public const int RsaPkcs1PaddingSize = 11;
        public const int RsaPkcs1OaepPaddingSize = 42;
        public const int ActivationNonceSize = 32;

        public static UASecurity.PaddingAlgorithm PaddingMethodForSecurityPolicy(
          SecurityPolicy policy)
        {
            switch (policy)
            {
                case SecurityPolicy.Basic256:
                    return UASecurity.PaddingAlgorithm.PKCS1_OAEP;
                case SecurityPolicy.Basic128Rsa15:
                    return UASecurity.PaddingAlgorithm.PKCS1;
                case SecurityPolicy.Basic256Sha256:
                    return UASecurity.PaddingAlgorithm.PKCS1_OAEP;
                default:
                    throw new Exception();
            }
        }

        public static int SymmetricKeySizeForSecurityPolicy(
          SecurityPolicy policy,
          int clientNonceLength = -1)
        {
            switch (policy)
            {
                case SecurityPolicy.Basic256:
                    return 32;
                case SecurityPolicy.Basic128Rsa15:
                    return 16;
                case SecurityPolicy.Basic256Sha256:
                    return clientNonceLength < 1 ? 32 : clientNonceLength;
                default:
                    throw new Exception();
            }
        }

        public static int SymmetricBlockSizeForSecurityPolicy(SecurityPolicy policy)
        {
            return 16;
        }

        public static int SymmetricSignatureKeySizeForSecurityPolicy(SecurityPolicy policy)
        {
            switch (policy)
            {
                case SecurityPolicy.Basic256:
                    return 24;
                case SecurityPolicy.Basic128Rsa15:
                    return UASecurity.SymmetricKeySizeForSecurityPolicy(policy, -1);
                case SecurityPolicy.Basic256Sha256:
                    return 32;
                default:
                    throw new Exception();
            }
        }

        public static RSAEncryptionPadding UseOaepForSecurityPolicy(
          SecurityPolicy policy)
        {
            switch (policy)
            {
                case SecurityPolicy.Basic256:
                case SecurityPolicy.Basic256Sha256:
                    return RSAEncryptionPadding.OaepSHA1;
                default:
                    return RSAEncryptionPadding.Pkcs1;
            }
        }

        public static int CalculatePublicKeyLength(X509Certificate2 cert)
        {
            if (!(cert.PublicKey.Key is RSA key))
            {
                throw new Exception("Could not create RSA");
            }

            return key.KeySize;
        }

        public static int CalculatePaddingSize(
          X509Certificate2 cert,
          SecurityPolicy policy,
          int position,
          int sigSize)
        {
            int plainBlockSize = UASecurity.GetPlainBlockSize(cert, UASecurity.UseOaepForSecurityPolicy(policy));
            int num = plainBlockSize - (position + sigSize) % plainBlockSize;
            if (num < 0)
            {
                throw new Exception();
            }

            return num;
        }

        public static int CalculateSymmetricEncryptedSize(int keySize, int position)
        {
            return (position + keySize - 1) / keySize * keySize;
        }

        public static int CalculateSymmetricPaddingSize(int keySize, int position)
        {
            if (keySize > 256)
            {
                throw new Exception("TODO: Handle keys above 2048 bits");
            }

            int num1 = position + keySize + 1;
            if (keySize > 0)
            {
                num1 -= num1 % keySize;
            }

            int num2 = num1 - position;
            if (num2 < 0 || num2 > 256)
            {
                throw new Exception();
            }

            return num2;
        }

        public static int CalculateSignatureSize(RSA key)
        {
            return key.KeySize / 8;
        }

        public static int CalculateSignatureSize(X509Certificate2 cert)
        {
            return UASecurity.CalculateSignatureSize(cert.PublicKey.Key as RSA);
        }

        public static int CalculateEncryptedSize(
          X509Certificate2 cert,
          int messageSize,
          UASecurity.PaddingAlgorithm paddingAlgorithm)
        {
            if (!(cert.PublicKey.Key is RSA))
            {
                throw new Exception("Could not create RSA");
            }

            int num1 = UASecurity.PaddingSizeForMethod(paddingAlgorithm);
            int num2 = UASecurity.CalculatePublicKeyLength(cert) / 8;
            if (num2 < num1)
            {
                throw new Exception();
            }

            int num3 = num2 - num1;
            return (messageSize + num3 - 1) / num3 * num2;
        }

        public static int PaddingSizeForMethod(UASecurity.PaddingAlgorithm paddingMethod)
        {
            switch (paddingMethod)
            {
                case UASecurity.PaddingAlgorithm.None:
                    return 0;
                case UASecurity.PaddingAlgorithm.PKCS1:
                    return 11;
                case UASecurity.PaddingAlgorithm.PKCS1_OAEP:
                    return 42;
                default:
                    throw new Exception();
            }
        }

        public static string ExportPEM(X509Certificate cert)
        {
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.AppendLine("-----BEGIN CERTIFICATE-----");
            stringBuilder.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            stringBuilder.AppendLine("-----END CERTIFICATE-----");
            return stringBuilder.ToString();
        }

        public static byte[] GenerateRandomBits(int numBits)
        {
            return UASecurity.GenerateRandomBytes((numBits + 7) / 8);
        }

        public static byte[] GenerateRandomBytes(int numBytes)
        {
            RandomNumberGenerator randomNumberGenerator = new RNGCryptoServiceProvider();
            byte[] data = new byte[numBytes];
            randomNumberGenerator.GetBytes(data);
            return data;
        }

        public static byte[] AesEncrypt(ArraySegment<byte> data, byte[] key, byte[] iv)
        {
            AesManaged aesManaged1 = new AesManaged();
            aesManaged1.Mode = CipherMode.CBC;
            aesManaged1.IV = iv;
            aesManaged1.Key = key;
            aesManaged1.Padding = PaddingMode.PKCS7;
            using (AesManaged aesManaged2 = aesManaged1)
            {
                using (ICryptoTransform encryptor = aesManaged2.CreateEncryptor(aesManaged2.Key, aesManaged2.IV))
                {
                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                        {
                            byte[] buffer = new byte[4]
                            {
                (byte) (data.Count &  byte.MaxValue),
                (byte) (data.Count >> 8 &  byte.MaxValue),
                (byte) (data.Count >> 16 &  byte.MaxValue),
                (byte) (data.Count >> 24 &  byte.MaxValue)
                            };
                            cryptoStream.Write(buffer, 0, 4);
                            cryptoStream.Write(data.Array, data.Offset, data.Count);
                        }
                        return memoryStream.ToArray();
                    }
                }
            }
        }

        public static byte[] AesDecrypt(ArraySegment<byte> data, byte[] key, byte[] iv)
        {
            if (data.Count < 4)
            {
                return null;
            }

            AesManaged aesManaged1 = new AesManaged();
            aesManaged1.Mode = CipherMode.CBC;
            aesManaged1.IV = iv;
            aesManaged1.Key = key;
            aesManaged1.Padding = PaddingMode.PKCS7;
            using (AesManaged aesManaged2 = aesManaged1)
            {
                using (ICryptoTransform decryptor = aesManaged2.CreateDecryptor(aesManaged2.Key, aesManaged2.IV))
                {
                    using (MemoryStream memoryStream1 = new MemoryStream(data.Array, data.Offset, data.Count))
                    {
                        byte[] buffer1 = new byte[data.Count];
                        int num = 0;
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream1, decryptor, CryptoStreamMode.Read))
                        {
                            num = cryptoStream.Read(buffer1, 0, buffer1.Length);
                        }

                        using (MemoryStream memoryStream2 = new MemoryStream(buffer1))
                        {
                            byte[] buffer2 = new byte[4];
                            memoryStream2.Read(buffer2, 0, 4);
                            int length = buffer2[0] | buffer2[1] << 8 | buffer2[2] << 16 | buffer2[3] << 24;
                            if (length + 4 > num)
                            {
                                return null;
                            }

                            byte[] numArray = new byte[length];
                            Array.Copy(buffer1, 4, numArray, 0, length);
                            return numArray;
                        }
                    }
                }
            }
        }

        public static int RijndaelEncryptInplace(ArraySegment<byte> data, byte[] key, byte[] iv)
        {
            RijndaelManaged rijndaelManaged1 = new RijndaelManaged();
            rijndaelManaged1.Mode = CipherMode.CBC;
            rijndaelManaged1.IV = iv;
            rijndaelManaged1.Key = key;
            rijndaelManaged1.Padding = PaddingMode.None;
            using (RijndaelManaged rijndaelManaged2 = rijndaelManaged1)
            {
                using (ICryptoTransform encryptor = rijndaelManaged2.CreateEncryptor(rijndaelManaged2.Key, rijndaelManaged2.IV))
                {
                    if ((uint)(data.Count % encryptor.InputBlockSize) > 0U)
                    {
                        throw new Exception(string.Format("Input data is not a multiple of block size, {0}/{1}", data.Count, encryptor.InputBlockSize));
                    }

                    encryptor.TransformBlock(data.Array, data.Offset, data.Count, data.Array, data.Offset);
                    return (data.Count + encryptor.InputBlockSize - 1) / encryptor.InputBlockSize * encryptor.InputBlockSize;
                }
            }
        }

        public static int RijndaelDecryptInplace(ArraySegment<byte> data, byte[] key, byte[] iv)
        {
            RijndaelManaged rijndaelManaged1 = new RijndaelManaged();
            rijndaelManaged1.Mode = CipherMode.CBC;
            rijndaelManaged1.IV = iv;
            rijndaelManaged1.Key = key;
            rijndaelManaged1.Padding = PaddingMode.None;
            using (RijndaelManaged rijndaelManaged2 = rijndaelManaged1)
            {
                using (ICryptoTransform decryptor = rijndaelManaged2.CreateDecryptor(rijndaelManaged2.Key, rijndaelManaged2.IV))
                {
                    if ((uint)(data.Count % decryptor.InputBlockSize) > 0U)
                    {
                        throw new Exception(string.Format("Input data is not a multiple of block size, {0}/{1}", data.Count, decryptor.InputBlockSize));
                    }

                    decryptor.TransformBlock(data.Array, data.Offset, data.Count, data.Array, data.Offset);
                    return (data.Count + decryptor.InputBlockSize - 1) / decryptor.InputBlockSize * decryptor.InputBlockSize;
                }
            }
        }

        public static string ExportRSAPrivateKey(RSAParameters parameters)
        {
            MemoryStream memoryStream1 = new MemoryStream();
            using (StreamWriter streamWriter = new StreamWriter(memoryStream1))
            {
                using (MemoryStream memoryStream2 = new MemoryStream())
                {
                    BinaryWriter stream1 = new BinaryWriter(memoryStream2);
                    stream1.Write((byte)48);
                    using (MemoryStream memoryStream3 = new MemoryStream())
                    {
                        BinaryWriter stream2 = new BinaryWriter(memoryStream3);
                        UASecurity.EncodeIntBigEndian(stream2, new byte[1]);
                        UASecurity.EncodeIntBigEndian(stream2, parameters.Modulus);
                        UASecurity.EncodeIntBigEndian(stream2, parameters.Exponent);
                        UASecurity.EncodeIntBigEndian(stream2, parameters.D);
                        UASecurity.EncodeIntBigEndian(stream2, parameters.P);
                        UASecurity.EncodeIntBigEndian(stream2, parameters.Q);
                        UASecurity.EncodeIntBigEndian(stream2, parameters.DP);
                        UASecurity.EncodeIntBigEndian(stream2, parameters.DQ);
                        UASecurity.EncodeIntBigEndian(stream2, parameters.InverseQ);
                        int length = (int)memoryStream3.Length;
                        UASecurity.EncodeLength(stream1, length);
                        stream1.Write(memoryStream3.ToArray(), 0, length);
                    }
                    char[] charArray = Convert.ToBase64String(memoryStream2.ToArray(), 0, (int)memoryStream2.Length).ToCharArray();
                    streamWriter.WriteLine("-----BEGIN RSA PRIVATE KEY-----");
                    for (int index = 0; index < charArray.Length; index += 64)
                    {
                        streamWriter.WriteLine(charArray, index, Math.Min(64, charArray.Length - index));
                    }

                    streamWriter.WriteLine("-----END RSA PRIVATE KEY-----");
                }
            }
            return Encoding.ASCII.GetString(memoryStream1.ToArray());
        }

        public static RSAParameters ImportRSAPrivateKey(string buf)
        {
            RSAParameters rsaParameters = new RSACryptoServiceProvider().ExportParameters(false);
            byte[] buffer = Convert.FromBase64String(string.Join(string.Empty, ((IEnumerable<string>)buf.Split(Environment.NewLine.ToArray<char>())).Where<string>(line => !line.Trim().StartsWith("-")).ToArray<string>()));
            MemoryStream memoryStream = new MemoryStream();
            memoryStream.Write(buffer, 0, buffer.Length);
            memoryStream.Seek(0L, SeekOrigin.Begin);
            using (BinaryReader stream = new BinaryReader(memoryStream))
            {
                if (stream.ReadByte() != 48)
                {
                    return rsaParameters;
                }

                UASecurity.DecodeLength(stream);
                byte[] numArray = UASecurity.DecodeIntBigEndian(stream);
                if (numArray.Length != 1 || numArray[0] > 0)
                {
                    return rsaParameters;
                }

                rsaParameters.Modulus = UASecurity.DecodeIntBigEndian(stream);
                rsaParameters.Exponent = UASecurity.DecodeIntBigEndian(stream);
                rsaParameters.D = UASecurity.DecodeIntBigEndian(stream);
                rsaParameters.P = UASecurity.DecodeIntBigEndian(stream);
                rsaParameters.Q = UASecurity.DecodeIntBigEndian(stream);
                rsaParameters.DP = UASecurity.DecodeIntBigEndian(stream);
                rsaParameters.DQ = UASecurity.DecodeIntBigEndian(stream);
                rsaParameters.InverseQ = UASecurity.DecodeIntBigEndian(stream);
            }
            return rsaParameters;
        }

        public static string ExportRSAPublicKey(RSAParameters parameters)
        {
            MemoryStream memoryStream1 = new MemoryStream();
            using (StreamWriter streamWriter = new StreamWriter(memoryStream1))
            {
                using (MemoryStream memoryStream2 = new MemoryStream())
                {
                    BinaryWriter stream1 = new BinaryWriter(memoryStream2);
                    stream1.Write((byte)48);
                    using (MemoryStream memoryStream3 = new MemoryStream())
                    {
                        BinaryWriter stream2 = new BinaryWriter(memoryStream3);
                        UASecurity.EncodeIntBigEndian(stream2, new byte[1]);
                        UASecurity.EncodeIntBigEndian(stream2, parameters.Modulus);
                        UASecurity.EncodeIntBigEndian(stream2, parameters.Exponent);
                        UASecurity.EncodeIntBigEndian(stream2, parameters.Exponent);
                        UASecurity.EncodeIntBigEndian(stream2, parameters.Exponent);
                        UASecurity.EncodeIntBigEndian(stream2, parameters.Exponent);
                        UASecurity.EncodeIntBigEndian(stream2, parameters.Exponent);
                        UASecurity.EncodeIntBigEndian(stream2, parameters.Exponent);
                        UASecurity.EncodeIntBigEndian(stream2, parameters.Exponent);
                        int length = (int)memoryStream3.Length;
                        UASecurity.EncodeLength(stream1, length);
                        stream1.Write(memoryStream3.ToArray(), 0, length);
                    }
                    char[] charArray = Convert.ToBase64String(memoryStream2.ToArray(), 0, (int)memoryStream2.Length).ToCharArray();
                    streamWriter.WriteLine("-----BEGIN RSA PUBLIC KEY-----");
                    for (int index = 0; index < charArray.Length; index += 64)
                    {
                        streamWriter.WriteLine(charArray, index, Math.Min(64, charArray.Length - index));
                    }

                    streamWriter.WriteLine("-----END RSA PUBLIC KEY-----");
                }
            }
            return Encoding.ASCII.GetString(memoryStream1.ToArray());
        }

        public static RSAParameters ImportRSAPublicKey(string buf)
        {
            RSAParameters rsaParameters = new RSACryptoServiceProvider().ExportParameters(false);
            byte[] buffer = Convert.FromBase64String(string.Join(string.Empty, ((IEnumerable<string>)buf.Split(Environment.NewLine.ToArray<char>())).Where<string>(line => !line.Trim().StartsWith("-")).ToArray<string>()));
            MemoryStream memoryStream = new MemoryStream();
            memoryStream.Write(buffer, 0, buffer.Length);
            memoryStream.Seek(0L, SeekOrigin.Begin);
            using (BinaryReader stream = new BinaryReader(memoryStream))
            {
                if (stream.ReadByte() != 48)
                {
                    return rsaParameters;
                }

                UASecurity.DecodeLength(stream);
                byte[] numArray = UASecurity.DecodeIntBigEndian(stream);
                if (numArray.Length != 1 || numArray[0] > 0)
                {
                    return rsaParameters;
                }

                rsaParameters.Modulus = UASecurity.DecodeIntBigEndian(stream);
                rsaParameters.Exponent = UASecurity.DecodeIntBigEndian(stream);
                UASecurity.DecodeIntBigEndian(stream);
                UASecurity.DecodeIntBigEndian(stream);
                UASecurity.DecodeIntBigEndian(stream);
                UASecurity.DecodeIntBigEndian(stream);
                UASecurity.DecodeIntBigEndian(stream);
                UASecurity.DecodeIntBigEndian(stream);
            }
            return rsaParameters;
        }

        private static int DecodeLength(BinaryReader stream)
        {
            int num1 = stream.ReadByte();
            if (num1 < 128)
            {
                return num1;
            }

            int num2 = num1 - 128;
            int num3 = 0;
            for (int index = num2 - 1; index >= 0; --index)
            {
                num3 |= stream.ReadByte() << 8 * index;
            }

            return num3;
        }

        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be non-negative");
            }

            if (length < 128)
            {
                stream.Write((byte)length);
            }
            else
            {
                int num = 0;
                for (int index = length; index > 0; index >>= 8)
                {
                    ++num;
                }

                stream.Write((byte)(num | 128));
                for (int index = num - 1; index >= 0; --index)
                {
                    stream.Write((byte)(length >> 8 * index & byte.MaxValue));
                }
            }
        }

        private static byte[] DecodeIntBigEndian(BinaryReader stream)
        {
            if (stream.ReadByte() != 2)
            {
                return null;
            }

            int length = UASecurity.DecodeLength(stream);
            if (length < 0)
            {
                return null;
            }

            byte[] numArray = new byte[length];
            for (int index = 0; index < length; ++index)
            {
                numArray[index] = stream.ReadByte();
            }

            return numArray;
        }

        private static void EncodeIntBigEndian(BinaryWriter stream, byte[] value)
        {
            stream.Write((byte)2);
            UASecurity.EncodeLength(stream, value.Length);
            for (int index = 0; index < value.Length; ++index)
            {
                stream.Write(value[index]);
            }
        }

        public static int GetPlainBlockSize(X509Certificate2 cert, RSAEncryptionPadding useOaep)
        {
            if (!(cert.PublicKey.Key is RSA key))
            {
                throw new Exception("Could not create RSA");
            }

            return key.KeySize / 8 - (useOaep == RSAEncryptionPadding.OaepSHA1 ? 42 : 11);
        }

        public static int GetCipherTextBlockSize(X509Certificate2 cert)
        {
            if (!(cert.PublicKey.Key is RSA key))
            {
                throw new Exception("Could not create RSA");
            }

            return key.KeySize / 8;
        }

        public static int GetSignatureLength(X509Certificate2 cert)
        {
            if (!(cert.PublicKey.Key is RSA key))
            {
                throw new Exception("Could not create RSA");
            }

            return key.KeySize / 8;
        }

        public static int GetSignatureLength(X509Certificate2 cert, SecurityPolicy policy)
        {
            return UASecurity.GetSignatureLength(cert);
        }

        public static byte[] RsaPkcs15Sha_Sign(
          ArraySegment<byte> data,
          RSA privProvider,
          SecurityPolicy policy)
        {
            byte[] hash = UASecurity.HashAlgorithmForSecurityPolicy(policy).ComputeHash(data.Array, data.Offset, data.Count);
            return privProvider.SignHash(hash, UASecurity.HashStrForSecurityPolicy(policy), RSASignaturePadding.Pkcs1);
        }

        private static HashAlgorithmName HashStrForSecurityPolicy(SecurityPolicy policy)
        {
            return policy == SecurityPolicy.Basic256Sha256 ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA1;
        }

        private static System.Security.Cryptography.HashAlgorithm HashAlgorithmForSecurityPolicy(
          SecurityPolicy policy)
        {
            return policy == SecurityPolicy.Basic256Sha256 ? new SHA256Managed() : (System.Security.Cryptography.HashAlgorithm)new SHA1Managed();
        }

        public static bool RsaPkcs15Sha_VerifySigned(
          ArraySegment<byte> data,
          byte[] signature,
          X509Certificate2 cert,
          SecurityPolicy policy)
        {
            return (cert.PublicKey.Key as RSA).VerifyHash(UASecurity.HashAlgorithmForSecurityPolicy(policy).ComputeHash(data.Array, data.Offset, data.Count), signature, UASecurity.HashStrForSecurityPolicy(policy), RSASignaturePadding.Pkcs1);
        }

        public static byte[] RsaPkcs15Sha_Encrypt(
          ArraySegment<byte> data,
          X509Certificate2 cert,
          SecurityPolicy policy)
        {
            RSA key = cert.PublicKey.Key as RSA;
            int plainBlockSize = UASecurity.GetPlainBlockSize(cert, UASecurity.UseOaepForSecurityPolicy(policy));
            if ((uint)(data.Count % plainBlockSize) > 0U)
            {
                throw new Exception(string.Format("Input data is not a multiple of block size, {0}/{1}", data.Count, plainBlockSize));
            }

            byte[] data1 = new byte[plainBlockSize];
            MemoryStream memoryStream = new MemoryStream();
            for (int index = 0; index < data.Count; index += plainBlockSize)
            {
                Array.Copy(data.Array, data.Offset + index, data1, 0, data1.Length);
                byte[] buffer = key.Encrypt(data1, UASecurity.UseOaepForSecurityPolicy(policy));
                memoryStream.Write(buffer, 0, buffer.Length);
            }
            memoryStream.Close();
            return memoryStream.ToArray();
        }

        public static byte[] RsaPkcs15Sha_Decrypt(
          ArraySegment<byte> data,
          X509Certificate2 cert,
          RSA rsaPrivate,
          SecurityPolicy policy)
        {
            int cipherTextBlockSize = UASecurity.GetCipherTextBlockSize(cert);
            byte[] buffer1 = new byte[data.Count / cipherTextBlockSize * UASecurity.GetPlainBlockSize(cert, UASecurity.UseOaepForSecurityPolicy(policy))];
            int length = rsaPrivate.KeySize / 8;
            UASecurity.GetPlainBlockSize(cert, UASecurity.UseOaepForSecurityPolicy(policy));
            if ((uint)(data.Count % length) > 0U)
            {
                throw new Exception(string.Format("Input data is not a multiple of block size, {0}/{1}", data.Count, length));
            }

            MemoryStream memoryStream = new MemoryStream(buffer1);
            byte[] data1 = new byte[length];
            for (int offset = data.Offset; offset < data.Offset + data.Count; offset += length)
            {
                Array.Copy(data.Array, offset, data1, 0, data1.Length);
                byte[] buffer2 = rsaPrivate.Decrypt(data1, UASecurity.UseOaepForSecurityPolicy(policy));
                memoryStream.Write(buffer2, 0, buffer2.Length);
            }
            memoryStream.Close();
            return buffer1;
        }

        public static bool VerifyCertificate(X509Certificate2 senderCert)
        {
            return senderCert != null;
        }

        public static byte[] SHACalculate(byte[] data, SecurityPolicy policy)
        {
            using (System.Security.Cryptography.HashAlgorithm hashAlgorithm = UASecurity.HashAlgorithmForSecurityPolicy(policy))
            {
                return hashAlgorithm.ComputeHash(data);
            }
        }

        public static byte[] SymmetricSign(byte[] key, ArraySegment<byte> data, SecurityPolicy policy)
        {
            using (MemoryStream memoryStream = new MemoryStream(data.Array, data.Offset, data.Count))
            {
                return UASecurity.HMACForSecurityPolicy(key, policy).ComputeHash(memoryStream);
            }
        }

        private static HMAC HMACForSecurityPolicy(byte[] key, SecurityPolicy policy)
        {
            return policy == SecurityPolicy.Basic256Sha256 ? new HMACSHA256(key) : (HMAC)new HMACSHA1(key);
        }

        public static byte[] SHACalculate(ArraySegment<byte> data, SecurityPolicy policy)
        {
            using (System.Security.Cryptography.HashAlgorithm hashAlgorithm = UASecurity.HashAlgorithmForSecurityPolicy(policy))
            {
                return hashAlgorithm.ComputeHash(data.Array, data.Offset, data.Count);
            }
        }

        public static bool SHAVerify(byte[] data, byte[] hash, SecurityPolicy policy)
        {
            byte[] numArray = UASecurity.SHACalculate(data, policy);
            if (numArray.Length != hash.Length)
            {
                return false;
            }

            for (int index = 0; index < numArray.Length; ++index)
            {
                if (hash[index] != numArray[index])
                {
                    return false;
                }
            }
            return true;
        }

        public static byte[] PSHA(byte[] secret, byte[] seed, int length, SecurityPolicy policy)
        {
            HMAC hmac = UASecurity.HMACForSecurityPolicy(secret, policy);
            int val1 = UASecurity.SignatureSizeForSecurityPolicy(policy);
            byte[] hash1 = hmac.ComputeHash(seed);
            byte[] buffer = new byte[val1 + seed.Length];
            Array.Copy(hash1, buffer, hash1.Length);
            Array.Copy(seed, 0, buffer, hash1.Length, seed.Length);
            byte[] numArray = new byte[length];
            int destinationIndex = 0;
            while (destinationIndex < length)
            {
                byte[] hash2 = hmac.ComputeHash(buffer);
                int length1 = Math.Min(val1, length - destinationIndex);
                Array.Copy(hash2, 0, numArray, destinationIndex, length1);
                destinationIndex += length1;
                hash1 = hmac.ComputeHash(hash1);
                Array.Copy(hash1, buffer, hash1.Length);
            }
            return numArray;
        }

        private static int SignatureSizeForSecurityPolicy(SecurityPolicy policy)
        {
            return policy == SecurityPolicy.Basic256Sha256 ? 32 : 20;
        }

        public static StatusCode UnsecureSymmetric(
          MemoryBuffer recvBuf,
          uint tokenID,
          uint? prevTokenID,
          int messageEncodedBlockStart,
          SLChannel.Keyset localKeyset,
          SLChannel.Keyset[] remoteKeysets,
          SecurityPolicy policy,
          MessageSecurityMode securityMode,
          out int decrSize)
        {
            decrSize = -1;
            int position = recvBuf.Position;
            if (!recvBuf.Decode(out byte v1) || !recvBuf.Decode(out uint v2) || (!recvBuf.Decode(out uint _) || !recvBuf.Decode(out uint v3)))
            {
                return StatusCode.BadDecodingError;
            }

            int index1;
            if ((int)tokenID == (int)v3)
            {
                index1 = 0;
            }
            else
            {
                if (!prevTokenID.HasValue || (int)prevTokenID.Value != (int)v3)
                {
                    return StatusCode.BadSecureChannelTokenUnknown;
                }

                index1 = 1;
            }
            if (securityMode == MessageSecurityMode.SignAndEncrypt)
            {
                try
                {
                    decrSize = UASecurity.RijndaelDecryptInplace(new ArraySegment<byte>(recvBuf.Buffer, messageEncodedBlockStart, (int)v2 - messageEncodedBlockStart), remoteKeysets[index1].SymEncKey, remoteKeysets[index1].SymIV) + messageEncodedBlockStart;
                }
                catch
                {
                    return StatusCode.BadSecurityChecksFailed;
                }
            }
            else
            {
                decrSize = (int)v2;
            }

            if (securityMode >= MessageSecurityMode.Sign)
            {
                try
                {
                    int count = UASecurity.SignatureSizeForSecurityPolicy(policy);
                    ArraySegment<byte> data = new ArraySegment<byte>(recvBuf.Buffer, 0, (int)v2 - count);
                    byte[] array = new ArraySegment<byte>(recvBuf.Buffer, (int)v2 - count, count).ToArray();
                    byte[] numArray = UASecurity.SymmetricSign(remoteKeysets[index1].SymSignKey, data, policy);
                    if (array.Length != numArray.Length)
                    {
                        return StatusCode.BadSecurityChecksFailed;
                    }

                    for (int index2 = 0; index2 < array.Length; ++index2)
                    {
                        if (array[index2] != numArray[index2])
                        {
                            return StatusCode.BadSecurityChecksFailed;
                        }
                    }
                    byte num = securityMode == MessageSecurityMode.SignAndEncrypt ? (byte)(recvBuf.Buffer[v2 - count - 1L] + 1U) : (byte)0;
                    if (decrSize > 0)
                    {
                        decrSize -= count;
                        decrSize -= num;
                        if (decrSize <= 0)
                        {
                            return StatusCode.BadSecurityChecksFailed;
                        }
                    }
                }
                catch
                {
                    return StatusCode.BadSecurityChecksFailed;
                }
            }
            if (!recvBuf.Decode(out uint _) || !recvBuf.Decode(out uint _))
            {
                return StatusCode.BadDecodingError;
            }

            recvBuf.Position = position;
            return StatusCode.Good;
        }

        public static StatusCode SecureSymmetric(
          MemoryBuffer respBuf,
          int messageEncodedBlockStart,
          SLChannel.Keyset localKeyset,
          SLChannel.Keyset remoteKeyset,
          SecurityPolicy policy,
          MessageSecurityMode securityMode)
        {
            if (securityMode == MessageSecurityMode.None)
            {
                return StatusCode.Good;
            }

            int num1 = UASecurity.SignatureSizeForSecurityPolicy(policy);
            if (securityMode >= MessageSecurityMode.SignAndEncrypt)
            {
                int symmetricPaddingSize = UASecurity.CalculateSymmetricPaddingSize(localKeyset.SymEncKey.Length, num1 + respBuf.Position - messageEncodedBlockStart);
                byte num2 = (byte)(symmetricPaddingSize - 1 & byte.MaxValue);
                byte[] Add = new byte[symmetricPaddingSize];
                for (int index = 0; index < symmetricPaddingSize; ++index)
                {
                    Add[index] = num2;
                }

                respBuf.Append(Add);
            }
            int num3 = respBuf.Position + num1;
            if (securityMode >= MessageSecurityMode.SignAndEncrypt)
            {
                num3 = messageEncodedBlockStart + UASecurity.CalculateSymmetricEncryptedSize(localKeyset.SymEncKey.Length, num3 - messageEncodedBlockStart);
            }

            if (num3 >= respBuf.Capacity)
            {
                return StatusCode.BadEncodingLimitsExceeded;
            }

            UASecurity.MarkUAMessageSize(respBuf, (uint)num3);
            byte[] Add1 = UASecurity.SymmetricSign(localKeyset.SymSignKey, new ArraySegment<byte>(respBuf.Buffer, 0, respBuf.Position), policy);
            respBuf.Append(Add1);
            if (num3 != respBuf.Position)
            {
                throw new Exception();
            }

            if (securityMode >= MessageSecurityMode.SignAndEncrypt)
            {
                UASecurity.RijndaelEncryptInplace(new ArraySegment<byte>(respBuf.Buffer, messageEncodedBlockStart, num3 - messageEncodedBlockStart), localKeyset.SymEncKey, localKeyset.SymIV);
            }

            return StatusCode.Good;
        }

        private static void MarkUAMessageSize(MemoryBuffer buf, uint position)
        {
            int position1 = buf.Position;
            buf.Position = 4;
            buf.Encode(position);
            buf.Position = position1;
        }

        public enum HashAlgorithm
        {
            None,
            SHA_160,
            SHA_224,
            SHA_256,
            SHA_384,
            SHA_512,
        }

        public enum PaddingAlgorithm
        {
            None,
            PKCS1,
            PKCS1_OAEP,
        }
    }
}
