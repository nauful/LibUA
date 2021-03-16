using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using LibUA.Core;

namespace LibUA
{
	public static class UASecurity
	{
		public const int Sha1Size = 20;
		public const int Sha256Size = 32;
		public const int RsaPkcs1PaddingSize = 11;
		public const int RsaPkcs1OaepPaddingSize = 42;
		public const int ActivationNonceSize = 32;

		public enum HashAlgorithm : int
		{
			None = 0,
			SHA_160,
			SHA_224,
			SHA_256,
			SHA_384,
			SHA_512,
		}

		public enum PaddingAlgorithm : int
		{
			None = 0,
			PKCS1,
			PKCS1_OAEP
		}

		public static PaddingAlgorithm PaddingMethodForSecurityPolicy(SecurityPolicy policy)
		{
			switch (policy)
			{
				case SecurityPolicy.Basic256: return PaddingAlgorithm.PKCS1_OAEP;
				case SecurityPolicy.Basic256Sha256: return PaddingAlgorithm.PKCS1_OAEP;
				case SecurityPolicy.Basic128Rsa15: return PaddingAlgorithm.PKCS1;
			}

			throw new Exception();
		}

		public static int SymmetricKeySizeForSecurityPolicy(SecurityPolicy policy, int clientNonceLength = -1)
		{
			switch (policy)
			{
				case SecurityPolicy.Basic256: return 32;
				case SecurityPolicy.Basic256Sha256: return clientNonceLength < 1 ? 32 : clientNonceLength;
				case SecurityPolicy.Basic128Rsa15: return 16;
			}

			throw new Exception();
		}


		public static int SymmetricBlockSizeForSecurityPolicy(SecurityPolicy policy)
		{
			return 16;
		}

		public static int SymmetricSignatureKeySizeForSecurityPolicy(SecurityPolicy policy)
		{
			switch (policy)
			{
				case SecurityPolicy.Basic256: return 24;
				case SecurityPolicy.Basic256Sha256: return 32;
				case SecurityPolicy.Basic128Rsa15: return SymmetricKeySizeForSecurityPolicy(policy);
				default:
					break;
			}

			throw new Exception();
		}

		public static RSAEncryptionPadding UseOaepForSecurityPolicy(SecurityPolicy policy)
		{
			switch (policy)
			{
				case SecurityPolicy.Basic256:
				case SecurityPolicy.Basic256Sha256:
					return RSAEncryptionPadding.OaepSHA1;
			}

			return RSAEncryptionPadding.Pkcs1;
		}

		public static int CalculatePublicKeyLength(X509Certificate2 cert)
		{
			RSA rsa = cert.PublicKey.Key as RSA;
			if (rsa == null)
			{
				throw new Exception("Could not create RSA");
			}

			return rsa.KeySize;
		}

		public static int CalculatePaddingSize(X509Certificate2 cert, SecurityPolicy policy, int position, int sigSize)
		{
			int plainBlockSize = GetPlainBlockSize(cert, UseOaepForSecurityPolicy(policy));

			int pad = plainBlockSize;
			pad -= (position + sigSize) % plainBlockSize;

			if (pad < 0)
			{
				throw new Exception();
			}

			return pad;
		}

		public static int CalculateSymmetricEncryptedSize(int keySize, int position)
		{
			int numBlocks = (position + keySize - 1) / keySize;
			return numBlocks * keySize;
		}

		public static int CalculateSymmetricPaddingSize(int keySize, int position)
		{
			if (keySize > 256)
			{
				throw new Exception("TODO: Handle keys above 2048 bits");
			}

			int pad = position + keySize;

			// Size byte
			pad++;
			if (keySize > 0)
			{
				pad -= pad % keySize;
			}
			pad -= position;

			if (pad < 0 || pad > 256)
			{
				throw new Exception();
			}

			return pad;
		}

		public static int CalculateSignatureSize(RSA key)
		{
			return key.KeySize / 8;
		}

		public static int CalculateSignatureSize(X509Certificate2 cert)
		{
			return CalculateSignatureSize(cert.PublicKey.Key as RSA);
		}

		public static int CalculateEncryptedSize(X509Certificate2 cert, int messageSize, PaddingAlgorithm paddingAlgorithm)
		{
			RSA rsa = cert.PublicKey.Key as RSA;
			if (rsa == null)
			{
				throw new Exception("Could not create RSA");
			}

			int pad = PaddingSizeForMethod(paddingAlgorithm);
			int keySize = CalculatePublicKeyLength(cert) / 8;

			if (keySize < pad)
			{
				throw new Exception();
			}

			int blockSize = keySize - pad;
			int numBlocks = (messageSize + blockSize - 1) / blockSize;

			return numBlocks * keySize;
		}

		public static int PaddingSizeForMethod(PaddingAlgorithm paddingMethod)
		{
			switch (paddingMethod)
			{
				case PaddingAlgorithm.None: return 0;
				case PaddingAlgorithm.PKCS1: return RsaPkcs1PaddingSize;
				case PaddingAlgorithm.PKCS1_OAEP: return RsaPkcs1OaepPaddingSize;
			}

			throw new Exception();
		}

		public static string ExportPEM(X509Certificate cert)
		{
			StringBuilder sb = new StringBuilder();

			sb.AppendLine("-----BEGIN CERTIFICATE-----");
			sb.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
			sb.AppendLine("-----END CERTIFICATE-----");

			return sb.ToString();
		}

		public static byte[] GenerateRandomBits(int numBits)
		{
			return GenerateRandomBytes((numBits + 7) / 8);
		}

		public static byte[] GenerateRandomBytes(int numBytes)
		{
			//var arr = Enumerable.Range(1, numBytes).Select(i => (byte)(i & 0xFF)).ToArray();
			//return arr;

			RandomNumberGenerator rng = new RNGCryptoServiceProvider();

			var res = new byte[numBytes];
			rng.GetBytes(res);

			return res;
		}

		public static byte[] AesEncrypt(ArraySegment<byte> data, byte[] key, byte[] iv)
		{
			using (var aes = new AesManaged()
			{
				Mode = CipherMode.CBC,
				IV = iv, // new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
				Key = key,
				Padding = PaddingMode.PKCS7
			})
			{
				using (var crypt = aes.CreateEncryptor(aes.Key, aes.IV))
				{
					using (var ms = new MemoryStream())
					{
						using (var cs = new CryptoStream(ms, crypt, CryptoStreamMode.Write))
						{
							var lengthBytes = new byte[]
							{
								(byte)(data.Count & 0xFF),
								(byte)((data.Count >> 8) & 0xFF),
								(byte)((data.Count >> 16) & 0xFF),
								(byte)((data.Count >> 24) & 0xFF),
							};

							cs.Write(lengthBytes, 0, 4);
							cs.Write(data.Array, data.Offset, data.Count);
						}

						return ms.ToArray();
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

			using (var aes = new AesManaged()
			{
				Mode = CipherMode.CBC,
				IV = iv, // new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
				Key = key,
				Padding = PaddingMode.PKCS7
			})
			{
				using (var crypt = aes.CreateDecryptor(aes.Key, aes.IV))
				{
					using (var ms = new MemoryStream(data.Array, data.Offset, data.Count))
					{
						byte[] plain = new byte[data.Count];
						int plainLength = 0;

						using (var cs = new CryptoStream(ms, crypt, CryptoStreamMode.Read))
						{
							plainLength = cs.Read(plain, 0, plain.Length);
						}

						using (var msRead = new MemoryStream(plain))
						{
							var lengthBytes = new byte[4];
							msRead.Read(lengthBytes, 0, 4);
							int length = lengthBytes[0] | (lengthBytes[1] << 8) | (lengthBytes[2] << 16) | (lengthBytes[3] << 24);

							if (length + 4 > plainLength)
							{
								return null;
							}

							var res = new byte[length];
							Array.Copy(plain, 4, res, 0, length);
							return res;
						}
					}
				}
			}
		}

		public static int RijndaelEncryptInplace(ArraySegment<byte> data, byte[] key, byte[] iv)
		{
			using (var rijn = new RijndaelManaged()
			{
				Mode = CipherMode.CBC,
				IV = iv,
				Key = key,
				Padding = PaddingMode.None
			})
			{
				using (var crypt = rijn.CreateEncryptor(rijn.Key, rijn.IV))
				{
					if (data.Count % crypt.InputBlockSize != 0)
					{
						throw new Exception(string.Format("Input data is not a multiple of block size, {0}/{1}", data.Count, crypt.InputBlockSize));
					}

					crypt.TransformBlock(data.Array, data.Offset, data.Count, data.Array, data.Offset);

					return ((data.Count + crypt.InputBlockSize - 1) / crypt.InputBlockSize) * crypt.InputBlockSize;
				}
			}
		}

		public static int RijndaelDecryptInplace(ArraySegment<byte> data, byte[] key, byte[] iv)
		{
			using (var rijn = new RijndaelManaged()
			{
				Mode = CipherMode.CBC,
				IV = iv,
				Key = key,
				Padding = PaddingMode.None
			})
			{
				using (var crypt = rijn.CreateDecryptor(rijn.Key, rijn.IV))
				{
					if (data.Count % crypt.InputBlockSize != 0)
					{
						throw new Exception(string.Format("Input data is not a multiple of block size, {0}/{1}", data.Count, crypt.InputBlockSize));
					}

					crypt.TransformBlock(data.Array, data.Offset, data.Count, data.Array, data.Offset);

					int numBlocks = (data.Count + crypt.InputBlockSize - 1) / crypt.InputBlockSize;
					return numBlocks * crypt.InputBlockSize;
				}
			}
		}

		public static string ExportRSAPrivateKey(RSAParameters parameters)
		{
			MemoryStream ms = new MemoryStream();

			using (var outputStream = new StreamWriter(ms))
			{
				using (var stream = new MemoryStream())
				{
					var writer = new BinaryWriter(stream);
					writer.Write((byte)0x30); // Sequence
					using (var innerStream = new MemoryStream())
					{
						var innerWriter = new BinaryWriter(innerStream);
						EncodeIntBigEndian(innerWriter, new byte[] { 0x00 }); // Version
						EncodeIntBigEndian(innerWriter, parameters.Modulus);
						EncodeIntBigEndian(innerWriter, parameters.Exponent);

						EncodeIntBigEndian(innerWriter, parameters.D);
						EncodeIntBigEndian(innerWriter, parameters.P);
						EncodeIntBigEndian(innerWriter, parameters.Q);
						EncodeIntBigEndian(innerWriter, parameters.DP);
						EncodeIntBigEndian(innerWriter, parameters.DQ);
						EncodeIntBigEndian(innerWriter, parameters.InverseQ);

						var length = (int)innerStream.Length;
						EncodeLength(writer, length);
						writer.Write(innerStream.ToArray(), 0, length);
					}

					var base64 = Convert.ToBase64String(stream.ToArray(), 0, (int)stream.Length).ToCharArray();

					outputStream.WriteLine("-----BEGIN RSA PRIVATE KEY-----");
					for (int i = 0; i < base64.Length; i += 64)
					{
						outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
					}

					outputStream.WriteLine("-----END RSA PRIVATE KEY-----");
				}
			}

			return System.Text.Encoding.ASCII.GetString(ms.ToArray());
		}

		public static RSAParameters ImportRSAPrivateKey(string buf)
		{
			var rsa = new RSACryptoServiceProvider();
			var parameters = rsa.ExportParameters(false);

			var b64line = string.Join(string.Empty, buf
				.Split(Environment.NewLine.ToArray())
				.Where(line => !line.Trim().StartsWith("-"))
				.ToArray());

			var byteArr = Convert.FromBase64String(b64line);
			var ms = new MemoryStream();
			ms.Write(byteArr, 0, byteArr.Length);
			ms.Seek(0, SeekOrigin.Begin);
			using (var inputStream = new BinaryReader(ms))
			{
				if (inputStream.ReadByte() != 0x30)
				{
					return parameters;
				}

				int length = DecodeLength(inputStream);
				byte[] version = DecodeIntBigEndian(inputStream);

				if (version.Length != 1 || version[0] != 0)
				{
					return parameters;
				}

				parameters.Modulus = DecodeIntBigEndian(inputStream);
				parameters.Exponent = DecodeIntBigEndian(inputStream);

				parameters.D = DecodeIntBigEndian(inputStream);
				parameters.P = DecodeIntBigEndian(inputStream);
				parameters.Q = DecodeIntBigEndian(inputStream);
				parameters.DP = DecodeIntBigEndian(inputStream);
				parameters.DQ = DecodeIntBigEndian(inputStream);
				parameters.InverseQ = DecodeIntBigEndian(inputStream);
			}

			return parameters;
		}

		public static string ExportRSAPublicKey(RSAParameters parameters)
		{
			MemoryStream ms = new MemoryStream();

			using (var outputStream = new StreamWriter(ms))
			{
				using (var stream = new MemoryStream())
				{
					var writer = new BinaryWriter(stream);
					writer.Write((byte)0x30); // Sequence
					using (var innerStream = new MemoryStream())
					{
						var innerWriter = new BinaryWriter(innerStream);
						EncodeIntBigEndian(innerWriter, new byte[] { 0x00 }); // Version
						EncodeIntBigEndian(innerWriter, parameters.Modulus);
						EncodeIntBigEndian(innerWriter, parameters.Exponent);

						EncodeIntBigEndian(innerWriter, parameters.Exponent);
						EncodeIntBigEndian(innerWriter, parameters.Exponent);
						EncodeIntBigEndian(innerWriter, parameters.Exponent);
						EncodeIntBigEndian(innerWriter, parameters.Exponent);
						EncodeIntBigEndian(innerWriter, parameters.Exponent);
						EncodeIntBigEndian(innerWriter, parameters.Exponent);

						var length = (int)innerStream.Length;
						EncodeLength(writer, length);
						writer.Write(innerStream.ToArray(), 0, length);
					}

					var base64 = Convert.ToBase64String(stream.ToArray(), 0, (int)stream.Length).ToCharArray();

					outputStream.WriteLine("-----BEGIN RSA PUBLIC KEY-----");
					for (int i = 0; i < base64.Length; i += 64)
					{
						outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
					}

					outputStream.WriteLine("-----END RSA PUBLIC KEY-----");
				}
			}

			return System.Text.Encoding.ASCII.GetString(ms.ToArray());
		}

		public static RSAParameters ImportRSAPublicKey(string buf)
		{
			var rsa = new RSACryptoServiceProvider();
			var parameters = rsa.ExportParameters(false);

			var b64line = string.Join(string.Empty, buf
				.Split(Environment.NewLine.ToArray())
				.Where(line => !line.Trim().StartsWith("-"))
				.ToArray());

			var byteArr = Convert.FromBase64String(b64line);
			var ms = new MemoryStream();
			ms.Write(byteArr, 0, byteArr.Length);
			ms.Seek(0, SeekOrigin.Begin);
			using (var inputStream = new BinaryReader(ms))
			{
				if (inputStream.ReadByte() != 0x30)
				{
					return parameters;
				}

				int length = DecodeLength(inputStream);
				byte[] version = DecodeIntBigEndian(inputStream);

				if (version.Length != 1 || version[0] != 0)
				{
					return parameters;
				}

				parameters.Modulus = DecodeIntBigEndian(inputStream);
				parameters.Exponent = DecodeIntBigEndian(inputStream);

				DecodeIntBigEndian(inputStream);
				DecodeIntBigEndian(inputStream);
				DecodeIntBigEndian(inputStream);
				DecodeIntBigEndian(inputStream);
				DecodeIntBigEndian(inputStream);
				DecodeIntBigEndian(inputStream);
			}

			return parameters;
		}

		private static int DecodeLength(BinaryReader stream)
		{
			int length = stream.ReadByte();
			if (length < 0x80)
			{
				return length;
			}

			int bytesRequired = length - 0x80;

			length = 0;
			for (int i = bytesRequired - 1; i >= 0; i--)
			{
				length |= (int)(stream.ReadByte() << (8 * i));
			}

			return length;
		}

		private static void EncodeLength(BinaryWriter stream, int length)
		{
			if (length < 0)
			{
				throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
			}

			if (length < 0x80)
			{
				stream.Write((byte)length);
			}
			else
			{
				var bytesRequired = 0;
				for (int temp = length; temp > 0; temp >>= 8)
				{
					bytesRequired++;
				}

				stream.Write((byte)(bytesRequired | 0x80));
				for (int i = bytesRequired - 1; i >= 0; i--)
				{
					stream.Write((byte)(length >> (8 * i) & 0xff));
				}
			}
		}

		private static byte[] DecodeIntBigEndian(BinaryReader stream)
		{
			if (stream.ReadByte() != 0x02)
			{
				return null;
			}

			int length = DecodeLength(stream);
			if (length < 0)
			{
				return null;
			}

			var arr = new byte[length];
			for (int i = 0; i < length; i++)
			{
				arr[i] = stream.ReadByte();
			}

			return arr;
		}

		private static void EncodeIntBigEndian(BinaryWriter stream, byte[] value)
		{
			stream.Write((byte)0x02); // Integer
			EncodeLength(stream, value.Length);

			for (int i = 0; i < value.Length; i++)
			{
				stream.Write(value[i]);
			}
		}

		public static int GetPlainBlockSize(X509Certificate2 cert, RSAEncryptionPadding useOaep)
		{
			var rsa = cert.PublicKey.Key as RSA;
			if (rsa == null)
			{
				throw new Exception("Could not create RSA");
			}

			return (rsa.KeySize / 8) - (useOaep == RSAEncryptionPadding.OaepSHA1 ? RsaPkcs1OaepPaddingSize : RsaPkcs1PaddingSize);
		}

		public static int GetCipherTextBlockSize(X509Certificate2 cert)
		{
			var rsa = cert.PublicKey.Key as RSA;
			if (rsa == null)
			{
				throw new Exception("Could not create RSA");
			}

			return rsa.KeySize / 8;
		}

		public static int GetSignatureLength(X509Certificate2 cert)
		{
			var rsa = cert.PublicKey.Key as RSA;
			if (rsa == null)
			{
				throw new Exception("Could not create RSA");
			}

			return rsa.KeySize / 8;
		}

		public static int GetSignatureLength(X509Certificate2 cert, SecurityPolicy policy)
		{
			return GetSignatureLength(cert);
		}

		public static byte[] RsaPkcs15Sha_Sign(ArraySegment<byte> data, RSA privProvider,
			SecurityPolicy policy)
		{
			var hash = HashAlgorithmForSecurityPolicy(policy);
			var digest = hash.ComputeHash(data.Array, data.Offset, data.Count);

			byte[] signature = privProvider.SignHash(digest, HashStrForSecurityPolicy(policy), RSASignaturePadding.Pkcs1);
			return signature;
		}

		private static HashAlgorithmName HashStrForSecurityPolicy(SecurityPolicy policy)
		{
			return policy == SecurityPolicy.Basic256Sha256 ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA1;
		}

		private static System.Security.Cryptography.HashAlgorithm HashAlgorithmForSecurityPolicy(SecurityPolicy policy)
		{
			return policy == SecurityPolicy.Basic256Sha256 ?
				new SHA256Managed() :
				(System.Security.Cryptography.HashAlgorithm)new SHA1Managed();
		}

		public static bool RsaPkcs15Sha_VerifySigned(ArraySegment<byte> data, byte[] signature, X509Certificate2 cert,
			SecurityPolicy policy)
		{
			var rsa = cert.PublicKey.Key as RSA;

			var hash = HashAlgorithmForSecurityPolicy(policy);
			var digest = hash.ComputeHash(data.Array, data.Offset, data.Count);

			bool match = rsa.VerifyHash(digest, signature, HashStrForSecurityPolicy(policy), RSASignaturePadding.Pkcs1);
			return match;
		}

		public static byte[] RsaPkcs15Sha_Encrypt(ArraySegment<byte> data, X509Certificate2 cert, SecurityPolicy policy)
		{
			var rsa = cert.PublicKey.Key as RSA;
			int inputBlockSize = GetPlainBlockSize(cert, UseOaepForSecurityPolicy(policy));

			if (data.Count % inputBlockSize != 0)
			{
				throw new Exception(string.Format("Input data is not a multiple of block size, {0}/{1}", data.Count, inputBlockSize));
			}

			var input = new byte[inputBlockSize];
			var ms = new MemoryStream();
			for (int i = 0; i < data.Count; i += inputBlockSize)
			{
				Array.Copy(data.Array, data.Offset + i, input, 0, input.Length);
				var encoded = rsa.Encrypt(input, UseOaepForSecurityPolicy(policy));
				ms.Write(encoded, 0, encoded.Length);
			}

			ms.Close();
			return ms.ToArray();
		}

		public static byte[] RsaPkcs15Sha_Decrypt(ArraySegment<byte> data, X509Certificate2 cert,
			RSA rsaPrivate, SecurityPolicy policy)
		{
			int cipherBlockSize = GetCipherTextBlockSize(cert);
			int plainSize = data.Count / cipherBlockSize;
			int blockSize = GetPlainBlockSize(cert, UseOaepForSecurityPolicy(policy));

			plainSize *= blockSize;

			var buffer = new byte[plainSize];
			int inputBlockSize = rsaPrivate.KeySize / 8;
			int outputBlockSize = GetPlainBlockSize(cert, UseOaepForSecurityPolicy(policy));

			if (data.Count % inputBlockSize != 0)
			{
				throw new Exception(string.Format("Input data is not a multiple of block size, {0}/{1}", data.Count, inputBlockSize));
			}

			var ms = new MemoryStream(buffer);
			var block = new byte[inputBlockSize];
			for (int i = data.Offset; i < data.Offset + data.Count; i += inputBlockSize)
			{
				Array.Copy(data.Array, i, block, 0, block.Length);
				var plain = rsaPrivate.Decrypt(block, UseOaepForSecurityPolicy(policy));
				ms.Write(plain, 0, plain.Length);
			}
			ms.Close();

			return buffer;
		}

		public static bool VerifyCertificate(X509Certificate2 senderCert)
		{
			return senderCert != null;
		}

		public static byte[] SHACalculate(byte[] data, SecurityPolicy policy)
		{
			using (var sha = HashAlgorithmForSecurityPolicy(policy))
			{
				return sha.ComputeHash(data);
			}
		}

		public static byte[] SymmetricSign(byte[] key, ArraySegment<byte> data, SecurityPolicy policy)
		{
			HMAC hmac = HMACForSecurityPolicy(key, policy);

			using (MemoryStream ms = new MemoryStream(data.Array, data.Offset, data.Count))
			{
				byte[] signature = hmac.ComputeHash(ms);
				return signature;
			}
		}

		private static HMAC HMACForSecurityPolicy(byte[] key, SecurityPolicy policy)
		{
			return policy == SecurityPolicy.Basic256Sha256 ?
							(HMAC)new HMACSHA256(key) : new HMACSHA1(key);
		}

		public static byte[] SHACalculate(ArraySegment<byte> data, SecurityPolicy policy)
		{
			using (var sha = HashAlgorithmForSecurityPolicy(policy))
			{
				return sha.ComputeHash(data.Array, data.Offset, data.Count);
			}
		}

		public static bool SHAVerify(byte[] data, byte[] hash, SecurityPolicy policy)
		{
			var calc = SHACalculate(data, policy);
			if (calc.Length != hash.Length)
			{
				return false;
			}

			for (int i = 0; i < calc.Length; i++)
			{
				if (hash[i] != calc[i])
				{
					return false;
				}
			}

			return true;
		}

		public static byte[] PSHA(byte[] secret, byte[] seed, int length, SecurityPolicy policy)
		{
			var hmac = HMACForSecurityPolicy(secret, policy);
			int sigSize = SignatureSizeForSecurityPolicy(policy);

			var tmp = hmac.ComputeHash(seed);
			var keySeed = new byte[sigSize + seed.Length];

			Array.Copy(tmp, keySeed, tmp.Length);
			Array.Copy(seed, 0, keySeed, tmp.Length, seed.Length);

			var output = new byte[length];

			int pos = 0;
			while (pos < length)
			{
				byte[] hash = hmac.ComputeHash(keySeed);

				int writeLen = Math.Min(sigSize, length - pos);
				Array.Copy(hash, 0, output, pos, writeLen);
				pos += writeLen;

				tmp = hmac.ComputeHash(tmp);
				Array.Copy(tmp, keySeed, tmp.Length);
			}

			return output;
		}

		private static int SignatureSizeForSecurityPolicy(SecurityPolicy policy)
		{
			return policy == SecurityPolicy.Basic256Sha256 ? Sha256Size : Sha1Size;
		}

		public static StatusCode UnsecureSymmetric(MemoryBuffer recvBuf, uint tokenID, uint? prevTokenID, int messageEncodedBlockStart, SLChannel.Keyset localKeyset, SLChannel.Keyset[] remoteKeysets, SecurityPolicy policy, MessageSecurityMode securityMode, out int decrSize)
		{
			decrSize = -1;
			int restorePos = recvBuf.Position;

			byte type = 0;
			uint messageSize = 0;
			UInt32 secureChannelId, securityTokenId, securitySeqNum, securityReqId;

			if (!recvBuf.Decode(out type)) { return StatusCode.BadDecodingError; }
			if (!recvBuf.Decode(out messageSize)) { return StatusCode.BadDecodingError; }
			if (!recvBuf.Decode(out secureChannelId)) { return StatusCode.BadDecodingError; }
			if (!recvBuf.Decode(out securityTokenId)) { return StatusCode.BadDecodingError; }

			int keysetIdx = -1;
			if (tokenID == securityTokenId)
			{
				keysetIdx = 0;
			}
			else if (prevTokenID.HasValue && prevTokenID.Value == securityTokenId)
			{
				keysetIdx = 1;
			}
			else
			{
				return StatusCode.BadSecureChannelTokenUnknown;
			}

			//UInt32 respDecodeSize = messageSize;
			if (securityMode == MessageSecurityMode.SignAndEncrypt)
			{
				try
				{
					decrSize = UASecurity.RijndaelDecryptInplace(
						new ArraySegment<byte>(recvBuf.Buffer, messageEncodedBlockStart, (int)messageSize - messageEncodedBlockStart),
						remoteKeysets[keysetIdx].SymEncKey, remoteKeysets[keysetIdx].SymIV) + messageEncodedBlockStart;

					//respDecodeSize = (UInt32)(messageEncodedBlockStart + decrSize);
				}
				catch
				{
					return StatusCode.BadSecurityChecksFailed;
				}
			}
			else
			{
				decrSize = (int)messageSize;
			}

			if (securityMode >= MessageSecurityMode.Sign)
			{
				try
				{
					int sigSize = SignatureSizeForSecurityPolicy(policy);
					var sigData = new ArraySegment<byte>(recvBuf.Buffer, 0, (int)messageSize - sigSize);

					var sig = new ArraySegment<byte>(recvBuf.Buffer, (int)messageSize - sigSize, sigSize).ToArray();
					var sigExpect = UASecurity.SymmetricSign(remoteKeysets[keysetIdx].SymSignKey, sigData, policy);

					if (sig.Length != sigExpect.Length)
					{
						return StatusCode.BadSecurityChecksFailed;
					}

					for (int i = 0; i < sig.Length; i++)
					{
						if (sig[i] != sigExpect[i])
						{
							return StatusCode.BadSecurityChecksFailed;
						}
					}

					byte padValue = securityMode == MessageSecurityMode.SignAndEncrypt ? (byte)(recvBuf.Buffer[messageSize - sigSize - 1] + 1) : (byte)0;
					if (decrSize > 0)
					{
						decrSize -= sigSize;
						decrSize -= (int)padValue;
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

			if (!recvBuf.Decode(out securitySeqNum)) { return StatusCode.BadDecodingError; }
			if (!recvBuf.Decode(out securityReqId)) { return StatusCode.BadDecodingError; }

			recvBuf.Position = restorePos;

			return StatusCode.Good;
		}

		public static StatusCode SecureSymmetric(MemoryBuffer respBuf, int messageEncodedBlockStart, SLChannel.Keyset localKeyset, SLChannel.Keyset remoteKeyset, SecurityPolicy policy, MessageSecurityMode securityMode)
		{
			if (securityMode == MessageSecurityMode.None)
			{
				return StatusCode.Good;
			}

			int sigSize = SignatureSizeForSecurityPolicy(policy);
			if (securityMode >= MessageSecurityMode.SignAndEncrypt)
			{
				//int padSize2 = CalculateSymmetricPaddingSize(remoteKeyset.SymEncKey.Length, sigSize + respBuf.Position - messageEncodedBlockStart);
				int padSize = CalculateSymmetricPaddingSize(localKeyset.SymEncKey.Length, sigSize + respBuf.Position - messageEncodedBlockStart);

				byte paddingValue = (byte)((padSize - 1) & 0xFF);

				var appendPadding = new byte[padSize];
				for (int i = 0; i < padSize; i++) { appendPadding[i] = paddingValue; }
				respBuf.Append(appendPadding);
			}

			int msgSize = respBuf.Position + sigSize;
			if (securityMode >= MessageSecurityMode.SignAndEncrypt)
			{
				msgSize = messageEncodedBlockStart + CalculateSymmetricEncryptedSize(localKeyset.SymEncKey.Length, msgSize - messageEncodedBlockStart);
			}

			if (msgSize >= respBuf.Capacity)
			{
				return StatusCode.BadEncodingLimitsExceeded;
			}

			MarkUAMessageSize(respBuf, (UInt32)msgSize);

			var sig = UASecurity.SymmetricSign(localKeyset.SymSignKey, new ArraySegment<byte>(respBuf.Buffer, 0, respBuf.Position), policy);
			respBuf.Append(sig);

			if (msgSize != respBuf.Position)
			{
				throw new Exception();
			}

			if (securityMode >= MessageSecurityMode.SignAndEncrypt)
			{
				int encrLen = UASecurity.RijndaelEncryptInplace(
					new ArraySegment<byte>(respBuf.Buffer, messageEncodedBlockStart, msgSize - messageEncodedBlockStart),
					localKeyset.SymEncKey, localKeyset.SymIV);
			}

			return StatusCode.Good;
		}

		private static void MarkUAMessageSize(MemoryBuffer buf, UInt32 position)
		{
			int restorePos = buf.Position;
			buf.Position = 4;
			buf.Encode(position);
			buf.Position = restorePos;
		}
	}
}
