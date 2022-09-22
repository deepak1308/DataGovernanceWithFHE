namespace SEALDemo
{
    using System;
    using System.IO;
    using System.Text;
    using Microsoft.Research.SEAL;
    class SEALNumberOperations
    {
        /// <summary>
        /// Helper function: Convert a ulong to a hex string representation
        /// </summary>
        public static string ULongToString(ulong value)
        {
            byte[] bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }
            return BitConverter.ToString(bytes).Replace("-", "");
        }

        public static int GetCiphertextSize(Ciphertext ciphertext)
        {
            MemoryStream mst = new MemoryStream();
            ciphertext.Save(mst, ComprModeType.ZLIB);
            byte[] buffer = mst.GetBuffer();
            string ctext = Encoding.UTF8.GetString(buffer);

            return ctext.Length;
        }

        public static int GetKeySize(SecretKey secretKey)
        {
            MemoryStream mst = new MemoryStream();
            secretKey.Save(mst, ComprModeType.ZLIB);
            byte[] buffer = mst.GetBuffer();
            string ctext = Encoding.UTF8.GetString(buffer);

            return ctext.Length;
        }

        public static void TestBFV()
        {
            using EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            ulong polyModulusDegree = 4096;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            parms.PlainModulus = new Modulus(1024);

            using SEALContext context = new SEALContext(parms);

            using KeyGenerator keygen = new KeyGenerator(context);
            using SecretKey secretKey = keygen.SecretKey;
            keygen.CreatePublicKey(out PublicKey publicKey);

            using Encryptor encryptor = new Encryptor(context, publicKey);
            using Evaluator evaluator = new Evaluator(context);
            using Decryptor decryptor = new Decryptor(context, secretKey);

            // encrypt and evaluate 5^2+1
            ulong x = 5;
            using Plaintext xPlain = new Plaintext(ULongToString(x));
            Console.WriteLine($"Express x = {x} as a plaintext polynomial 0x{xPlain}.");
            using Ciphertext xEncrypted = new Ciphertext();
            encryptor.Encrypt(xPlain, xEncrypted);

            Console.WriteLine($"    + size of freshly encrypted x: {xEncrypted.Size}");
            Console.WriteLine("    + noise budget in freshly encrypted x: {0} bits",
                decryptor.InvariantNoiseBudget(xEncrypted));

            using Plaintext xDecrypted = new Plaintext();
            Console.Write("    + decryption of encrypted_x: ");
            decryptor.Decrypt(xEncrypted, xDecrypted);
            Console.WriteLine($"0x{xDecrypted} ...... Correct.");

            using Ciphertext xSqPlusOne = new Ciphertext();
            evaluator.Square(xEncrypted, xSqPlusOne);
            using Plaintext plainOne = new Plaintext("1");
            evaluator.AddPlainInplace(xSqPlusOne, plainOne);

            Console.WriteLine($"    + size of xSqPlusOne: {xSqPlusOne.Size}");
            Console.WriteLine("    + noise budget in xSqPlusOne: {0} bits",
                decryptor.InvariantNoiseBudget(xSqPlusOne));

            // decrypt and check result
            using Plaintext decryptedResult = new Plaintext();
            Console.Write("    + decryption of xSqPlusOne: ");
            decryptor.Decrypt(xSqPlusOne, decryptedResult);
            Console.WriteLine($"0x{decryptedResult} ...... Correct.");
            Console.WriteLine($"Final result: {Convert.ToInt32($"0x{decryptedResult}", 16)}");
        }

        public static bool AreEqual(ulong n1, ulong n2)
        {
            using EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            ulong polyModulusDegree = 4096;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            parms.PlainModulus = new Modulus(1024);

            using SEALContext context = new SEALContext(parms);

            using KeyGenerator keygen = new KeyGenerator(context);
            using SecretKey secretKey = keygen.SecretKey;
            Console.WriteLine("Key size: " + GetKeySize(secretKey));
            keygen.CreatePublicKey(out PublicKey publicKey);

            using Encryptor encryptor = new Encryptor(context, publicKey);
            using Evaluator evaluator = new Evaluator(context);
            using Decryptor decryptor = new Decryptor(context, secretKey);

            using Plaintext plain1 = new Plaintext(ULongToString(n1));
            Console.WriteLine($"Express x = {n1} as a plaintext polynomial 0x{plain1}.");
            using Ciphertext encrypted1 = new Ciphertext();
            encryptor.Encrypt(plain1, encrypted1);
            Console.WriteLine("Encrypted n1: " + encrypted1.IsTransparent);
            Console.WriteLine($"Invariant noise budget n1: " + decryptor.InvariantNoiseBudget(encrypted1));

            using Plaintext plain2 = new Plaintext(ULongToString(n2));
            Console.WriteLine($"Express x = {n2} as a plaintext polynomial 0x{plain2}.");
            using Ciphertext encrypted2 = new Ciphertext();
            encryptor.Encrypt(plain2, encrypted2);
            Console.WriteLine("Encrypted n2: " + encrypted2.IsTransparent);
            Console.WriteLine($"Invariant noise budget n2: " + decryptor.InvariantNoiseBudget(encrypted2));

            using Ciphertext encrypted3 = new Ciphertext();
            evaluator.Sub(encrypted1, encrypted2, encrypted3);
            Console.WriteLine($"Invariant noise budget n3: " + decryptor.InvariantNoiseBudget(encrypted3));
            Console.WriteLine($"Size n1: {encrypted1.Size} n2: {encrypted2.Size} n3: {encrypted3.Size}");
            using Plaintext plain3 = new Plaintext();
            using Plaintext zero = new Plaintext(ULongToString(0ul));
            decryptor.Decrypt(encrypted3, plain3);

            Console.WriteLine("Decrypted result: " + plain3);

            Console.WriteLine("Size of ciphertext: " + GetCiphertextSize(encrypted3));

            return plain3.Equals(zero);
        }
    }
}
