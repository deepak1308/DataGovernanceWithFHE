namespace SEALDemo
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using Microsoft.Research.SEAL;

    class SEALStringOperations
    {
		// encryption params
		private EncryptionParameters encryptionParams;
		private SecretKey secretKey;
		private PublicKey publicKey;
		private RelinKeys relinKeys;

		private int index = 1;
		// ciphertext map
		private Dictionary<string, List<Ciphertext>> cmap;
		private Dictionary<string, Ciphertext> crmap;

		public static bool log = false;

		public void InitParams()
		{
			this.encryptionParams = new EncryptionParameters(SchemeType.BFV);
			ulong polyModulusDegree = 4096;
			this.encryptionParams.PolyModulusDegree = polyModulusDegree;
			this.encryptionParams.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
			this.encryptionParams.PlainModulus = PlainModulus.Batching(polyModulusDegree, 20);

			SEALContext context = new SEALContext(this.encryptionParams);
			KeyGenerator keygen = new KeyGenerator(context);
			this.secretKey = keygen.SecretKey;
			if (log)
				Console.WriteLine("Key size: " + SEALNumberOperations.GetKeySize(secretKey));
			keygen.CreatePublicKey(out this.publicKey);
			keygen.CreateRelinKeys(out this.relinKeys);

			cmap = new Dictionary<string, List<Ciphertext>>();
			crmap = new Dictionary<string, Ciphertext>();
		}

		public void PrintMatrix(List<ulong> matrix, int sz)
		{
			if (log)
            {
				Console.WriteLine("Print matrix:");
				for (int i = 0; i < sz; i++)
				{
					Console.Write(matrix[i] + " ");
				}
				Console.WriteLine();
			}
		}

		public bool CompareString(string uid, string input, bool startsWith)
		{
			if (!cmap.ContainsKey(uid))
			{
				return false;
			}

			using SEALContext context = new SEALContext(this.encryptionParams);
			using Encryptor encryptor = new Encryptor(context, this.publicKey);
			using Evaluator evaluator = new Evaluator(context);
			using Decryptor decryptor = new Decryptor(context, secretKey);
			using BatchEncoder encoder = new BatchEncoder(context);

			ulong slotCount = encoder.SlotCount;

			List<ulong> inputMatrix = new List<ulong>(new ulong[slotCount]);

			for (int i = 0; i < input.Length; i++)
			{
				inputMatrix[i] = Convert.ToUInt64(input[i]);
			}

			PrintMatrix(inputMatrix, input.Length);

			using Plaintext plainMatrix = new Plaintext();
			encoder.Encode(inputMatrix, plainMatrix);

			using Ciphertext encryptedResult = new Ciphertext();
			evaluator.SubPlain(cmap[uid][0], plainMatrix, encryptedResult);
			evaluator.RelinearizeInplace(encryptedResult, this.relinKeys);
			if (log)
				Console.WriteLine($"Noise budget in encryptedResult: {decryptor.InvariantNoiseBudget(encryptedResult)} bits");

			using Plaintext plainResult = new Plaintext();
			decryptor.Decrypt(encryptedResult, plainResult);

			if (!startsWith)
			{
				return plainResult.IsZero;
			}

			List<ulong> podResult = new List<ulong>(); ;
			encoder.Decode(plainResult, podResult);

			PrintMatrix(podResult, input.Length);

			for (int i = 0; i < input.Length && startsWith; i++)
			{
				startsWith = startsWith && (podResult[i] == 0);
			}

			return startsWith;
		}

		public bool SubstringMatch(string uid, string input)
		{
			if (!cmap.ContainsKey(uid))
			{
				return false;
			}

			using SEALContext context = new SEALContext(this.encryptionParams);
			using Encryptor encryptor = new Encryptor(context, this.publicKey);
			using Evaluator evaluator = new Evaluator(context);
			using Decryptor decryptor = new Decryptor(context, secretKey);
			using BatchEncoder encoder = new BatchEncoder(context);

			ulong slotCount = encoder.SlotCount;

			List<ulong> inputMatrix = new List<ulong>(new ulong[slotCount]);

			for (int i = 0; i < input.Length; i++)
			{
				inputMatrix[i] = Convert.ToUInt64(input[i]);
			}

			PrintMatrix(inputMatrix, input.Length);

			using Plaintext plainMatrix = new Plaintext();
			encoder.Encode(inputMatrix, plainMatrix);

			List<Ciphertext> encryptedMatrix = cmap[uid];
			List<Ciphertext> encryptedResult = new List<Ciphertext>();
			for (int st = 0; st < encryptedMatrix.Count; st++)
			{
				encryptedResult.Add(new Ciphertext());
				evaluator.SubPlain(encryptedMatrix[st], plainMatrix, encryptedResult[st]);
				evaluator.RelinearizeInplace(encryptedResult[st], this.relinKeys);
			}
			if (log)
				Console.WriteLine($"Noise budget in encryptedResult: {decryptor.InvariantNoiseBudget(encryptedResult[0])} bits");

			for (int st = 0; st < encryptedResult.Count; st++)
			{
				using Plaintext plainResult = new Plaintext();
				decryptor.Decrypt(encryptedResult[st], plainResult);

				if (plainResult.IsZero)
				{
					return true;
				}

				List<ulong> podResult = new List<ulong>();
				encoder.Decode(plainResult, podResult);

				PrintMatrix(podResult, input.Length);

				bool startsWith = true;
				for (int i = 0; i < input.Length && startsWith; i++)
				{
					startsWith = startsWith && (podResult[i] == 0);
				}

				if (startsWith)
				{
					return true;
				}
			}

			return false;
		}

		public string StoreCiphertext(string pattern)
		{
			using SEALContext context = new SEALContext(this.encryptionParams);
			using Encryptor encryptor = new Encryptor(context, this.publicKey);
			using Decryptor decryptor = new Decryptor(context, secretKey);
			using BatchEncoder encoder = new BatchEncoder(context);

			ulong slotCount = encoder.SlotCount;

			List<List<ulong>> podMatrix = new List<List<ulong>>(pattern.Length);
			for (int st = 0; st < pattern.Length; st++)
			{
				podMatrix.Add(new List<ulong>(new ulong[slotCount]));
				for (int i = st; i < pattern.Length; i++)
				{
					podMatrix[st][i - st] = Convert.ToUInt64(pattern[i]);
				}
			}

			PrintMatrix(podMatrix[0], pattern.Length);

			List<Plaintext> plainMatrix = new List<Plaintext>();
			for (int st = 0; st < pattern.Length; st++)
			{
				plainMatrix.Add(new Plaintext());
				encoder.Encode(podMatrix[st], plainMatrix[st]);
			}

			List<Ciphertext> encryptedMatrix = new List<Ciphertext>();
			for (int st = 0; st < pattern.Length; st++)
			{
				encryptedMatrix.Add(new Ciphertext());
				encryptor.Encrypt(plainMatrix[st], encryptedMatrix[st]);
			}
			if (log)
				Console.WriteLine($"Noise budget in encryptedResult: {decryptor.InvariantNoiseBudget(encryptedMatrix[0])} bits");
			if (log)
				Console.WriteLine("Ciphertext size: " + SEALNumberOperations.GetCiphertextSize(encryptedMatrix[0]));

			foreach(var entry in cmap)
            {
				if (CompareString(entry.Key, pattern, false))
                {
					return entry.Key;
                }
            }

			string uniqueId = "xxxxxxxxxx_" + (index++);
			cmap.Add(uniqueId, encryptedMatrix);

			int pos = pattern.IndexOf("/**");
			if (pos != -1)
			{
				string newPattern = pattern.Substring(0, pos);
				//Console.WriteLine("Processing recurrent attribute: " + newPattern);

				List<ulong> podMatrix2 = new List<ulong>(new ulong[slotCount]);
				for (int i = 0; i < newPattern.Length; i++)
				{
					podMatrix2[i] = Convert.ToUInt64(newPattern[i]);
				}

				PrintMatrix(podMatrix2, newPattern.Length);

				Plaintext plainMatrix2 = new Plaintext();
				encoder.Encode(podMatrix2, plainMatrix2);

				Ciphertext encryptedMatrix2 = new Ciphertext();
				encryptor.Encrypt(plainMatrix2, encryptedMatrix2);
				if (log)
					Console.WriteLine($"Noise budget in encryptedResult: {decryptor.InvariantNoiseBudget(encryptedMatrix2)} bits");
				if (log)
					Console.WriteLine("Ciphertext size: " + SEALNumberOperations.GetCiphertextSize(encryptedMatrix2));

				crmap.Add(uniqueId, encryptedMatrix2);
			}

			return uniqueId;
		}

		public bool InputStartsWithPattern(string uid, string input)
		{
			if (!cmap.ContainsKey(uid))
			{
				return false;
			}
			if (!crmap.ContainsKey(uid))
			{
				return false;
			}

			using SEALContext context = new SEALContext(this.encryptionParams);
			using Encryptor encryptor = new Encryptor(context, this.publicKey);
			using Evaluator evaluator = new Evaluator(context);
			using Decryptor decryptor = new Decryptor(context, secretKey);
			using BatchEncoder encoder = new BatchEncoder(context);

			ulong slotCount = encoder.SlotCount;

			List<ulong> inputMatrix = new List<ulong>(new ulong[input.Length]);

			for (int i = 0; i < input.Length; i++)
			{
				inputMatrix[i] = Convert.ToUInt64(input[i]);
			}

			PrintMatrix(inputMatrix, input.Length);

			using Plaintext plainMatrix = new Plaintext();
			encoder.Encode(inputMatrix, plainMatrix);

			using Ciphertext encryptedResult = new Ciphertext();
			evaluator.SubPlain(crmap[uid], plainMatrix, encryptedResult);
			evaluator.RelinearizeInplace(encryptedResult, this.relinKeys);
			if (log)
				Console.WriteLine($"Noise budget in encryptedResult: {decryptor.InvariantNoiseBudget(encryptedResult)} bits");

			using Plaintext plainResult = new Plaintext();
			decryptor.Decrypt(encryptedResult, plainResult);

			List<ulong> podResult = new List<ulong>();
			encoder.Decode(plainResult, podResult);

			PrintMatrix(podResult, input.Length);

			bool startsWith = true;
			for (int i = 0; i < cmap[uid].Count - 3 && startsWith; i++)
			{
				startsWith = startsWith && (podResult[i] == 0);
			}

			return startsWith;
		}
	}
}
