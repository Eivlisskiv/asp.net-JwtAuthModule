using System.Security.Cryptography;

namespace WebService.JwtAuthentication
{
	public static class DataHash
    {
        const int SALT_SIZE = 16;
        const int HASH_SIZE = 20;
        const int ITERATION_COUNT = 100000;

        private readonly static RandomNumberGenerator RNG = RandomNumberGenerator.Create();

        public static string Hash(string password)
        {
            byte[] salt; //cryptographic PRNG

            RNG.GetBytes(salt = new byte[SALT_SIZE]);

            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, ITERATION_COUNT);
            byte[] hash = pbkdf2.GetBytes(HASH_SIZE);

            byte[] hashBytes = new byte[SALT_SIZE + HASH_SIZE];
            Array.Copy(salt, 0, hashBytes, 0, SALT_SIZE);
            Array.Copy(hash, 0, hashBytes, SALT_SIZE, HASH_SIZE);

            return Convert.ToBase64String(hashBytes);
        }

        public static bool Verify(string input, string hashed)
        {
            /* Extract the bytes */
            byte[] hashBytes = Convert.FromBase64String(hashed);
            /* Get the salt */
            byte[] salt = new byte[SALT_SIZE];
            Array.Copy(hashBytes, 0, salt, 0, SALT_SIZE);
            /* Compute the hash on the password the user entered */
            var pbkdf2 = new Rfc2898DeriveBytes(input, salt, ITERATION_COUNT);
            byte[] hash = pbkdf2.GetBytes(HASH_SIZE);
            /* Compare the results */
            for (int i = 0; i < HASH_SIZE; i++)
                if (hashBytes[i + SALT_SIZE] != hash[i])
                    return false;

            return true;
        }
    }
}
