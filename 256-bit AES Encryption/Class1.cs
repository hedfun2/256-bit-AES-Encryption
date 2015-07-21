using System;
using System.IO;
using System.Security.Cryptography;

namespace Encryption
{
    public class AESEncryption
    {
        private readonly byte[] salt = { 6, 22, 42, 1, 238, 156, 23, 19 };
        private const int KEY_SIZE = 256;
        private const int BLOCK_SIZE = 128;
        private readonly PaddingMode PADDING_MODE = PaddingMode.PKCS7;

        /// <summary>
        /// Encrypts specified byte[] with 256-bit AES Encryption using specified password byte[] and specified IV byte[]
        /// </summary>
        /// <param name="bytesToBeEncrypted">The byte[] to be encrypted</param>
        /// <param name="passwordBytes">The password used to generate the AES key</param>
        /// <param name="iv">The initialization vector that will be used to encrypt the byte[]</param>
        /// <returns>The encrypted byte[]</returns>
        public byte[] EncryptBytes(byte[] bytesToBeEncrypted, byte[] passwordBytes, byte[] iv)
        {
            //If parameters are null throw exception
            if (bytesToBeEncrypted == null)
                throw new ArgumentNullException("bytesToBeEncrypted");
            if (passwordBytes == null)
                throw new ArgumentNullException("passwordBytes");

            byte[] encryptedBytes = null;

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    AES.Padding = PADDING_MODE;

                    //Generates key and IV
                    var key = new Rfc2898DeriveBytes(passwordBytes, salt, 10000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = iv;

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        try
                        {
                            cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                            cs.Close();
                        }
                        catch (CryptographicException e)
                        {
                            throw e;
                        }
                    }
                    encryptedBytes = ms.ToArray();

                }
            }
            return encryptedBytes;
        }

        /// <summary>
        /// Decrypts specified byte[] with 256-bit AES Encryption using specified password byte[] and specified IV byte[]
        /// </summary>
        /// <param name="bytesToBeDecrypted">The byte[] to be decrypted</param>
        /// <param name="passwordBytes">The password used to generate the AES key</param>
        /// <param name="iv">The initialization vector that was used to encrypt the byte[]</param>
        /// <returns>The decrypted byte[]</returns>
        public byte[] DecryptBytes(byte[] bytesToBeDecrypted, byte[] passwordBytes, byte[] iv)
        {
            //If parameters are null throw exception
            if (bytesToBeDecrypted == null)
                throw new ArgumentNullException("bytesToBeDecrypted");
            if (passwordBytes == null)
                throw new ArgumentNullException("passwordBytes");

            byte[] decryptedBytes = null;

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    AES.Padding = PADDING_MODE;

                    //Generates key
                    var key = new Rfc2898DeriveBytes(passwordBytes, salt, 10000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = iv;

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        try
                        {
                            cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                            cs.Close();
                        }
                        catch (CryptographicException e)
                        {
                            throw new CryptographicException("Invalid Password");
                        }
                    }
                    decryptedBytes = ms.ToArray();

                }
            }
            return decryptedBytes;
        }

        /// <summary>
        /// Encrypts unencryptedFilePath using 256-bit AES Encryption to the encryptedFilePath using the password passwordBytes
        /// </summary>
        /// <param name="unencryptedFilePath">The file path to the unencrypted file</param>
        /// <param name="encryptedFilePath">The file path in which the encrypted file will be placed</param>
        /// <param name="passwordBytes">The password used to generate the AES key</param>
        public void EncryptFile(string unencryptedFilePath, string encryptedFilePath, byte[] passwordBytes)
        {
            //If parameters are null throw exception
            if (unencryptedFilePath == null)
                throw new ArgumentNullException("unencryptedFilePath");
            if (encryptedFilePath == null)
                throw new ArgumentNullException("encryptedFilePath");
            try
            {
                using (FileStream fsUnencrypt = File.Open(unencryptedFilePath, FileMode.Open))
                using (FileStream fsEncrypt = File.Open(encryptedFilePath, FileMode.CreateNew))
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    AES.Padding = PADDING_MODE;

                    //Creates key
                    var key = new Rfc2898DeriveBytes(passwordBytes, salt, 10000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.Mode = CipherMode.CBC;

                    //Writes IV to beginning of encrypted file
                    fsEncrypt.Write(AES.IV, 0, 16);

                    using (var cs = new CryptoStream(fsEncrypt, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        //copys bytes from unencrypted file to encrypted file while encrypting them
                        fsUnencrypt.CopyTo(cs, 4096);
                        cs.Close();
                    }

                    fsEncrypt.Close();
                    fsUnencrypt.Close();
                }
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        /// <summary>
        /// Encrypts unencryptedFilePath asynchronously using 256-bit AES Encryption to the encryptedFilePath using the password passwordBytes
        /// </summary>
        /// <param name="unencryptedFilePath">The file path to the unencrypted file</param>
        /// <param name="encryptedFilePath">The file path in which the encrypted file will be placed</param>
        /// <param name="passwordBytes">The password used to generate the AES key</param>
        public async void EncryptFileAsync(string unencryptedFilePath, string encryptedFilePath, byte[] passwordBytes)
        {
            //If parameters are null throw exception
            if (unencryptedFilePath == null)
                throw new ArgumentNullException("unencryptedFilePath");
            if (encryptedFilePath == null)
                throw new ArgumentNullException("encryptedFilePath");
            try
            {
                using (FileStream fsUnencrypt = File.Open(unencryptedFilePath, FileMode.Open))
                using (FileStream fsEncrypt = File.Open(encryptedFilePath, FileMode.CreateNew))
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    AES.Padding = PADDING_MODE;

                    //Creates key
                    var key = new Rfc2898DeriveBytes(passwordBytes, salt, 10000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.Mode = CipherMode.CBC;

                    //Writes IV to beginning of encrypted file
                    await fsEncrypt.WriteAsync(AES.IV, 0, 16);

                    using (var cs = new CryptoStream(fsEncrypt, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        //copys bytes from unencrypted file to encrypted file while encrypting them
                        await fsUnencrypt.CopyToAsync(cs, 4096);
                        cs.Close();
                    }

                    fsEncrypt.Close();
                    fsUnencrypt.Close();
                }
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        /// <summary>
        /// Decrypts encryptedFilePath using 256-bit AES Encryption to the unencryptedFilePath using the password passwordBytes
        /// </summary>
        /// <param name="unencryptedFilePath">The file path in which the unencrypted file will be placed</param>
        /// <param name="encryptedFilePath">The file path to the encrypted</param>
        /// <param name="passwordBytes">The password used to generate the AES key</param>
        public void DecryptFile(string unencryptedFilePath, string encryptedFilePath, byte[] passwordBytes)
        {
            //If parameters are null throw exception
            if (unencryptedFilePath == null)
                throw new ArgumentNullException("unencryptedFilePath");
            if (encryptedFilePath == null)
                throw new ArgumentNullException("encryptedFilePath");

            try
            {
                using (FileStream fsEncrypt = File.Open(encryptedFilePath, FileMode.Open))
                using (FileStream fsUnencrypt = File.Open(unencryptedFilePath, FileMode.CreateNew))
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    AES.Padding = PADDING_MODE;

                    //Creates key
                    var key = new Rfc2898DeriveBytes(passwordBytes, salt, 10000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.Mode = CipherMode.CBC;

                    //Reads IV from beginning of file
                    byte[] theIV = new byte[16];
                    fsEncrypt.Read(theIV, 0, 16);
                    AES.IV = theIV;

                    using (var cs = new CryptoStream(fsUnencrypt, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        //copys bytes from encrypted file to unencrypted file while decrypting them
                        try
                        {
                            fsEncrypt.CopyTo(cs, 4096);
                            cs.Close();
                        }
                        catch (CryptographicException e)
                        {
                            throw new CryptographicException("Invalid Password");
                        }
                    }
                    fsUnencrypt.Close();
                }
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        /// <summary>
        /// Decrypts encryptedFilePath asynchronously using 256-bit AES Encryption to the unencryptedFilePath using the password passwordBytes
        /// </summary>
        /// <param name="unencryptedFilePath">The file path in which the unencrypted file will be placed</param>
        /// <param name="encryptedFilePath">The file path to the encrypted</param>
        /// <param name="passwordBytes">The password used to generate the AES key</param>
        public async void DecryptFileAsync(string unencryptedFilePath, string encryptedFilePath, byte[] passwordBytes)
        {
            //If parameters are null throw exception
            if (unencryptedFilePath == null)
                throw new ArgumentNullException("unencryptedFilePath");
            if (encryptedFilePath == null)
                throw new ArgumentNullException("encryptedFilePath");

            try
            {
                using (FileStream fsEncrypt = File.Open(encryptedFilePath, FileMode.Open))
                using (FileStream fsUnencrypt = File.Open(unencryptedFilePath, FileMode.CreateNew))
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    AES.Padding = PADDING_MODE;

                    //Creates key
                    var key = new Rfc2898DeriveBytes(passwordBytes, salt, 10000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.Mode = CipherMode.CBC;

                    //Reads IV from beginning of file
                    byte[] theIV = new byte[16];
                    await fsEncrypt.ReadAsync(theIV, 0, 16);
                    AES.IV = theIV;

                    using (var cs = new CryptoStream(fsUnencrypt, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        //copys bytes from encrypted file to unencrypted file while decrypting them
                        try
                        {
                            await fsEncrypt.CopyToAsync(cs, 4096);
                            cs.Close();
                        }
                        catch (CryptographicException e)
                        {
                            throw new CryptographicException("Invalid Password");
                        }
                    }
                    fsUnencrypt.Close();
                }
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        /// <summary>
        /// Encrypts specified byte[] with 256-bit AES Encryption using specified password string and specified IV byte[]
        /// </summary>
        /// <param name="bytesToBeEncrypted">The byte[] to be encrypted</param>
        /// <param name="password">The password used to generate the AES key</param>
        /// <param name="iv">The initialization vector that will be used to encrypt the byte[]</param>
        /// <returns>The encrypted byte[]</returns>
        public byte[] EncryptBytes(byte[] bytesToBeEncrypted, string password, byte[] iv)
        {
            byte[] passwordByte = System.Text.Encoding.UTF8.GetBytes(password);
            return EncryptBytes(bytesToBeEncrypted, passwordByte, iv);
        }

        /// <summary>
        /// Decrypts specified byte[] with 256-bit AES Encryption using specified password string and specified IV byte[]
        /// </summary>
        /// <param name="bytesToBeDecrypted">The byte[] to be decrypted</param>
        /// <param name="password">The password used to generate the AES key</param>
        /// <param name="iv">The initialization vector that was used to encrypt the byte[]</param>
        /// <returns>The decrypted byte[]</returns>
        public byte[] DecryptBytes(byte[] bytesToBeDecrypted, string password, byte[] iv)
        {
            byte[] passwordByte = System.Text.Encoding.UTF8.GetBytes(password);
            return DecryptBytes(bytesToBeDecrypted, passwordByte, iv);
        }

        /// <summary>
        /// Encrypts specified byte[] with 256-bit AES Encryption using specified password byte[] and generates a random 16 byte IV and attaches it to the beginning of the encryption
        /// </summary>
        /// <param name="bytesToBeEncrypted">The byte[] to be encrypted</param>
        /// <param name="passwordBytes">The password used to generate the AES key</param>
        /// <returns>The encrypted byte[]</returns>
        public byte[] EncryptBytes(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            //If parameters are null throw exception
            if (bytesToBeEncrypted == null)
                throw new ArgumentNullException("bytesToBeEncrypted");
            if (passwordBytes == null)
                throw new ArgumentNullException("passwordBytes");

            byte[] encryptedBytes = null;

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    AES.Padding = PADDING_MODE;

                    //Generates key and IV
                    var key = new Rfc2898DeriveBytes(passwordBytes, salt, 10000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.GenerateIV();

                    AES.Mode = CipherMode.CBC;

                    //writes the IV to the beginning of the memory stream
                    ms.Write(AES.IV, 0, AES.IV.Length);
                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();

                }
            }
            return encryptedBytes;
        }

        /// <summary>
        /// Decrypts specified byte[] with 256-bit AES Encryption using specified password byte[] and reads the IV from the encrypted bytes
        /// </summary>
        /// <param name="bytesToBeDecrypted">The byte[] to be decrypted</param>
        /// <param name="passwordBytes">The password used to generate the AES key</param>
        /// <returns>The decrypted byte[]</returns>
        public byte[] DecryptBytes(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] iv = GetIVFromEncryption(bytesToBeDecrypted);
            byte[] withoutIV = new byte[bytesToBeDecrypted.Length - 16];
            for (int i = 16; i < bytesToBeDecrypted.Length; i++)
            {
                withoutIV[i - 16] = bytesToBeDecrypted[i];
            }
            return DecryptBytes(withoutIV, passwordBytes, iv);
        }


        /// <summary>
        /// Encrypts specified byte[] with 256-bit AES Encryption using specified password string
        /// </summary>
        /// <param name="bytesToBeEncrypted">The byte[] to be encrypted</param>
        /// <param name="password">The password used to generate the AES key</param>
        /// <returns>The encrypted byte[]</returns>
        public byte[] EncryptBytes(byte[] bytesToBeEncrypted, string password)
        {
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            return EncryptBytes(bytesToBeEncrypted, passwordBytes);
        }

        /// <summary>
        /// Decrypts specified byte[] with 256-bit AES Encryption using specified password string
        /// </summary>
        /// <param name="bytesToBeDecrypted">The byte[] to be decrypted</param>
        /// <param name="password">The password used to generate the AES key</param>
        /// <returns>The decrypted byte[]</returns>
        public byte[] DecryptBytes(byte[] bytesToBeDecrypted, string password)
        {
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            return DecryptBytes(bytesToBeDecrypted, passwordBytes);
        }

        /// <summary>
        /// Encrypts specified string with 256-bit AES Encryption using specified password byte[]
        /// </summary>
        /// <param name="stringToBeEncrypted">The string to be encrypted</param>
        /// <param name="passwordBytes">The password used to generate the AES key</param>
        /// <returns>The encrypted base64 string</returns>
        public string EncryptString(string stringToBeEncrypted, byte[] passwordBytes)
        {
            byte[] stringInByteForm = System.Text.Encoding.UTF8.GetBytes(stringToBeEncrypted);
            byte[] encryptedBytes = EncryptBytes(stringInByteForm, passwordBytes);
            return Convert.ToBase64String(encryptedBytes);
        }

        /// <summary>
        /// Decrypts specified string with 256-bit AES Encryption using specified password byte[]
        /// </summary>
        /// <param name="stringToBeDecrypted">The string to be decrypted</param>
        /// <param name="passwordBytes">The password used to generate the AES key</param>
        /// <returns>The decrypted string</returns>
        public string DecryptString(string stringToBeDecrypted, byte[] passwordBytes)
        {
            byte[] stringInByteForm = Convert.FromBase64String(stringToBeDecrypted);
            byte[] decryptedBytes = DecryptBytes(stringInByteForm, passwordBytes);
            return System.Text.Encoding.UTF8.GetString(decryptedBytes);
        }

        /// <summary>
        /// Encrypts specified string with 256-bit AES Encryption using specified password string
        /// </summary>
        /// <param name="stringToBeEncrypted">The string to be encrypted</param>
        /// <param name="password">The password used to generate the AES key</param>
        /// <returns>The encrypted base64 string</returns>
        public string EncryptString(string stringToBeEncrypted, string password)
        {
            byte[] stringInByteForm = System.Text.Encoding.UTF8.GetBytes(stringToBeEncrypted);
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] encryptedBytes = EncryptBytes(stringInByteForm, passwordBytes);
            return Convert.ToBase64String(encryptedBytes);
        }

        /// <summary>
        /// Decrypts specified string with 256-bit AES Encryption using specified password string
        /// </summary>
        /// <param name="stringToBeDecrypted">The string to be decrypted</param>
        /// <param name="passwordBytes">The password used to generate the AES key</param>
        /// <returns>The decrypted string</returns>
        public string DecryptString(string stringToBeDecrypted, string password)
        {
            byte[] stringInByteForm = Convert.FromBase64String(stringToBeDecrypted);
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] decryptedBytes = DecryptBytes(stringInByteForm, passwordBytes);
            return System.Text.Encoding.UTF8.GetString(decryptedBytes);
        }

        /// <summary>
        /// Retrieves the IV from the encrypted bytes
        /// </summary>
        /// <param name="encryptedBytes">The encrypted bytes in which the IV will come from</param>
        /// <returns>The IV from the encryptedBytes</returns>
        public byte[] GetIVFromEncryption(byte[] encryptedBytes)
        {
            if (encryptedBytes == null)
                throw new ArgumentNullException("encryptedBytes");
            if (encryptedBytes.Length < 16)
                throw new ArgumentException("encryptedBytes must be atleast 16 bytes long");
            byte[] IV = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                IV[i] = encryptedBytes[i];
            }
            return IV;
        }

        /// <summary>
        /// Generates a random IV
        /// </summary>
        /// <returns>Random IV</returns>
        public byte[] GenerateIV()
        {
            RijndaelManaged AES = new RijndaelManaged();
            AES.GenerateIV();
            return AES.IV;
        }



    }

}