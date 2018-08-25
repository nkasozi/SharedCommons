using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Messaging;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Linq;
using System.ServiceProcess;

public static class SharedCommons
{
    //generate unique id
    //Get Telecom 
    //Is Valid Ug Number
    //0785975800 256785975800
    public static string GetUgPhoneNetworkCode(string Phone)
    {
        if (string.IsNullOrEmpty(Phone))
        {
            return "UNKNOWN";
        }
        if (Phone.Length != 10 && Phone.Length != 12)
        {
            return "UNKNOWN";
        }
        if (Phone.StartsWith("079"))
        {
            return "AFRICELL";
        }
        if (Phone.StartsWith("078"))
        {
            return "MTN";
        }
        if (Phone.StartsWith("077"))
        {
            return "MTN";
        }
        if (Phone.StartsWith("075"))
        {
            return "AIRTEL";
        }
        if (Phone.StartsWith("074"))
        {
            return "SMART";
        }
        if (Phone.StartsWith("071"))
        {
            return "UTL";
        }
        if (Phone.StartsWith("070"))
        {
            return "AIRTEL";
        }

        //256
        if (Phone.StartsWith("25679"))
        {
            return "AFRICELL";
        }
        if (Phone.StartsWith("25678"))
        {
            return "MTN";
        }
        if (Phone.StartsWith("25677"))
        {
            return "MTN";
        }
        if (Phone.StartsWith("25675"))
        {
            return "AIRTEL";
        }
        if (Phone.StartsWith("25674"))
        {
            return "SMART";
        }
        if (Phone.StartsWith("25671"))
        {
            return "UTL";
        }
        if (Phone.StartsWith("25670"))
        {
            return "AIRTEL";
        }
        return "UNKNOWN";
    }

    public static string FormatUgPhoneNumber(string Phone)
    {
        Phone = Phone.Replace("+", string.Empty);
        Phone = Phone.Replace("-", string.Empty);
        Phone = Phone.Replace(" ", string.Empty);
        if (string.IsNullOrEmpty(Phone))
        {
            return Phone;
        }
        if (Phone.StartsWith("0"))
        {
            Phone = "256" + Phone.Substring(1);
        }
        if (Phone.StartsWith("7"))
        {
            Phone = "256" + Phone;
        }
        return Phone;
    }

    public static string RemoveCommasFromMoneyString(string money)
    {
        if (!string.IsNullOrEmpty(money))
        {
            money = money.Replace(",", string.Empty);
        }
        return money;
    }

    public static CommonResult StartService(string serviceName)
    {
        CommonResult result = new CommonResult();
        try
        {
            ServiceController service = new ServiceController(serviceName);
            if (service.Status == ServiceControllerStatus.Stopped)
            {
                service.Start();
                result.StatusCode = SharedCommonsGlobals.SUCCESS_STATUS_CODE;
                result.StatusDesc = SharedCommonsGlobals.SUCCESS_STATUS_TEXT;
                return result;
            }
            result.StatusCode = SharedCommonsGlobals.SUCCESS_STATUS_CODE;
            result.StatusDesc = "SERVICE STATUS = " + service.Status;
            return result;
        }
        catch (Exception ex)
        {
            result.StatusCode = SharedCommonsGlobals.FAILURE_STATUS_CODE;
            result.StatusDesc = "ERROR:" + ex.Message;
        }
        return result;
    }

    public static CommonResult RemoveUserFromGroup(string userId, string groupName, string domain)
    {
        CommonResult result = new CommonResult();
        try
        {
            using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, domain))
            {
                GroupPrincipal group = GroupPrincipal.FindByIdentity(pc, groupName);
                Principal user = group.Members.Where(i => i.SamAccountName.ToUpper() == userId.ToUpper()).FirstOrDefault();
                if (user != null)
                {
                    group.Members.Remove(pc, IdentityType.SamAccountName, userId);
                    group.Save();
                    result.StatusCode = SharedCommonsGlobals.SUCCESS_STATUS_CODE;
                    result.StatusDesc = SharedCommonsGlobals.SUCCESS_STATUS_TEXT;
                    return result;
                }
                result.StatusCode = SharedCommonsGlobals.FAILURE_STATUS_CODE;
                result.StatusDesc = $"ERROR: USER WITH ID {userId} NOT FOUND IN DOMAIN MEMBERS";
                return result;
            }
        }
        catch (Exception ex)
        {
            result.StatusCode = SharedCommonsGlobals.FAILURE_STATUS_CODE;
            result.StatusDesc = "ERROR:" + ex.Message;
        }
        return result;
    }

    public static string FormatTranAmount(string Amount)
    {
        Amount = Amount.Trim();
        return RemoveCommasFromMoneyString(Amount);
    }

    public static string GenerateUniqueId(string LeadString)
    {
        return LeadString + "-" + DateTime.Now.Ticks.ToString();
    }

    //0785975800 256785975800
    public static bool IsValidUgPhoneNumber(string Phone)
    {
        if (string.IsNullOrEmpty(Phone))
        {
            return false;
        }
        if (Phone.Length != 10 && Phone.Length != 12)
        {
            return false;
        }

        //check if there is any invalid character in the phone number
        foreach (char i in Phone)
        {
            if (!char.IsDigit(i))
            {
                return false;
            }
        }

        //start checking the short codes
        if (Phone.StartsWith("079"))
        {
            return true;
        }
        if (Phone.StartsWith("078"))
        {
            return true;
        }
        if (Phone.StartsWith("077"))
        {
            return true;
        }
        if (Phone.StartsWith("075"))
        {
            return true;
        }
        if (Phone.StartsWith("074"))
        {
            return true;
        }
        if (Phone.StartsWith("071"))
        {
            return true;
        }
        if (Phone.StartsWith("070"))
        {
            return true;
        }

        //256
        if (Phone.StartsWith("25679"))
        {
            return true;
        }
        if (Phone.StartsWith("25678"))
        {
            return true;
        }
        if (Phone.StartsWith("25677"))
        {
            return true;
        }
        if (Phone.StartsWith("25675"))
        {
            return true;
        }
        if (Phone.StartsWith("25674"))
        {
            return true;
        }
        if (Phone.StartsWith("25671"))
        {
            return true;
        }
        if (Phone.StartsWith("25670"))
        {
            return true;
        }

        return false;
    }
    public static string GenerateMD5Hash(string input)
    {
        // Use input string to calculate MD5 hash
        MD5 md5 = MD5.Create();
        byte[] inputBytes = Encoding.ASCII.GetBytes(input);
        byte[] hashBytes = md5.ComputeHash(inputBytes);

        // Convert the byte array to hexadecimal string
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hashBytes.Length; i++)
        {
            sb.Append(hashBytes[i].ToString("X2"));
        }
        return sb.ToString();
    }

    public static string GenerateRandomString(int size = 6, string charsAllowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
    {
        using (var crypto = new RNGCryptoServiceProvider())
        {
            var data = new byte[size];

            // If chars.Length isn't a power of 2 then there is a bias if
            // we simply use the modulus operator. The first characters of
            // chars will be more probable than the last ones.

            // buffer used if we encounter an unusable random byte. We will
            // regenerate it in this buffer
            byte[] smallBuffer = null;

            // Maximum random number that can be used without introducing a
            // bias
            int maxRandom = byte.MaxValue - ((byte.MaxValue + 1) % charsAllowed.Length);

            crypto.GetBytes(data);

            var result = new char[size];

            for (int i = 0; i < size; i++)
            {
                byte v = data[i];

                while (v > maxRandom)
                {
                    if (smallBuffer == null)
                    {
                        smallBuffer = new byte[1];
                    }

                    crypto.GetBytes(smallBuffer);
                    v = smallBuffer[0];
                }

                result[i] = charsAllowed[v % charsAllowed.Length];
            }

            return new string(result);
        }
    }

    public static bool GetBoolFromStringDefaultsToFalse(string text)
    {
        try
        {
            return Convert.ToBoolean(text);
        }

        catch (Exception ex)
        {
            return false;
        }
    }

    public static int GetIntFromStringDefaultsToFalse(string text)
    {
        try
        {
            return Convert.ToInt32(text);
        }
        catch (Exception ex)
        {
            return 0;
        }
    }

    public static string GetDigitalSignature(string dataToSign, string PathToPrivateKey, string PasswordForPrivateKey)
    {
        // path to your private key
        string pathToPrivateKey = PathToPrivateKey;

        // Password of your private key 
        string Password = PasswordForPrivateKey;

        // load the private key
        X509Certificate2 cert = new X509Certificate2(pathToPrivateKey, Password, X509KeyStorageFlags.UserKeySet);
        RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)cert.PrivateKey;

        // Hash the data
        SHA1Managed sha1 = new SHA1Managed();
        ASCIIEncoding encoding = new ASCIIEncoding();
        byte[] data = encoding.GetBytes(dataToSign);
        byte[] hash = sha1.ComputeHash(data);

        // Sign the hash
        byte[] digitalSignatureBytes = rsa.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));
        string strDigitalSignature = Convert.ToBase64String(digitalSignatureBytes);
        return strDigitalSignature;
    }

    public static string MaskString(string inputString, int leftUnMaskLength, int rightUnMaskLength, char mask)
    {
        if ((leftUnMaskLength + rightUnMaskLength) > inputString.Length)
            return inputString;

        return inputString.Substring(0, leftUnMaskLength) +
            new string(mask, inputString.Length - (leftUnMaskLength + rightUnMaskLength)) +
            inputString.Substring(inputString.Length - rightUnMaskLength);
    }

    public static bool VerifyDigitalSignature(string data, string digitalSignature, string pathToPublicKey)
    {
        return true;
    }

    public static string GenearetHMACSha256Hash(string key, string dataToSign)
    {
        ASCIIEncoding encoding = new ASCIIEncoding();
        byte[] keyByte = encoding.GetBytes(key);
        byte[] messageBytes = encoding.GetBytes(dataToSign);
        using (var hmacsha256 = new HMACSHA256(keyByte))
        {
            byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
            string base64string = Convert.ToBase64String(hashmessage);
            string HmacHexString = ByteArrayToString(hashmessage);
            return HmacHexString;
        }
    }

    public static string ByteToString(byte[] buff)
    {
        string sbinary = "";

        for (int i = 0; i < buff.Length; i++)
        {
            sbinary += buff[i].ToString("X2"); // hex format
        }
        return (sbinary);
    }

    public static string DecryptString(string encryptedText, string Key)
    {
        return Encryption.encrypt.DecryptString(encryptedText, Key);
    }

    public static string EncryptString(string plainText, string Key)
    {
        return Encryption.encrypt.EncryptString(plainText, Key);
    }

    public static string CheckForNulls(object obj, string nullableProperties)
    {
        string[] nullables = nullableProperties.ToUpper().Split('|');

        List<string> propertiesThatAreAllowedToBeNull = new List<string>();
        propertiesThatAreAllowedToBeNull.AddRange(nullables);

        Type objType = obj.GetType();
        PropertyInfo[] oldFields = objType.GetProperties(BindingFlags.DeclaredOnly | BindingFlags.Public | BindingFlags.Instance);

        //loop through all object fields
        foreach (var objProperty in oldFields)
        {

            string propertyName = objProperty.Name;

            //check if this field is expected from check
            if (propertiesThatAreAllowedToBeNull.Contains(propertyName.ToUpper()))
            {
                continue;
            }

            //get field obj
            object fieldObj = objProperty.GetValue(obj, new object[] { });

            if (objProperty.PropertyType == typeof(string))
            {
                //convert to string
                string propertyValue = fieldObj as string;

                //check if string is null
                if (string.IsNullOrEmpty(propertyValue))
                {
                    return "PLEASE SUPPLY A VALUE IN FIELD [" + propertyName + "]";
                }

                //field is a string and is not null
                continue;
            }

            //this is some other object type
            //so we just check to make sure it aint null
            if (fieldObj == null)
            {
                return "PLEASE SUPPLY A VALUE IN FIELD [" + propertyName + "]";
            }

            //field is not null
            continue;
        }

        return SharedCommonsGlobals.SUCCESS_STATUS_TEXT;
    }

    public static CommonResult InsertIntoMSMQ(string QueuePath, Object obj)
    {
        CommonResult result = new CommonResult();
        try
        {
            MessageQueue queue = CreateQueueIfNotExists(QueuePath);
            Message msg = new Message();
            msg.Body = obj;
            msg.Recoverable = true;
            queue.Send(msg);
            result.StatusCode = SharedCommonsGlobals.SUCCESS_STATUS_CODE;
            result.StatusDesc = SharedCommonsGlobals.SUCCESS_STATUS_TEXT;
            result.ResponseId = msg.Id;
        }
        catch (Exception ex)
        {
            result.StatusCode = SharedCommonsGlobals.FAILURE_STATUS_CODE;
            result.StatusDesc = ex.Message;
        }
        return result;
    }

    public static Message PeekCopyOfTopItemFromMSMQ(string QueuePath, Type T)
    {
        try
        {
            MessageQueue msMq = CreateQueueIfNotExists(QueuePath);
            Message msg = new Message();
            msg = msMq.Peek();
            if (T != null) { msg.Formatter = new XmlMessageFormatter(new Type[] { T }); };
            return msg;
        }
        catch (Exception ex)
        {
            return null;
        }
    }

    public static Message PeekCopyOfTopItemFromMSMQByID(string QueuePath, Type T,string Id)
    {
        try
        {
            MessageQueue msMq = CreateQueueIfNotExists(QueuePath);
            Message msg = new Message();
            msg = msMq.PeekById(Id);
            if (T != null) { msg.Formatter = new XmlMessageFormatter(new Type[] { T }); };
            return msg;
        }
        catch (Exception ex)
        {
            return null;
        }
    }

    public static Message RemoveTopMostItemFromMSMQ(string QueuePath, Type T)
    {
        try
        {
            MessageQueue msMq = CreateQueueIfNotExists(QueuePath);
            Message msg = new Message();
            if (T != null) { msg.Formatter = new XmlMessageFormatter(new Type[] { T }); };
            msg = msMq.Receive();
            return msg;
        }
        catch (Exception)
        {
            return null;
        }
    }

    public static Message RemoveTopItemFromMSMQByID(string QueuePath, Type T, string Id)
    {
        try
        {
            MessageQueue msMq = CreateQueueIfNotExists(QueuePath);
            Message msg = new Message();
            msg = msMq.ReceiveById(Id);
            if (T != null) { msg.Formatter = new XmlMessageFormatter(new Type[] { T }); };
            return null;
        }
        catch (Exception ex)
        {
            return null;
        }
    }

    private static MessageQueue CreateQueueIfNotExists(string queuePath)
    {
        if (MessageQueue.Exists(queuePath))
        {
            return new MessageQueue(queuePath);
        }
        return MessageQueue.Create(queuePath);
    }

    public static CommonResult TransferItemToOtherMSMQ(string SourceQueuePath,string DestQueuePath, string Id)
    {
        CommonResult result = new CommonResult();
        try
        {
            Message msg = PeekCopyOfTopItemFromMSMQByID(SourceQueuePath, null, Id);
            result = InsertIntoMSMQ(DestQueuePath, msg);

            if (result.StatusCode != SharedCommonsGlobals.SUCCESS_STATUS_CODE)
            {
                return result;
            }

            msg = RemoveTopItemFromMSMQByID(SourceQueuePath, null, msg.Id);

            if (msg == null)
            {
                result.StatusCode = SharedCommonsGlobals.FAILURE_STATUS_CODE;
                result.StatusDesc = "TRANSFER STATUS: SUCCESS, REMOVE FROM OLD QUEUE STATUS: FAILED";
                return result;
            }

            result.StatusCode = SharedCommonsGlobals.SUCCESS_STATUS_CODE;
            result.StatusDesc = SharedCommonsGlobals.SUCCESS_STATUS_TEXT;
            result.ResponseId = msg.Id;
            return result;
        }
        catch (Exception ex)
        {
            result.StatusCode = SharedCommonsGlobals.FAILURE_STATUS_CODE;
            result.StatusDesc = ex.Message;
        }
        return result;
    }

    public static CommonResult SkipTopItemInMSMQ(string QueuePath, Type T)
    {
        CommonResult result = new CommonResult();
        try
        {
            Message msg = PeekCopyOfTopItemFromMSMQ(QueuePath, T);

            if (msg == null)
            {
                result.StatusCode = SharedCommonsGlobals.FAILURE_STATUS_CODE;
                result.StatusDesc = "RE-INSERT STATUS: FAILED, REMOVE STATUS: FAILED";
                return result;
            }

            result = InsertIntoMSMQ(QueuePath, msg);

            if (result.StatusCode != SharedCommonsGlobals.SUCCESS_STATUS_CODE)
            {
                return result;
            }

            msg = RemoveTopItemFromMSMQByID(QueuePath, T, msg.Id);

            if (msg == null)
            {
                result.StatusCode = SharedCommonsGlobals.FAILURE_STATUS_CODE;
                result.StatusDesc = "RE-INSERT STATUS: SUCCESS, REMOVE STATUS: FAILED";
                return result;
            }

            result.StatusCode = SharedCommonsGlobals.SUCCESS_STATUS_CODE;
            result.StatusDesc = SharedCommonsGlobals.SUCCESS_STATUS_TEXT;
            result.ResponseId = msg.Id;
            return result;
        }
        catch (Exception ex)
        {
            result.StatusCode = SharedCommonsGlobals.FAILURE_STATUS_CODE;
            result.StatusDesc = ex.Message;
        }
        return result;
    }

    public static CommonResult SkipTopItemInMSMQByID(string QueuePath, Type T,string Id)
    {
        CommonResult result = new CommonResult();
        try
        {
            Message msg = PeekCopyOfTopItemFromMSMQByID(QueuePath, T,Id);

            if (msg == null)
            {
                result.StatusCode = SharedCommonsGlobals.FAILURE_STATUS_CODE;
                result.StatusDesc = "RE-INSERT STATUS: FAILED, REMOVE STATUS: FAILED";
                return result;
            }

            result = InsertIntoMSMQ(QueuePath, msg);

            if (result.StatusCode != SharedCommonsGlobals.SUCCESS_STATUS_CODE)
            {
                return result;
            }

            msg = RemoveTopItemFromMSMQByID(QueuePath, T, msg.Id);

            if (msg == null)
            {
                result.StatusCode = SharedCommonsGlobals.FAILURE_STATUS_CODE;
                result.StatusDesc = "RE-INSERT STATUS: SUCCESS, REMOVE STATUS: FAILED";
                return result;
            }

            result.StatusCode = SharedCommonsGlobals.SUCCESS_STATUS_CODE;
            result.StatusDesc = SharedCommonsGlobals.SUCCESS_STATUS_TEXT;
            result.ResponseId = msg.Id;
            return result;
        }
        catch (Exception ex)
        {
            result.StatusCode = SharedCommonsGlobals.FAILURE_STATUS_CODE;
            result.StatusDesc = ex.Message;
        }
        return result;
    }

    public static bool IsNumeric(string Amount)
    {
        try
        {
            Amount = SanitizeNumericInput(Amount);
            int amount = int.Parse(Amount);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static string SanitizeNumericInput(string Amount)
    {
        try
        {
            Amount = Amount.Trim();
            if (string.IsNullOrEmpty(Amount))
            {
                Amount = "0";
            }
            Amount = Amount.Replace(",", string.Empty);
            Amount = Amount.Split('.')[0];

            return Amount;
        }
        catch (Exception)
        {
            return Amount;
        }
    }

    public static bool IsNumericAndAboveZero(string Amount)
    {
        try
        {
            Amount = Amount.Replace(",", string.Empty);
            int amount = int.Parse(Amount.Split('.')[0]);
            if (amount <= 0)
            {
                return false;
            }
            else
            {
                return true;
            }
        }
        catch (Exception ex)
        {
            return false;
        }
    }

    public static bool IsValidBoolean(string p)
    {
        if (String.IsNullOrEmpty(p))
        {
            return false;
        }
        else if (p.ToUpper() == "TRUE" || p.ToUpper() == "FALSE")
        {
            return true;
        }

        return false;
    }

    public static bool IsValidEmail(string email)
    {
        try
        {
            if (email == "N/A") { return true; }
            System.Net.Mail.MailAddress addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }

    public static string ByteArrayToString(byte[] ba)
    {
        StringBuilder hex = new StringBuilder(ba.Length * 2);
        foreach (byte b in ba)
            hex.AppendFormat("{0:x2}", b);
        return hex.ToString();
    }
}

