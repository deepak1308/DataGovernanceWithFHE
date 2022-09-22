namespace SEALDemo
{
    using System;
    using System.IO;
    using System.Text.Json;

    class PolicyJsonParser
    {
        private static JsonSerializerOptions options = new JsonSerializerOptions()
        {
            IgnoreNullValues = true,
            WriteIndented = true,
        };

        public static ResourceAttribute ReadResourceAttribute(string file)
        {
            try
            {
                string jsonString = File.ReadAllText(file);
                ResourceAttribute attribute =
                    JsonSerializer.Deserialize<ResourceAttribute>(jsonString);
                return attribute;
            }
            catch (Exception ex)
            {
                Console.WriteLine("File now found: " + file);
                throw ex;
            }
        }

        public static PolicyElement ReadPolicyElement(string file)
        {
            try
            {
                string jsonString = File.ReadAllText(file);
                PolicyElement policyElement =
                    JsonSerializer.Deserialize<PolicyElement>(jsonString, options);
                return policyElement;
            }
            catch (Exception ex)
            {
                Console.WriteLine("File now found: " + file);
                throw ex;
            }            
        }

        public static void WritePolicyElement(PolicyElement policyElement, string file)
        {
            try
            {
                string jsonString = JsonSerializer.Serialize(policyElement, options);
                File.WriteAllText(file, jsonString);
            }
            catch (Exception ex)
            {
                Console.WriteLine("File now found: " + file);
                throw ex;
            }            
        }
    }
}
