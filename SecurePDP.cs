namespace SEALDemo
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;

    class SecurePDP
    {
        string path = @"TestData\";
        Dictionary<string, List<string>> policies = new Dictionary<string, List<string>>();

        public static bool verbose = true;

        void TestSealString(SEALStringOperations sseal)
        {
            sseal.StoreCiphertext("abcd");
            sseal.StoreCiphertext("abc");
            sseal.StoreCiphertext("acd");
            sseal.StoreCiphertext("/a/b/**");
            Console.WriteLine(sseal.CompareString("Ciphertext_1", "abcd", false));
            Console.WriteLine(sseal.CompareString("Ciphertext_1", "xyz", false));
            Console.WriteLine(sseal.CompareString("Ciphertext_1", "abc", true));
            Console.WriteLine(sseal.CompareString("Ciphertext_1", "bcd", true));
            Console.WriteLine(sseal.SubstringMatch("Ciphertext_1", "bc"));
            Console.WriteLine(sseal.SubstringMatch("Ciphertext_1", "bd"));
            Console.WriteLine(sseal.InputStartsWithPattern("Ciphertext_4", "/a/b/c/d"));
            Console.WriteLine(sseal.InputStartsWithPattern("Ciphertext_4", "/b/c/d"));
        }

        void PrintVerbose(string uid, string input, int op = 0, bool result = false)
        {
            if(!verbose)
            {
                return;
            }

            Console.WriteLine();

            if (op==1)
            {
                Console.WriteLine($"Performing exact match between UID: {uid} and input: {input} , result: {result}");
            }
            else if (op==2)
            {
                Console.WriteLine($"Performing regex match between UID: {uid} and input: {input} , result: {result}");
            }
            else if (op==3)
            {
                Console.WriteLine($"Performing substring match between UID: {uid} and input: {input} , result: {result}");
            }
            else
            {
                Console.WriteLine($"Storing attribute: {input} with UID: {uid}");
            }
        }

        void ProcessPolicyElement(PolicyElement policy, SEALStringOperations sseal)
        {
            string resource=null, action=null, user=null;
            List<string> uids = new List<string>();
            string uid = null;

            policy.decisionRules.ForEach(rule => {
                rule.cnfCondition.ForEach(attributes => {
                    attributes.ForEach(attribute => {
                        if (attribute.attributeName.Equals("resource.azure.path"))
                        {
                            resource = attribute.attributeValueIncludedIn[0];
                            uid = sseal.StoreCiphertext(resource);
                        }
                        else if (attribute.attributeName.Equals("principal.microsoft.id"))
                        {
                            user = attribute.attributeValueIncludedIn[0];
                            uid = sseal.StoreCiphertext(user);
                        }                            
                        else if (attribute.attributeName.Equals("resource.azure.dataAction"))
                        {
                            action = attribute.attributeValueIncludedIn[0];
                            uid = sseal.StoreCiphertext(action);
                        }

                        PrintVerbose(uid, attribute.attributeValueIncludedIn[0]);
                        attribute.attributeValueIncludedIn[0] = uid;                        
                        if (!uids.Contains(uid))
                        {
                            uids.Add(uid);
                        }
                    });
                });
            });

            if(!policies.ContainsKey(policy.name))
            {
                policies.Add(policy.name, uids);
            }
        }

        void CheckAccess(ResourceAttribute resourceAttribute, SEALStringOperations sseal)
        {
            string resource = null, action = null, user = null;
            resourceAttribute.attributes.ForEach(attribute => {
                if (attribute.attributeName.Equals("resource.azure.path"))
                {
                    resource = attribute.attributeValueIncludes;
                }
                else if (attribute.attributeName.Equals("principal.microsoft.id"))
                {
                    user = attribute.attributeValueIncludes;
                }
                else if (attribute.attributeName.Equals("resource.azure.dataAction"))
                {
                    action = attribute.attributeValueIncludes;
                }
            });

            bool matched, decision = true;
            bool noEffect = true;
            foreach (var file in policies.Keys)
            {
                PolicyElement policy =
                        PolicyJsonParser.ReadPolicyElement(path + "encr_" + file + ".json");

                if (verbose)
                {
                    Console.WriteLine("----------------------------------------");
                    Console.WriteLine($"Matching with encrypted policy: {file} ");
                    Console.WriteLine("----------------------------------------");
                }

                policy.decisionRules.ForEach(rule => {
                    Console.WriteLine("----------------------------------------");
                    Console.WriteLine($"Matching with rule ID: {rule.id} ");
                    Console.WriteLine("----------------------------------------");
                    matched = true;
                    rule.cnfCondition.ForEach(attributes => {
                        attributes.ForEach(attribute => {
                            if (matched &&
                                attribute.attributeName.Equals("resource.azure.path"))
                            {
                                bool exactMatch =
                                    sseal.CompareString(attribute.attributeValueIncludedIn[0], resource, false);
                                bool regexMatch = exactMatch ||
                                    sseal.InputStartsWithPattern(attribute.attributeValueIncludedIn[0], resource);

                                PrintVerbose(attribute.attributeValueIncludedIn[0], resource, 1, exactMatch);
                                if (!exactMatch) {
                                    PrintVerbose(attribute.attributeValueIncludedIn[0], resource, 2, regexMatch);
                                }
                                matched = matched && ( exactMatch || regexMatch );
                            }
                            else if (matched &&
                                    attribute.attributeName.Equals("principal.microsoft.id"))
                            {
                                bool exactMatch =
                                    sseal.CompareString(attribute.attributeValueIncludedIn[0], user, false);

                                PrintVerbose(attribute.attributeValueIncludedIn[0], user, 1, exactMatch);
                                matched = matched && exactMatch;
                            }
                            else if (matched &&
                                    attribute.attributeName.Equals("resource.azure.dataAction"))
                            {
                                bool exactMatch =
                                    sseal.CompareString(attribute.attributeValueIncludedIn[0], action, false);

                                PrintVerbose(attribute.attributeValueIncludedIn[0], action, 1, exactMatch);
                                matched = matched && exactMatch;
                            }
                        });
                    });
                    if(matched)
                    {
                        if (verbose)
                        {
                            Console.WriteLine($"Rule with ID: {rule.id} matched.");
                        }
                        
                        decision = decision && (rule.effect.Equals("Permit"));
                        noEffect = false;
                    }
                });
            }

            Console.WriteLine($"Final decision: " + (noEffect ? "Not Applicable" : (decision ? "Permit" : "Deny")));
        }

        void GetPoliciesWithResource(string resource, SEALStringOperations sseal)
        {
            foreach (var name in policies.Keys)
            {
                if (verbose)
                {
                    Console.WriteLine("----------------------------------------");
                    Console.WriteLine($"Matching with policy: {name} attributes.");
                    Console.WriteLine("----------------------------------------");
                }

                foreach (var uid in policies[name])
                {
                    bool result = sseal.SubstringMatch(uid, resource);
                    PrintVerbose(uid, resource, 3, result);
                    if (result)
                    {
                        if (verbose)
                        {
                            Console.WriteLine($"Matched policy: {name}");
                        }
                        break;
                    }
                }
            }
        }

        static void Main(string[] args)
        {
            SEALStringOperations sseal = new SEALStringOperations();
            sseal.InitParams();

            SecurePDP spdp = new SecurePDP();

            //TestSealString(sseal);

            //Console.WriteLine(SEALNumberOperations.AreEqual(15, 15));

            Console.WriteLine("------------------------------------------");
            Console.WriteLine("----------------Secure PDP----------------");
            Console.WriteLine("------------------------------------------");

            int ip = 0;
            Stopwatch sw = new Stopwatch();
            do
            {
                Console.WriteLine("Enter option: ");
                Console.WriteLine("1. Encrypt policy");
                Console.WriteLine("2. Get policy");
                Console.WriteLine("3. Get attribute");
                Console.WriteLine("4. Check access");
                Console.WriteLine("5. Get policies with resource substring");
                Console.WriteLine("0. Exit");

                try
                {
                    ip = Convert.ToInt32(Console.ReadLine());

                    if (ip == 1)
                    {
                        Console.WriteLine("Enter policy name: ");
                        string file = Console.ReadLine();
                        PolicyElement policyElement =
                            PolicyJsonParser.ReadPolicyElement(spdp.path + file + ".json");

                        sw.Restart();
                        spdp.ProcessPolicyElement(policyElement, sseal);
                        sw.Stop();
                        Console.WriteLine("Elapsed time in ms: " + sw.ElapsedMilliseconds);

                        PolicyJsonParser.WritePolicyElement(policyElement, spdp.path + "encr_" + file + ".json");
                    }
                    else if (ip == 2)
                    {
                        Console.WriteLine("Enter policy name: ");
                        string file = Console.ReadLine();

                        sw.Restart();
                        Console.WriteLine(File.ReadAllText(spdp.path + "encr_" + file + ".json"));
                        sw.Stop();
                        Console.WriteLine("Elapsed time in ms: " + sw.ElapsedMilliseconds);
                    }
                    else if (ip == 3)
                    {
                        Console.WriteLine("Enter attribute name: ");
                        string file = Console.ReadLine();

                        sw.Restart();
                        Console.WriteLine(File.ReadAllText(spdp.path + file + ".json"));
                        sw.Stop();
                        Console.WriteLine("Elapsed time in ms: " + sw.ElapsedMilliseconds);
                    }
                    else if (ip == 4)
                    {
                        Console.WriteLine("Enter attribute name: ");
                        string file = Console.ReadLine();
                        ResourceAttribute attribute =
                            PolicyJsonParser.ReadResourceAttribute(spdp.path + file + ".json");

                        sw.Restart();
                        spdp.CheckAccess(attribute, sseal);
                        sw.Stop();
                        Console.WriteLine("Elapsed time in ms: " + sw.ElapsedMilliseconds);
                    }
                    else if (ip == 5)
                    {
                        Console.WriteLine("Enter resource substring: ");
                        string resource = Console.ReadLine();

                        sw.Restart();
                        spdp.GetPoliciesWithResource(resource, sseal);
                        sw.Stop();
                        Console.WriteLine("Elapsed time in ms: " + sw.ElapsedMilliseconds);
                    }
                    else
                    {
                        for (int i = 1; i <= 3; i++)
                        {
                            PolicyElement policyElement =
                                PolicyJsonParser.ReadPolicyElement(spdp.path + "policy" + i + ".json");
                            PolicyJsonParser.WritePolicyElement(policyElement, spdp.path + "encr_" + "policy" + i + ".json");
                        }
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine("Failed to process input");
                }
            } while (ip >= 1 && ip <=5);
        }
    }
}
