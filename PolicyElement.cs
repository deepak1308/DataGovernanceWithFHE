namespace SEALDemo
{
    using System.Collections.Generic;

    class PolicyElement
    {
        public string name { get; set; }
        public string id { get; set; }
        public string description { get; set; }
        public int version { get; set; }
        public List<DecisionRule> decisionRules { get; set; }
    }

    class DecisionRule
    {
        public string kind { get; set; }
        public string effect { get; set; }
        public string id { get; set; }
        public string updatedAt { get; set; }
        public List<List<AttributeMatcher>> cnfCondition { get; set; }
    }

    class AttributeMatcher
    {
        public string attributeName { get; set; }
        public List<string> attributeValueIncludedIn { get; set; }
    }
}
