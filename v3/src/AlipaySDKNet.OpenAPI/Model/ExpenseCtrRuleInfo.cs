/*
 * 支付宝开放平台API
 *
 * 支付宝开放平台v3协议文档
 *
 * The version of the OpenAPI document: 2025-02-19
 * Generated by: https://github.com/openapitools/openapi-generator.git
 */


using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System.ComponentModel.DataAnnotations;
using OpenAPIDateConverter = AlipaySDKNet.OpenAPI.Client.OpenAPIDateConverter;

namespace AlipaySDKNet.OpenAPI.Model
{
    /// <summary>
    /// ExpenseCtrRuleInfo
    /// </summary>
    [DataContract(Name = "ExpenseCtrRuleInfo")]
    public partial class ExpenseCtrRuleInfo : IEquatable<ExpenseCtrRuleInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ExpenseCtrRuleInfo" /> class.
        /// </summary>
        /// <param name="ruleFactor">费控维度.</param>
        /// <param name="ruleId">费控条件ID.</param>
        /// <param name="ruleName">费控条件名称.</param>
        /// <param name="ruleOperator">费控条件操作符 枚举值： LT(\&quot;&lt;\&quot;,\&quot;小于\&quot;) LE(\&quot;&lt;&#x3D;\&quot;,\&quot;小于等于\&quot;) EQ(\&quot;&#x3D;\&quot;,\&quot;等于\&quot;) NE(\&quot;!&#x3D;\&quot;,\&quot;不等于\&quot;) GE(\&quot;&gt;&#x3D;\&quot;,\&quot;大于等于\&quot;) GT(\&quot;&gt;\&quot;,\&quot;大于\&quot;).</param>
        /// <param name="ruleValue">费控条件值.</param>
        public ExpenseCtrRuleInfo(string ruleFactor = default(string), string ruleId = default(string), string ruleName = default(string), string ruleOperator = default(string), string ruleValue = default(string))
        {
            this.RuleFactor = ruleFactor;
            this.RuleId = ruleId;
            this.RuleName = ruleName;
            this.RuleOperator = ruleOperator;
            this.RuleValue = ruleValue;
        }

        /// <summary>
        /// 费控维度
        /// </summary>
        /// <value>费控维度</value>
        [DataMember(Name = "rule_factor", EmitDefaultValue = false)]
        public string RuleFactor { get; set; }

        /// <summary>
        /// 费控条件ID
        /// </summary>
        /// <value>费控条件ID</value>
        [DataMember(Name = "rule_id", EmitDefaultValue = false)]
        public string RuleId { get; set; }

        /// <summary>
        /// 费控条件名称
        /// </summary>
        /// <value>费控条件名称</value>
        [DataMember(Name = "rule_name", EmitDefaultValue = false)]
        public string RuleName { get; set; }

        /// <summary>
        /// 费控条件操作符 枚举值： LT(\&quot;&lt;\&quot;,\&quot;小于\&quot;) LE(\&quot;&lt;&#x3D;\&quot;,\&quot;小于等于\&quot;) EQ(\&quot;&#x3D;\&quot;,\&quot;等于\&quot;) NE(\&quot;!&#x3D;\&quot;,\&quot;不等于\&quot;) GE(\&quot;&gt;&#x3D;\&quot;,\&quot;大于等于\&quot;) GT(\&quot;&gt;\&quot;,\&quot;大于\&quot;)
        /// </summary>
        /// <value>费控条件操作符 枚举值： LT(\&quot;&lt;\&quot;,\&quot;小于\&quot;) LE(\&quot;&lt;&#x3D;\&quot;,\&quot;小于等于\&quot;) EQ(\&quot;&#x3D;\&quot;,\&quot;等于\&quot;) NE(\&quot;!&#x3D;\&quot;,\&quot;不等于\&quot;) GE(\&quot;&gt;&#x3D;\&quot;,\&quot;大于等于\&quot;) GT(\&quot;&gt;\&quot;,\&quot;大于\&quot;)</value>
        [DataMember(Name = "rule_operator", EmitDefaultValue = false)]
        public string RuleOperator { get; set; }

        /// <summary>
        /// 费控条件值
        /// </summary>
        /// <value>费控条件值</value>
        [DataMember(Name = "rule_value", EmitDefaultValue = false)]
        public string RuleValue { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ExpenseCtrRuleInfo {\n");
            sb.Append("  RuleFactor: ").Append(RuleFactor).Append("\n");
            sb.Append("  RuleId: ").Append(RuleId).Append("\n");
            sb.Append("  RuleName: ").Append(RuleName).Append("\n");
            sb.Append("  RuleOperator: ").Append(RuleOperator).Append("\n");
            sb.Append("  RuleValue: ").Append(RuleValue).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public virtual string ToJson()
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(this, Newtonsoft.Json.Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="input">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object input)
        {
            return this.Equals(input as ExpenseCtrRuleInfo);
        }

        /// <summary>
        /// Returns true if ExpenseCtrRuleInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of ExpenseCtrRuleInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ExpenseCtrRuleInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.RuleFactor == input.RuleFactor ||
                    (this.RuleFactor != null &&
                    this.RuleFactor.Equals(input.RuleFactor))
                ) && 
                (
                    this.RuleId == input.RuleId ||
                    (this.RuleId != null &&
                    this.RuleId.Equals(input.RuleId))
                ) && 
                (
                    this.RuleName == input.RuleName ||
                    (this.RuleName != null &&
                    this.RuleName.Equals(input.RuleName))
                ) && 
                (
                    this.RuleOperator == input.RuleOperator ||
                    (this.RuleOperator != null &&
                    this.RuleOperator.Equals(input.RuleOperator))
                ) && 
                (
                    this.RuleValue == input.RuleValue ||
                    (this.RuleValue != null &&
                    this.RuleValue.Equals(input.RuleValue))
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                int hashCode = 41;
                if (this.RuleFactor != null)
                {
                    hashCode = (hashCode * 59) + this.RuleFactor.GetHashCode();
                }
                if (this.RuleId != null)
                {
                    hashCode = (hashCode * 59) + this.RuleId.GetHashCode();
                }
                if (this.RuleName != null)
                {
                    hashCode = (hashCode * 59) + this.RuleName.GetHashCode();
                }
                if (this.RuleOperator != null)
                {
                    hashCode = (hashCode * 59) + this.RuleOperator.GetHashCode();
                }
                if (this.RuleValue != null)
                {
                    hashCode = (hashCode * 59) + this.RuleValue.GetHashCode();
                }
                return hashCode;
            }
        }

        /// <summary>
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        public IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

}
