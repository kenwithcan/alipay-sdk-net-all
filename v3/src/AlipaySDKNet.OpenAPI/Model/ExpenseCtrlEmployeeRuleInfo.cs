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
    /// ExpenseCtrlEmployeeRuleInfo
    /// </summary>
    [DataContract(Name = "ExpenseCtrlEmployeeRuleInfo")]
    public partial class ExpenseCtrlEmployeeRuleInfo : IEquatable<ExpenseCtrlEmployeeRuleInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ExpenseCtrlEmployeeRuleInfo" /> class.
        /// </summary>
        /// <param name="effective">费控规则状态，1表示有效，0表示无效.</param>
        /// <param name="effectiveEndDate">费控规则有效期截止.</param>
        /// <param name="effectiveStartDate">费控规则有效期起始.</param>
        /// <param name="ownerType">费控规则作用范围， EMPLOYEE表示员工，ENTERPRISE表示企业.</param>
        /// <param name="standardId">费控规则ID.</param>
        /// <param name="standardName">费控规则名称.</param>
        public ExpenseCtrlEmployeeRuleInfo(int effective = default(int), string effectiveEndDate = default(string), string effectiveStartDate = default(string), string ownerType = default(string), string standardId = default(string), string standardName = default(string))
        {
            this.Effective = effective;
            this.EffectiveEndDate = effectiveEndDate;
            this.EffectiveStartDate = effectiveStartDate;
            this.OwnerType = ownerType;
            this.StandardId = standardId;
            this.StandardName = standardName;
        }

        /// <summary>
        /// 费控规则状态，1表示有效，0表示无效
        /// </summary>
        /// <value>费控规则状态，1表示有效，0表示无效</value>
        [DataMember(Name = "effective", EmitDefaultValue = false)]
        public int Effective { get; set; }

        /// <summary>
        /// 费控规则有效期截止
        /// </summary>
        /// <value>费控规则有效期截止</value>
        [DataMember(Name = "effective_end_date", EmitDefaultValue = false)]
        public string EffectiveEndDate { get; set; }

        /// <summary>
        /// 费控规则有效期起始
        /// </summary>
        /// <value>费控规则有效期起始</value>
        [DataMember(Name = "effective_start_date", EmitDefaultValue = false)]
        public string EffectiveStartDate { get; set; }

        /// <summary>
        /// 费控规则作用范围， EMPLOYEE表示员工，ENTERPRISE表示企业
        /// </summary>
        /// <value>费控规则作用范围， EMPLOYEE表示员工，ENTERPRISE表示企业</value>
        [DataMember(Name = "owner_type", EmitDefaultValue = false)]
        public string OwnerType { get; set; }

        /// <summary>
        /// 费控规则ID
        /// </summary>
        /// <value>费控规则ID</value>
        [DataMember(Name = "standard_id", EmitDefaultValue = false)]
        public string StandardId { get; set; }

        /// <summary>
        /// 费控规则名称
        /// </summary>
        /// <value>费控规则名称</value>
        [DataMember(Name = "standard_name", EmitDefaultValue = false)]
        public string StandardName { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ExpenseCtrlEmployeeRuleInfo {\n");
            sb.Append("  Effective: ").Append(Effective).Append("\n");
            sb.Append("  EffectiveEndDate: ").Append(EffectiveEndDate).Append("\n");
            sb.Append("  EffectiveStartDate: ").Append(EffectiveStartDate).Append("\n");
            sb.Append("  OwnerType: ").Append(OwnerType).Append("\n");
            sb.Append("  StandardId: ").Append(StandardId).Append("\n");
            sb.Append("  StandardName: ").Append(StandardName).Append("\n");
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
            return this.Equals(input as ExpenseCtrlEmployeeRuleInfo);
        }

        /// <summary>
        /// Returns true if ExpenseCtrlEmployeeRuleInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of ExpenseCtrlEmployeeRuleInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ExpenseCtrlEmployeeRuleInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Effective == input.Effective ||
                    this.Effective.Equals(input.Effective)
                ) && 
                (
                    this.EffectiveEndDate == input.EffectiveEndDate ||
                    (this.EffectiveEndDate != null &&
                    this.EffectiveEndDate.Equals(input.EffectiveEndDate))
                ) && 
                (
                    this.EffectiveStartDate == input.EffectiveStartDate ||
                    (this.EffectiveStartDate != null &&
                    this.EffectiveStartDate.Equals(input.EffectiveStartDate))
                ) && 
                (
                    this.OwnerType == input.OwnerType ||
                    (this.OwnerType != null &&
                    this.OwnerType.Equals(input.OwnerType))
                ) && 
                (
                    this.StandardId == input.StandardId ||
                    (this.StandardId != null &&
                    this.StandardId.Equals(input.StandardId))
                ) && 
                (
                    this.StandardName == input.StandardName ||
                    (this.StandardName != null &&
                    this.StandardName.Equals(input.StandardName))
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
                hashCode = (hashCode * 59) + this.Effective.GetHashCode();
                if (this.EffectiveEndDate != null)
                {
                    hashCode = (hashCode * 59) + this.EffectiveEndDate.GetHashCode();
                }
                if (this.EffectiveStartDate != null)
                {
                    hashCode = (hashCode * 59) + this.EffectiveStartDate.GetHashCode();
                }
                if (this.OwnerType != null)
                {
                    hashCode = (hashCode * 59) + this.OwnerType.GetHashCode();
                }
                if (this.StandardId != null)
                {
                    hashCode = (hashCode * 59) + this.StandardId.GetHashCode();
                }
                if (this.StandardName != null)
                {
                    hashCode = (hashCode * 59) + this.StandardName.GetHashCode();
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
