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
    /// InvoiceComplianceCheckResult
    /// </summary>
    [DataContract(Name = "InvoiceComplianceCheckResult")]
    public partial class InvoiceComplianceCheckResult : IEquatable<InvoiceComplianceCheckResult>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InvoiceComplianceCheckResult" /> class.
        /// </summary>
        /// <param name="matchResultType">发票和账单匹配的合规检查结果： 0 - 模糊匹配 1 - 精准匹配.</param>
        public InvoiceComplianceCheckResult(string matchResultType = default(string))
        {
            this.MatchResultType = matchResultType;
        }

        /// <summary>
        /// 发票和账单匹配的合规检查结果： 0 - 模糊匹配 1 - 精准匹配
        /// </summary>
        /// <value>发票和账单匹配的合规检查结果： 0 - 模糊匹配 1 - 精准匹配</value>
        [DataMember(Name = "match_result_type", EmitDefaultValue = false)]
        public string MatchResultType { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class InvoiceComplianceCheckResult {\n");
            sb.Append("  MatchResultType: ").Append(MatchResultType).Append("\n");
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
            return this.Equals(input as InvoiceComplianceCheckResult);
        }

        /// <summary>
        /// Returns true if InvoiceComplianceCheckResult instances are equal
        /// </summary>
        /// <param name="input">Instance of InvoiceComplianceCheckResult to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(InvoiceComplianceCheckResult input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.MatchResultType == input.MatchResultType ||
                    (this.MatchResultType != null &&
                    this.MatchResultType.Equals(input.MatchResultType))
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
                if (this.MatchResultType != null)
                {
                    hashCode = (hashCode * 59) + this.MatchResultType.GetHashCode();
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
