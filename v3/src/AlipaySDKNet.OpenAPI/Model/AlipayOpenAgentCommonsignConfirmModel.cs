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
    /// AlipayOpenAgentCommonsignConfirmModel
    /// </summary>
    [DataContract(Name = "AlipayOpenAgentCommonsignConfirmModel")]
    public partial class AlipayOpenAgentCommonsignConfirmModel : IEquatable<AlipayOpenAgentCommonsignConfirmModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenAgentCommonsignConfirmModel" /> class.
        /// </summary>
        /// <param name="batchNo">ISV 代商户操作事务编号，通过事务开启接口alipay.open.agent.create调用返回。.</param>
        public AlipayOpenAgentCommonsignConfirmModel(string batchNo = default(string))
        {
            this.BatchNo = batchNo;
        }

        /// <summary>
        /// ISV 代商户操作事务编号，通过事务开启接口alipay.open.agent.create调用返回。
        /// </summary>
        /// <value>ISV 代商户操作事务编号，通过事务开启接口alipay.open.agent.create调用返回。</value>
        [DataMember(Name = "batch_no", EmitDefaultValue = false)]
        public string BatchNo { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenAgentCommonsignConfirmModel {\n");
            sb.Append("  BatchNo: ").Append(BatchNo).Append("\n");
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
            return this.Equals(input as AlipayOpenAgentCommonsignConfirmModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenAgentCommonsignConfirmModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenAgentCommonsignConfirmModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenAgentCommonsignConfirmModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.BatchNo == input.BatchNo ||
                    (this.BatchNo != null &&
                    this.BatchNo.Equals(input.BatchNo))
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
                if (this.BatchNo != null)
                {
                    hashCode = (hashCode * 59) + this.BatchNo.GetHashCode();
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
