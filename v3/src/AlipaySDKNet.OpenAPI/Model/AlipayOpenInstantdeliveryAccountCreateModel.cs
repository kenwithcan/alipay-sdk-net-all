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
    /// AlipayOpenInstantdeliveryAccountCreateModel
    /// </summary>
    [DataContract(Name = "AlipayOpenInstantdeliveryAccountCreateModel")]
    public partial class AlipayOpenInstantdeliveryAccountCreateModel : IEquatable<AlipayOpenInstantdeliveryAccountCreateModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenInstantdeliveryAccountCreateModel" /> class.
        /// </summary>
        /// <param name="logisticsCodes">配送公司编码.</param>
        /// <param name="outBizNo">外部业务号.</param>
        public AlipayOpenInstantdeliveryAccountCreateModel(List<string> logisticsCodes = default(List<string>), string outBizNo = default(string))
        {
            this.LogisticsCodes = logisticsCodes;
            this.OutBizNo = outBizNo;
        }

        /// <summary>
        /// 配送公司编码
        /// </summary>
        /// <value>配送公司编码</value>
        [DataMember(Name = "logistics_codes", EmitDefaultValue = false)]
        public List<string> LogisticsCodes { get; set; }

        /// <summary>
        /// 外部业务号
        /// </summary>
        /// <value>外部业务号</value>
        [DataMember(Name = "out_biz_no", EmitDefaultValue = false)]
        public string OutBizNo { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenInstantdeliveryAccountCreateModel {\n");
            sb.Append("  LogisticsCodes: ").Append(LogisticsCodes).Append("\n");
            sb.Append("  OutBizNo: ").Append(OutBizNo).Append("\n");
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
            return this.Equals(input as AlipayOpenInstantdeliveryAccountCreateModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenInstantdeliveryAccountCreateModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenInstantdeliveryAccountCreateModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenInstantdeliveryAccountCreateModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.LogisticsCodes == input.LogisticsCodes ||
                    this.LogisticsCodes != null &&
                    input.LogisticsCodes != null &&
                    this.LogisticsCodes.SequenceEqual(input.LogisticsCodes)
                ) && 
                (
                    this.OutBizNo == input.OutBizNo ||
                    (this.OutBizNo != null &&
                    this.OutBizNo.Equals(input.OutBizNo))
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
                if (this.LogisticsCodes != null)
                {
                    hashCode = (hashCode * 59) + this.LogisticsCodes.GetHashCode();
                }
                if (this.OutBizNo != null)
                {
                    hashCode = (hashCode * 59) + this.OutBizNo.GetHashCode();
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
