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
    /// ContributeDetail
    /// </summary>
    [DataContract(Name = "ContributeDetail")]
    public partial class ContributeDetail : IEquatable<ContributeDetail>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ContributeDetail" /> class.
        /// </summary>
        /// <param name="contributeAmount">出资方金额.</param>
        /// <param name="contributeType">出资方类型.</param>
        public ContributeDetail(string contributeAmount = default(string), string contributeType = default(string))
        {
            this.ContributeAmount = contributeAmount;
            this.ContributeType = contributeType;
        }

        /// <summary>
        /// 出资方金额
        /// </summary>
        /// <value>出资方金额</value>
        [DataMember(Name = "contribute_amount", EmitDefaultValue = false)]
        public string ContributeAmount { get; set; }

        /// <summary>
        /// 出资方类型
        /// </summary>
        /// <value>出资方类型</value>
        [DataMember(Name = "contribute_type", EmitDefaultValue = false)]
        public string ContributeType { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ContributeDetail {\n");
            sb.Append("  ContributeAmount: ").Append(ContributeAmount).Append("\n");
            sb.Append("  ContributeType: ").Append(ContributeType).Append("\n");
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
            return this.Equals(input as ContributeDetail);
        }

        /// <summary>
        /// Returns true if ContributeDetail instances are equal
        /// </summary>
        /// <param name="input">Instance of ContributeDetail to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ContributeDetail input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ContributeAmount == input.ContributeAmount ||
                    (this.ContributeAmount != null &&
                    this.ContributeAmount.Equals(input.ContributeAmount))
                ) && 
                (
                    this.ContributeType == input.ContributeType ||
                    (this.ContributeType != null &&
                    this.ContributeType.Equals(input.ContributeType))
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
                if (this.ContributeAmount != null)
                {
                    hashCode = (hashCode * 59) + this.ContributeAmount.GetHashCode();
                }
                if (this.ContributeType != null)
                {
                    hashCode = (hashCode * 59) + this.ContributeType.GetHashCode();
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
