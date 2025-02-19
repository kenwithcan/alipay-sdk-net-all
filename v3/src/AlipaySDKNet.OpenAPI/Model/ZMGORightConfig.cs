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
    /// ZMGORightConfig
    /// </summary>
    [DataContract(Name = "ZMGORightConfig")]
    public partial class ZMGORightConfig : IEquatable<ZMGORightConfig>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ZMGORightConfig" /> class.
        /// </summary>
        /// <param name="cumulativePreferentialRedirectSchema">芝麻GO管理页已享优惠进度的重定向链接.</param>
        /// <param name="customBenefitDesc">权益描述.</param>
        /// <param name="customSubBenefitDesc">权益描述子标题.</param>
        public ZMGORightConfig(string cumulativePreferentialRedirectSchema = default(string), string customBenefitDesc = default(string), string customSubBenefitDesc = default(string))
        {
            this.CumulativePreferentialRedirectSchema = cumulativePreferentialRedirectSchema;
            this.CustomBenefitDesc = customBenefitDesc;
            this.CustomSubBenefitDesc = customSubBenefitDesc;
        }

        /// <summary>
        /// 芝麻GO管理页已享优惠进度的重定向链接
        /// </summary>
        /// <value>芝麻GO管理页已享优惠进度的重定向链接</value>
        [DataMember(Name = "cumulative_preferential_redirect_schema", EmitDefaultValue = false)]
        public string CumulativePreferentialRedirectSchema { get; set; }

        /// <summary>
        /// 权益描述
        /// </summary>
        /// <value>权益描述</value>
        [DataMember(Name = "custom_benefit_desc", EmitDefaultValue = false)]
        public string CustomBenefitDesc { get; set; }

        /// <summary>
        /// 权益描述子标题
        /// </summary>
        /// <value>权益描述子标题</value>
        [DataMember(Name = "custom_sub_benefit_desc", EmitDefaultValue = false)]
        public string CustomSubBenefitDesc { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ZMGORightConfig {\n");
            sb.Append("  CumulativePreferentialRedirectSchema: ").Append(CumulativePreferentialRedirectSchema).Append("\n");
            sb.Append("  CustomBenefitDesc: ").Append(CustomBenefitDesc).Append("\n");
            sb.Append("  CustomSubBenefitDesc: ").Append(CustomSubBenefitDesc).Append("\n");
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
            return this.Equals(input as ZMGORightConfig);
        }

        /// <summary>
        /// Returns true if ZMGORightConfig instances are equal
        /// </summary>
        /// <param name="input">Instance of ZMGORightConfig to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ZMGORightConfig input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.CumulativePreferentialRedirectSchema == input.CumulativePreferentialRedirectSchema ||
                    (this.CumulativePreferentialRedirectSchema != null &&
                    this.CumulativePreferentialRedirectSchema.Equals(input.CumulativePreferentialRedirectSchema))
                ) && 
                (
                    this.CustomBenefitDesc == input.CustomBenefitDesc ||
                    (this.CustomBenefitDesc != null &&
                    this.CustomBenefitDesc.Equals(input.CustomBenefitDesc))
                ) && 
                (
                    this.CustomSubBenefitDesc == input.CustomSubBenefitDesc ||
                    (this.CustomSubBenefitDesc != null &&
                    this.CustomSubBenefitDesc.Equals(input.CustomSubBenefitDesc))
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
                if (this.CumulativePreferentialRedirectSchema != null)
                {
                    hashCode = (hashCode * 59) + this.CumulativePreferentialRedirectSchema.GetHashCode();
                }
                if (this.CustomBenefitDesc != null)
                {
                    hashCode = (hashCode * 59) + this.CustomBenefitDesc.GetHashCode();
                }
                if (this.CustomSubBenefitDesc != null)
                {
                    hashCode = (hashCode * 59) + this.CustomSubBenefitDesc.GetHashCode();
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
