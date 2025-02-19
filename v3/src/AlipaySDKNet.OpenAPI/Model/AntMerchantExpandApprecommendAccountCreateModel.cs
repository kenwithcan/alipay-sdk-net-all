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
    /// AntMerchantExpandApprecommendAccountCreateModel
    /// </summary>
    [DataContract(Name = "AntMerchantExpandApprecommendAccountCreateModel")]
    public partial class AntMerchantExpandApprecommendAccountCreateModel : IEquatable<AntMerchantExpandApprecommendAccountCreateModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AntMerchantExpandApprecommendAccountCreateModel" /> class.
        /// </summary>
        /// <param name="accNo">待绑定账号PID.</param>
        /// <param name="appNo">待绑定小程序的app_id.</param>
        public AntMerchantExpandApprecommendAccountCreateModel(string accNo = default(string), string appNo = default(string))
        {
            this.AccNo = accNo;
            this.AppNo = appNo;
        }

        /// <summary>
        /// 待绑定账号PID
        /// </summary>
        /// <value>待绑定账号PID</value>
        [DataMember(Name = "acc_no", EmitDefaultValue = false)]
        public string AccNo { get; set; }

        /// <summary>
        /// 待绑定小程序的app_id
        /// </summary>
        /// <value>待绑定小程序的app_id</value>
        [DataMember(Name = "app_no", EmitDefaultValue = false)]
        public string AppNo { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AntMerchantExpandApprecommendAccountCreateModel {\n");
            sb.Append("  AccNo: ").Append(AccNo).Append("\n");
            sb.Append("  AppNo: ").Append(AppNo).Append("\n");
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
            return this.Equals(input as AntMerchantExpandApprecommendAccountCreateModel);
        }

        /// <summary>
        /// Returns true if AntMerchantExpandApprecommendAccountCreateModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AntMerchantExpandApprecommendAccountCreateModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AntMerchantExpandApprecommendAccountCreateModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AccNo == input.AccNo ||
                    (this.AccNo != null &&
                    this.AccNo.Equals(input.AccNo))
                ) && 
                (
                    this.AppNo == input.AppNo ||
                    (this.AppNo != null &&
                    this.AppNo.Equals(input.AppNo))
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
                if (this.AccNo != null)
                {
                    hashCode = (hashCode * 59) + this.AccNo.GetHashCode();
                }
                if (this.AppNo != null)
                {
                    hashCode = (hashCode * 59) + this.AppNo.GetHashCode();
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
