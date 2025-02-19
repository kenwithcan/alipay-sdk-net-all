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
    /// BalanceAccountDetail
    /// </summary>
    [DataContract(Name = "BalanceAccountDetail")]
    public partial class BalanceAccountDetail : IEquatable<BalanceAccountDetail>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="BalanceAccountDetail" /> class.
        /// </summary>
        /// <param name="acs">acs余额，单位：元.</param>
        /// <param name="bank">bank余额，单位：元.</param>
        public BalanceAccountDetail(string acs = default(string), string bank = default(string))
        {
            this.Acs = acs;
            this.Bank = bank;
        }

        /// <summary>
        /// acs余额，单位：元
        /// </summary>
        /// <value>acs余额，单位：元</value>
        [DataMember(Name = "acs", EmitDefaultValue = false)]
        public string Acs { get; set; }

        /// <summary>
        /// bank余额，单位：元
        /// </summary>
        /// <value>bank余额，单位：元</value>
        [DataMember(Name = "bank", EmitDefaultValue = false)]
        public string Bank { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class BalanceAccountDetail {\n");
            sb.Append("  Acs: ").Append(Acs).Append("\n");
            sb.Append("  Bank: ").Append(Bank).Append("\n");
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
            return this.Equals(input as BalanceAccountDetail);
        }

        /// <summary>
        /// Returns true if BalanceAccountDetail instances are equal
        /// </summary>
        /// <param name="input">Instance of BalanceAccountDetail to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(BalanceAccountDetail input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Acs == input.Acs ||
                    (this.Acs != null &&
                    this.Acs.Equals(input.Acs))
                ) && 
                (
                    this.Bank == input.Bank ||
                    (this.Bank != null &&
                    this.Bank.Equals(input.Bank))
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
                if (this.Acs != null)
                {
                    hashCode = (hashCode * 59) + this.Acs.GetHashCode();
                }
                if (this.Bank != null)
                {
                    hashCode = (hashCode * 59) + this.Bank.GetHashCode();
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
