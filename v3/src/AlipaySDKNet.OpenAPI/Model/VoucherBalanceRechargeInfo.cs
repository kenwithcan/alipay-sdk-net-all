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
    /// VoucherBalanceRechargeInfo
    /// </summary>
    [DataContract(Name = "VoucherBalanceRechargeInfo")]
    public partial class VoucherBalanceRechargeInfo : IEquatable<VoucherBalanceRechargeInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="VoucherBalanceRechargeInfo" /> class.
        /// </summary>
        /// <param name="amount">支付宝余额充值金额  限制：   1.币种为人民币，单位元。   2. 总预算&#x3D;优惠金额*总发券张数.</param>
        /// <param name="logonId">出资的商户支付宝登录账号.</param>
        /// <param name="partnerId">出资的商户支付宝ID.</param>
        public VoucherBalanceRechargeInfo(string amount = default(string), string logonId = default(string), string partnerId = default(string))
        {
            this.Amount = amount;
            this.LogonId = logonId;
            this.PartnerId = partnerId;
        }

        /// <summary>
        /// 支付宝余额充值金额  限制：   1.币种为人民币，单位元。   2. 总预算&#x3D;优惠金额*总发券张数
        /// </summary>
        /// <value>支付宝余额充值金额  限制：   1.币种为人民币，单位元。   2. 总预算&#x3D;优惠金额*总发券张数</value>
        [DataMember(Name = "amount", EmitDefaultValue = false)]
        public string Amount { get; set; }

        /// <summary>
        /// 出资的商户支付宝登录账号
        /// </summary>
        /// <value>出资的商户支付宝登录账号</value>
        [DataMember(Name = "logon_id", EmitDefaultValue = false)]
        public string LogonId { get; set; }

        /// <summary>
        /// 出资的商户支付宝ID
        /// </summary>
        /// <value>出资的商户支付宝ID</value>
        [DataMember(Name = "partner_id", EmitDefaultValue = false)]
        public string PartnerId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class VoucherBalanceRechargeInfo {\n");
            sb.Append("  Amount: ").Append(Amount).Append("\n");
            sb.Append("  LogonId: ").Append(LogonId).Append("\n");
            sb.Append("  PartnerId: ").Append(PartnerId).Append("\n");
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
            return this.Equals(input as VoucherBalanceRechargeInfo);
        }

        /// <summary>
        /// Returns true if VoucherBalanceRechargeInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of VoucherBalanceRechargeInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(VoucherBalanceRechargeInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Amount == input.Amount ||
                    (this.Amount != null &&
                    this.Amount.Equals(input.Amount))
                ) && 
                (
                    this.LogonId == input.LogonId ||
                    (this.LogonId != null &&
                    this.LogonId.Equals(input.LogonId))
                ) && 
                (
                    this.PartnerId == input.PartnerId ||
                    (this.PartnerId != null &&
                    this.PartnerId.Equals(input.PartnerId))
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
                if (this.Amount != null)
                {
                    hashCode = (hashCode * 59) + this.Amount.GetHashCode();
                }
                if (this.LogonId != null)
                {
                    hashCode = (hashCode * 59) + this.LogonId.GetHashCode();
                }
                if (this.PartnerId != null)
                {
                    hashCode = (hashCode * 59) + this.PartnerId.GetHashCode();
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
