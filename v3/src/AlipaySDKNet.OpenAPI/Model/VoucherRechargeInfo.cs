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
    /// VoucherRechargeInfo
    /// </summary>
    [DataContract(Name = "VoucherRechargeInfo")]
    public partial class VoucherRechargeInfo : IEquatable<VoucherRechargeInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="VoucherRechargeInfo" /> class.
        /// </summary>
        /// <param name="rechargeType">预充值方式。.</param>
        /// <param name="voucherBalanceRechargeInfo">voucherBalanceRechargeInfo.</param>
        public VoucherRechargeInfo(string rechargeType = default(string), VoucherBalanceRechargeInfo voucherBalanceRechargeInfo = default(VoucherBalanceRechargeInfo))
        {
            this.RechargeType = rechargeType;
            this.VoucherBalanceRechargeInfo = voucherBalanceRechargeInfo;
        }

        /// <summary>
        /// 预充值方式。
        /// </summary>
        /// <value>预充值方式。</value>
        [DataMember(Name = "recharge_type", EmitDefaultValue = false)]
        public string RechargeType { get; set; }

        /// <summary>
        /// Gets or Sets VoucherBalanceRechargeInfo
        /// </summary>
        [DataMember(Name = "voucher_balance_recharge_info", EmitDefaultValue = false)]
        public VoucherBalanceRechargeInfo VoucherBalanceRechargeInfo { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class VoucherRechargeInfo {\n");
            sb.Append("  RechargeType: ").Append(RechargeType).Append("\n");
            sb.Append("  VoucherBalanceRechargeInfo: ").Append(VoucherBalanceRechargeInfo).Append("\n");
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
            return this.Equals(input as VoucherRechargeInfo);
        }

        /// <summary>
        /// Returns true if VoucherRechargeInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of VoucherRechargeInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(VoucherRechargeInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.RechargeType == input.RechargeType ||
                    (this.RechargeType != null &&
                    this.RechargeType.Equals(input.RechargeType))
                ) && 
                (
                    this.VoucherBalanceRechargeInfo == input.VoucherBalanceRechargeInfo ||
                    (this.VoucherBalanceRechargeInfo != null &&
                    this.VoucherBalanceRechargeInfo.Equals(input.VoucherBalanceRechargeInfo))
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
                if (this.RechargeType != null)
                {
                    hashCode = (hashCode * 59) + this.RechargeType.GetHashCode();
                }
                if (this.VoucherBalanceRechargeInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherBalanceRechargeInfo.GetHashCode();
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
