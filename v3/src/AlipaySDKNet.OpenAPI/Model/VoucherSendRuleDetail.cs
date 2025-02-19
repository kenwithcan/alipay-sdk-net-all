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
    /// VoucherSendRuleDetail
    /// </summary>
    [DataContract(Name = "VoucherSendRuleDetail")]
    public partial class VoucherSendRuleDetail : IEquatable<VoucherSendRuleDetail>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="VoucherSendRuleDetail" /> class.
        /// </summary>
        /// <param name="naturalPersonLimit">是否开启自然人领取限制。自然人表示按照身份证纬度进行领取限制。.</param>
        /// <param name="phoneNumberLimit">是否开启电话号码领取限制。.</param>
        /// <param name="voucherQuantity">发行券的数量。.</param>
        /// <param name="voucherQuantityLimitPerUser">每人领取限制。默认按照支付宝uid进行领取限制; 不填写或填入0，默认没有领取限制。.</param>
        public VoucherSendRuleDetail(bool naturalPersonLimit = default(bool), bool phoneNumberLimit = default(bool), int voucherQuantity = default(int), int voucherQuantityLimitPerUser = default(int))
        {
            this.NaturalPersonLimit = naturalPersonLimit;
            this.PhoneNumberLimit = phoneNumberLimit;
            this.VoucherQuantity = voucherQuantity;
            this.VoucherQuantityLimitPerUser = voucherQuantityLimitPerUser;
        }

        /// <summary>
        /// 是否开启自然人领取限制。自然人表示按照身份证纬度进行领取限制。
        /// </summary>
        /// <value>是否开启自然人领取限制。自然人表示按照身份证纬度进行领取限制。</value>
        [DataMember(Name = "natural_person_limit", EmitDefaultValue = true)]
        public bool NaturalPersonLimit { get; set; }

        /// <summary>
        /// 是否开启电话号码领取限制。
        /// </summary>
        /// <value>是否开启电话号码领取限制。</value>
        [DataMember(Name = "phone_number_limit", EmitDefaultValue = true)]
        public bool PhoneNumberLimit { get; set; }

        /// <summary>
        /// 发行券的数量。
        /// </summary>
        /// <value>发行券的数量。</value>
        [DataMember(Name = "voucher_quantity", EmitDefaultValue = false)]
        public int VoucherQuantity { get; set; }

        /// <summary>
        /// 每人领取限制。默认按照支付宝uid进行领取限制; 不填写或填入0，默认没有领取限制。
        /// </summary>
        /// <value>每人领取限制。默认按照支付宝uid进行领取限制; 不填写或填入0，默认没有领取限制。</value>
        [DataMember(Name = "voucher_quantity_limit_per_user", EmitDefaultValue = false)]
        public int VoucherQuantityLimitPerUser { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class VoucherSendRuleDetail {\n");
            sb.Append("  NaturalPersonLimit: ").Append(NaturalPersonLimit).Append("\n");
            sb.Append("  PhoneNumberLimit: ").Append(PhoneNumberLimit).Append("\n");
            sb.Append("  VoucherQuantity: ").Append(VoucherQuantity).Append("\n");
            sb.Append("  VoucherQuantityLimitPerUser: ").Append(VoucherQuantityLimitPerUser).Append("\n");
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
            return this.Equals(input as VoucherSendRuleDetail);
        }

        /// <summary>
        /// Returns true if VoucherSendRuleDetail instances are equal
        /// </summary>
        /// <param name="input">Instance of VoucherSendRuleDetail to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(VoucherSendRuleDetail input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.NaturalPersonLimit == input.NaturalPersonLimit ||
                    this.NaturalPersonLimit.Equals(input.NaturalPersonLimit)
                ) && 
                (
                    this.PhoneNumberLimit == input.PhoneNumberLimit ||
                    this.PhoneNumberLimit.Equals(input.PhoneNumberLimit)
                ) && 
                (
                    this.VoucherQuantity == input.VoucherQuantity ||
                    this.VoucherQuantity.Equals(input.VoucherQuantity)
                ) && 
                (
                    this.VoucherQuantityLimitPerUser == input.VoucherQuantityLimitPerUser ||
                    this.VoucherQuantityLimitPerUser.Equals(input.VoucherQuantityLimitPerUser)
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
                hashCode = (hashCode * 59) + this.NaturalPersonLimit.GetHashCode();
                hashCode = (hashCode * 59) + this.PhoneNumberLimit.GetHashCode();
                hashCode = (hashCode * 59) + this.VoucherQuantity.GetHashCode();
                hashCode = (hashCode * 59) + this.VoucherQuantityLimitPerUser.GetHashCode();
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
