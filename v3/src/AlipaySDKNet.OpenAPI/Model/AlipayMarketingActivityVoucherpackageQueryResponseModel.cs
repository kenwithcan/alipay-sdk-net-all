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
    /// AlipayMarketingActivityVoucherpackageQueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayMarketingActivityVoucherpackageQueryResponseModel")]
    public partial class AlipayMarketingActivityVoucherpackageQueryResponseModel : IEquatable<AlipayMarketingActivityVoucherpackageQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMarketingActivityVoucherpackageQueryResponseModel" /> class.
        /// </summary>
        /// <param name="voucherPackageActivityInfo">券包活动信息.</param>
        /// <param name="voucherPackageBaseInfo">voucherPackageBaseInfo.</param>
        /// <param name="voucherPackageSalesInfo">voucherPackageSalesInfo.</param>
        /// <param name="voucherPackageUseRule">voucherPackageUseRule.</param>
        public AlipayMarketingActivityVoucherpackageQueryResponseModel(List<VoucherPackageActivityInfo> voucherPackageActivityInfo = default(List<VoucherPackageActivityInfo>), VoucherPackageBaseInfo voucherPackageBaseInfo = default(VoucherPackageBaseInfo), VoucherPackageSalesInfo voucherPackageSalesInfo = default(VoucherPackageSalesInfo), VoucherPackageUseRule voucherPackageUseRule = default(VoucherPackageUseRule))
        {
            this.VoucherPackageActivityInfo = voucherPackageActivityInfo;
            this.VoucherPackageBaseInfo = voucherPackageBaseInfo;
            this.VoucherPackageSalesInfo = voucherPackageSalesInfo;
            this.VoucherPackageUseRule = voucherPackageUseRule;
        }

        /// <summary>
        /// 券包活动信息
        /// </summary>
        /// <value>券包活动信息</value>
        [DataMember(Name = "voucher_package_activity_info", EmitDefaultValue = false)]
        public List<VoucherPackageActivityInfo> VoucherPackageActivityInfo { get; set; }

        /// <summary>
        /// Gets or Sets VoucherPackageBaseInfo
        /// </summary>
        [DataMember(Name = "voucher_package_base_info", EmitDefaultValue = false)]
        public VoucherPackageBaseInfo VoucherPackageBaseInfo { get; set; }

        /// <summary>
        /// Gets or Sets VoucherPackageSalesInfo
        /// </summary>
        [DataMember(Name = "voucher_package_sales_info", EmitDefaultValue = false)]
        public VoucherPackageSalesInfo VoucherPackageSalesInfo { get; set; }

        /// <summary>
        /// Gets or Sets VoucherPackageUseRule
        /// </summary>
        [DataMember(Name = "voucher_package_use_rule", EmitDefaultValue = false)]
        public VoucherPackageUseRule VoucherPackageUseRule { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayMarketingActivityVoucherpackageQueryResponseModel {\n");
            sb.Append("  VoucherPackageActivityInfo: ").Append(VoucherPackageActivityInfo).Append("\n");
            sb.Append("  VoucherPackageBaseInfo: ").Append(VoucherPackageBaseInfo).Append("\n");
            sb.Append("  VoucherPackageSalesInfo: ").Append(VoucherPackageSalesInfo).Append("\n");
            sb.Append("  VoucherPackageUseRule: ").Append(VoucherPackageUseRule).Append("\n");
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
            return this.Equals(input as AlipayMarketingActivityVoucherpackageQueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayMarketingActivityVoucherpackageQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayMarketingActivityVoucherpackageQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayMarketingActivityVoucherpackageQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.VoucherPackageActivityInfo == input.VoucherPackageActivityInfo ||
                    this.VoucherPackageActivityInfo != null &&
                    input.VoucherPackageActivityInfo != null &&
                    this.VoucherPackageActivityInfo.SequenceEqual(input.VoucherPackageActivityInfo)
                ) && 
                (
                    this.VoucherPackageBaseInfo == input.VoucherPackageBaseInfo ||
                    (this.VoucherPackageBaseInfo != null &&
                    this.VoucherPackageBaseInfo.Equals(input.VoucherPackageBaseInfo))
                ) && 
                (
                    this.VoucherPackageSalesInfo == input.VoucherPackageSalesInfo ||
                    (this.VoucherPackageSalesInfo != null &&
                    this.VoucherPackageSalesInfo.Equals(input.VoucherPackageSalesInfo))
                ) && 
                (
                    this.VoucherPackageUseRule == input.VoucherPackageUseRule ||
                    (this.VoucherPackageUseRule != null &&
                    this.VoucherPackageUseRule.Equals(input.VoucherPackageUseRule))
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
                if (this.VoucherPackageActivityInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherPackageActivityInfo.GetHashCode();
                }
                if (this.VoucherPackageBaseInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherPackageBaseInfo.GetHashCode();
                }
                if (this.VoucherPackageSalesInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherPackageSalesInfo.GetHashCode();
                }
                if (this.VoucherPackageUseRule != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherPackageUseRule.GetHashCode();
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
