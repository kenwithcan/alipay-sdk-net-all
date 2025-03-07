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
    /// VoucherAvailableScopeInfo
    /// </summary>
    [DataContract(Name = "VoucherAvailableScopeInfo")]
    public partial class VoucherAvailableScopeInfo : IEquatable<VoucherAvailableScopeInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="VoucherAvailableScopeInfo" /> class.
        /// </summary>
        /// <param name="voucherAvailableAccountInfo">voucherAvailableAccountInfo.</param>
        /// <param name="voucherAvailableAppInfo">voucherAvailableAppInfo.</param>
        /// <param name="voucherAvailableGeographyScopeInfo">voucherAvailableGeographyScopeInfo.</param>
        /// <param name="voucherAvailableGoodsInfo">voucherAvailableGoodsInfo.</param>
        /// <param name="voucherAvailableItemInfo">voucherAvailableItemInfo.</param>
        public VoucherAvailableScopeInfo(VoucherAvailableAccountInfo voucherAvailableAccountInfo = default(VoucherAvailableAccountInfo), VoucherAvailableAppInfo voucherAvailableAppInfo = default(VoucherAvailableAppInfo), VoucherAvailableGeographyScopeInfo voucherAvailableGeographyScopeInfo = default(VoucherAvailableGeographyScopeInfo), VoucherAvailableGoodsInfo voucherAvailableGoodsInfo = default(VoucherAvailableGoodsInfo), VoucherAvailableItemInfo voucherAvailableItemInfo = default(VoucherAvailableItemInfo))
        {
            this.VoucherAvailableAccountInfo = voucherAvailableAccountInfo;
            this.VoucherAvailableAppInfo = voucherAvailableAppInfo;
            this.VoucherAvailableGeographyScopeInfo = voucherAvailableGeographyScopeInfo;
            this.VoucherAvailableGoodsInfo = voucherAvailableGoodsInfo;
            this.VoucherAvailableItemInfo = voucherAvailableItemInfo;
        }

        /// <summary>
        /// Gets or Sets VoucherAvailableAccountInfo
        /// </summary>
        [DataMember(Name = "voucher_available_account_info", EmitDefaultValue = false)]
        public VoucherAvailableAccountInfo VoucherAvailableAccountInfo { get; set; }

        /// <summary>
        /// Gets or Sets VoucherAvailableAppInfo
        /// </summary>
        [DataMember(Name = "voucher_available_app_info", EmitDefaultValue = false)]
        public VoucherAvailableAppInfo VoucherAvailableAppInfo { get; set; }

        /// <summary>
        /// Gets or Sets VoucherAvailableGeographyScopeInfo
        /// </summary>
        [DataMember(Name = "voucher_available_geography_scope_info", EmitDefaultValue = false)]
        public VoucherAvailableGeographyScopeInfo VoucherAvailableGeographyScopeInfo { get; set; }

        /// <summary>
        /// Gets or Sets VoucherAvailableGoodsInfo
        /// </summary>
        [DataMember(Name = "voucher_available_goods_info", EmitDefaultValue = false)]
        public VoucherAvailableGoodsInfo VoucherAvailableGoodsInfo { get; set; }

        /// <summary>
        /// Gets or Sets VoucherAvailableItemInfo
        /// </summary>
        [DataMember(Name = "voucher_available_item_info", EmitDefaultValue = false)]
        public VoucherAvailableItemInfo VoucherAvailableItemInfo { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class VoucherAvailableScopeInfo {\n");
            sb.Append("  VoucherAvailableAccountInfo: ").Append(VoucherAvailableAccountInfo).Append("\n");
            sb.Append("  VoucherAvailableAppInfo: ").Append(VoucherAvailableAppInfo).Append("\n");
            sb.Append("  VoucherAvailableGeographyScopeInfo: ").Append(VoucherAvailableGeographyScopeInfo).Append("\n");
            sb.Append("  VoucherAvailableGoodsInfo: ").Append(VoucherAvailableGoodsInfo).Append("\n");
            sb.Append("  VoucherAvailableItemInfo: ").Append(VoucherAvailableItemInfo).Append("\n");
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
            return this.Equals(input as VoucherAvailableScopeInfo);
        }

        /// <summary>
        /// Returns true if VoucherAvailableScopeInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of VoucherAvailableScopeInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(VoucherAvailableScopeInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.VoucherAvailableAccountInfo == input.VoucherAvailableAccountInfo ||
                    (this.VoucherAvailableAccountInfo != null &&
                    this.VoucherAvailableAccountInfo.Equals(input.VoucherAvailableAccountInfo))
                ) && 
                (
                    this.VoucherAvailableAppInfo == input.VoucherAvailableAppInfo ||
                    (this.VoucherAvailableAppInfo != null &&
                    this.VoucherAvailableAppInfo.Equals(input.VoucherAvailableAppInfo))
                ) && 
                (
                    this.VoucherAvailableGeographyScopeInfo == input.VoucherAvailableGeographyScopeInfo ||
                    (this.VoucherAvailableGeographyScopeInfo != null &&
                    this.VoucherAvailableGeographyScopeInfo.Equals(input.VoucherAvailableGeographyScopeInfo))
                ) && 
                (
                    this.VoucherAvailableGoodsInfo == input.VoucherAvailableGoodsInfo ||
                    (this.VoucherAvailableGoodsInfo != null &&
                    this.VoucherAvailableGoodsInfo.Equals(input.VoucherAvailableGoodsInfo))
                ) && 
                (
                    this.VoucherAvailableItemInfo == input.VoucherAvailableItemInfo ||
                    (this.VoucherAvailableItemInfo != null &&
                    this.VoucherAvailableItemInfo.Equals(input.VoucherAvailableItemInfo))
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
                if (this.VoucherAvailableAccountInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherAvailableAccountInfo.GetHashCode();
                }
                if (this.VoucherAvailableAppInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherAvailableAppInfo.GetHashCode();
                }
                if (this.VoucherAvailableGeographyScopeInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherAvailableGeographyScopeInfo.GetHashCode();
                }
                if (this.VoucherAvailableGoodsInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherAvailableGoodsInfo.GetHashCode();
                }
                if (this.VoucherAvailableItemInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherAvailableItemInfo.GetHashCode();
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
