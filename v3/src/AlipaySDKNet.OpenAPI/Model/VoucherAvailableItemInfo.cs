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
    /// VoucherAvailableItemInfo
    /// </summary>
    [DataContract(Name = "VoucherAvailableItemInfo")]
    public partial class VoucherAvailableItemInfo : IEquatable<VoucherAvailableItemInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="VoucherAvailableItemInfo" /> class.
        /// </summary>
        /// <param name="itemId">内部商品ID.</param>
        /// <param name="outItemInfo">外部商品信息.</param>
        public VoucherAvailableItemInfo(string itemId = default(string), List<VoucherAvailableOutItemInfo> outItemInfo = default(List<VoucherAvailableOutItemInfo>))
        {
            this.ItemId = itemId;
            this.OutItemInfo = outItemInfo;
        }

        /// <summary>
        /// 内部商品ID
        /// </summary>
        /// <value>内部商品ID</value>
        [DataMember(Name = "item_id", EmitDefaultValue = false)]
        public string ItemId { get; set; }

        /// <summary>
        /// 外部商品信息
        /// </summary>
        /// <value>外部商品信息</value>
        [DataMember(Name = "out_item_info", EmitDefaultValue = false)]
        public List<VoucherAvailableOutItemInfo> OutItemInfo { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class VoucherAvailableItemInfo {\n");
            sb.Append("  ItemId: ").Append(ItemId).Append("\n");
            sb.Append("  OutItemInfo: ").Append(OutItemInfo).Append("\n");
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
            return this.Equals(input as VoucherAvailableItemInfo);
        }

        /// <summary>
        /// Returns true if VoucherAvailableItemInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of VoucherAvailableItemInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(VoucherAvailableItemInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ItemId == input.ItemId ||
                    (this.ItemId != null &&
                    this.ItemId.Equals(input.ItemId))
                ) && 
                (
                    this.OutItemInfo == input.OutItemInfo ||
                    this.OutItemInfo != null &&
                    input.OutItemInfo != null &&
                    this.OutItemInfo.SequenceEqual(input.OutItemInfo)
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
                if (this.ItemId != null)
                {
                    hashCode = (hashCode * 59) + this.ItemId.GetHashCode();
                }
                if (this.OutItemInfo != null)
                {
                    hashCode = (hashCode * 59) + this.OutItemInfo.GetHashCode();
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
