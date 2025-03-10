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
    /// OrderVoucherAvailableScopeResult
    /// </summary>
    [DataContract(Name = "OrderVoucherAvailableScopeResult")]
    public partial class OrderVoucherAvailableScopeResult : IEquatable<OrderVoucherAvailableScopeResult>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OrderVoucherAvailableScopeResult" /> class.
        /// </summary>
        /// <param name="orderVoucherAvailableShopResult">orderVoucherAvailableShopResult.</param>
        /// <param name="voucherAvailableType">可用范围类型。.</param>
        public OrderVoucherAvailableScopeResult(OrderVoucherAvailableShopResult orderVoucherAvailableShopResult = default(OrderVoucherAvailableShopResult), string voucherAvailableType = default(string))
        {
            this.OrderVoucherAvailableShopResult = orderVoucherAvailableShopResult;
            this.VoucherAvailableType = voucherAvailableType;
        }

        /// <summary>
        /// Gets or Sets OrderVoucherAvailableShopResult
        /// </summary>
        [DataMember(Name = "order_voucher_available_shop_result", EmitDefaultValue = false)]
        public OrderVoucherAvailableShopResult OrderVoucherAvailableShopResult { get; set; }

        /// <summary>
        /// 可用范围类型。
        /// </summary>
        /// <value>可用范围类型。</value>
        [DataMember(Name = "voucher_available_type", EmitDefaultValue = false)]
        public string VoucherAvailableType { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class OrderVoucherAvailableScopeResult {\n");
            sb.Append("  OrderVoucherAvailableShopResult: ").Append(OrderVoucherAvailableShopResult).Append("\n");
            sb.Append("  VoucherAvailableType: ").Append(VoucherAvailableType).Append("\n");
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
            return this.Equals(input as OrderVoucherAvailableScopeResult);
        }

        /// <summary>
        /// Returns true if OrderVoucherAvailableScopeResult instances are equal
        /// </summary>
        /// <param name="input">Instance of OrderVoucherAvailableScopeResult to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(OrderVoucherAvailableScopeResult input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.OrderVoucherAvailableShopResult == input.OrderVoucherAvailableShopResult ||
                    (this.OrderVoucherAvailableShopResult != null &&
                    this.OrderVoucherAvailableShopResult.Equals(input.OrderVoucherAvailableShopResult))
                ) && 
                (
                    this.VoucherAvailableType == input.VoucherAvailableType ||
                    (this.VoucherAvailableType != null &&
                    this.VoucherAvailableType.Equals(input.VoucherAvailableType))
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
                if (this.OrderVoucherAvailableShopResult != null)
                {
                    hashCode = (hashCode * 59) + this.OrderVoucherAvailableShopResult.GetHashCode();
                }
                if (this.VoucherAvailableType != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherAvailableType.GetHashCode();
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
