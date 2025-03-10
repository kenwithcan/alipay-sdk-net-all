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
    /// ActivityExchangeVoucher
    /// </summary>
    [DataContract(Name = "ActivityExchangeVoucher")]
    public partial class ActivityExchangeVoucher : IEquatable<ActivityExchangeVoucher>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ActivityExchangeVoucher" /> class.
        /// </summary>
        /// <param name="amount">券的价值。.</param>
        /// <param name="floorAmount">门槛金额。说明：该字段可不填，认为无门槛;.</param>
        /// <param name="overdueRefundable">是否支持优惠券过期后，自动退款给用户。 不填默认否，枚举值： true：是 false：否  自动退款功能需要服务商在优惠券过期时，主动调用alipay.marketing.activity.order.refund接口进行退款。  如果配置优惠券时选择了过期自动退款，但是实际券过期后，服务商没有进行退款，那么用户投诉后，需要服务商进行解决。.</param>
        /// <param name="refundable">购买的优惠券是否允许退款。 不填默认否，枚举值： true：是 false：否.</param>
        /// <param name="saleAmount">用户购买优惠券需要支付的金额。.</param>
        public ActivityExchangeVoucher(string amount = default(string), string floorAmount = default(string), bool overdueRefundable = default(bool), bool refundable = default(bool), string saleAmount = default(string))
        {
            this.Amount = amount;
            this.FloorAmount = floorAmount;
            this.OverdueRefundable = overdueRefundable;
            this.Refundable = refundable;
            this.SaleAmount = saleAmount;
        }

        /// <summary>
        /// 券的价值。
        /// </summary>
        /// <value>券的价值。</value>
        [DataMember(Name = "amount", EmitDefaultValue = false)]
        public string Amount { get; set; }

        /// <summary>
        /// 门槛金额。说明：该字段可不填，认为无门槛;
        /// </summary>
        /// <value>门槛金额。说明：该字段可不填，认为无门槛;</value>
        [DataMember(Name = "floor_amount", EmitDefaultValue = false)]
        public string FloorAmount { get; set; }

        /// <summary>
        /// 是否支持优惠券过期后，自动退款给用户。 不填默认否，枚举值： true：是 false：否  自动退款功能需要服务商在优惠券过期时，主动调用alipay.marketing.activity.order.refund接口进行退款。  如果配置优惠券时选择了过期自动退款，但是实际券过期后，服务商没有进行退款，那么用户投诉后，需要服务商进行解决。
        /// </summary>
        /// <value>是否支持优惠券过期后，自动退款给用户。 不填默认否，枚举值： true：是 false：否  自动退款功能需要服务商在优惠券过期时，主动调用alipay.marketing.activity.order.refund接口进行退款。  如果配置优惠券时选择了过期自动退款，但是实际券过期后，服务商没有进行退款，那么用户投诉后，需要服务商进行解决。</value>
        [DataMember(Name = "overdue_refundable", EmitDefaultValue = true)]
        public bool OverdueRefundable { get; set; }

        /// <summary>
        /// 购买的优惠券是否允许退款。 不填默认否，枚举值： true：是 false：否
        /// </summary>
        /// <value>购买的优惠券是否允许退款。 不填默认否，枚举值： true：是 false：否</value>
        [DataMember(Name = "refundable", EmitDefaultValue = true)]
        public bool Refundable { get; set; }

        /// <summary>
        /// 用户购买优惠券需要支付的金额。
        /// </summary>
        /// <value>用户购买优惠券需要支付的金额。</value>
        [DataMember(Name = "sale_amount", EmitDefaultValue = false)]
        public string SaleAmount { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ActivityExchangeVoucher {\n");
            sb.Append("  Amount: ").Append(Amount).Append("\n");
            sb.Append("  FloorAmount: ").Append(FloorAmount).Append("\n");
            sb.Append("  OverdueRefundable: ").Append(OverdueRefundable).Append("\n");
            sb.Append("  Refundable: ").Append(Refundable).Append("\n");
            sb.Append("  SaleAmount: ").Append(SaleAmount).Append("\n");
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
            return this.Equals(input as ActivityExchangeVoucher);
        }

        /// <summary>
        /// Returns true if ActivityExchangeVoucher instances are equal
        /// </summary>
        /// <param name="input">Instance of ActivityExchangeVoucher to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ActivityExchangeVoucher input)
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
                    this.FloorAmount == input.FloorAmount ||
                    (this.FloorAmount != null &&
                    this.FloorAmount.Equals(input.FloorAmount))
                ) && 
                (
                    this.OverdueRefundable == input.OverdueRefundable ||
                    this.OverdueRefundable.Equals(input.OverdueRefundable)
                ) && 
                (
                    this.Refundable == input.Refundable ||
                    this.Refundable.Equals(input.Refundable)
                ) && 
                (
                    this.SaleAmount == input.SaleAmount ||
                    (this.SaleAmount != null &&
                    this.SaleAmount.Equals(input.SaleAmount))
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
                if (this.FloorAmount != null)
                {
                    hashCode = (hashCode * 59) + this.FloorAmount.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.OverdueRefundable.GetHashCode();
                hashCode = (hashCode * 59) + this.Refundable.GetHashCode();
                if (this.SaleAmount != null)
                {
                    hashCode = (hashCode * 59) + this.SaleAmount.GetHashCode();
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
