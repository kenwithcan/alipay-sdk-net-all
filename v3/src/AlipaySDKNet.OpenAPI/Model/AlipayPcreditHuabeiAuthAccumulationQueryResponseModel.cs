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
    /// AlipayPcreditHuabeiAuthAccumulationQueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayPcreditHuabeiAuthAccumulationQueryResponseModel")]
    public partial class AlipayPcreditHuabeiAuthAccumulationQueryResponseModel : IEquatable<AlipayPcreditHuabeiAuthAccumulationQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayPcreditHuabeiAuthAccumulationQueryResponseModel" /> class.
        /// </summary>
        /// <param name="payAmount">本周期内支付宝端根据用户消费情况试算出的应付费用，仅供参考使用。.</param>
        /// <param name="totalDiscountAmount">本周期内用户累计享受的优惠金额.</param>
        /// <param name="totalPayCount">本周期内用户总的消费次数.</param>
        /// <param name="totalRealPayAmount">本周期内用户累计支付宝付款金额.</param>
        public AlipayPcreditHuabeiAuthAccumulationQueryResponseModel(string payAmount = default(string), string totalDiscountAmount = default(string), string totalPayCount = default(string), string totalRealPayAmount = default(string))
        {
            this.PayAmount = payAmount;
            this.TotalDiscountAmount = totalDiscountAmount;
            this.TotalPayCount = totalPayCount;
            this.TotalRealPayAmount = totalRealPayAmount;
        }

        /// <summary>
        /// 本周期内支付宝端根据用户消费情况试算出的应付费用，仅供参考使用。
        /// </summary>
        /// <value>本周期内支付宝端根据用户消费情况试算出的应付费用，仅供参考使用。</value>
        [DataMember(Name = "pay_amount", EmitDefaultValue = false)]
        public string PayAmount { get; set; }

        /// <summary>
        /// 本周期内用户累计享受的优惠金额
        /// </summary>
        /// <value>本周期内用户累计享受的优惠金额</value>
        [DataMember(Name = "total_discount_amount", EmitDefaultValue = false)]
        public string TotalDiscountAmount { get; set; }

        /// <summary>
        /// 本周期内用户总的消费次数
        /// </summary>
        /// <value>本周期内用户总的消费次数</value>
        [DataMember(Name = "total_pay_count", EmitDefaultValue = false)]
        public string TotalPayCount { get; set; }

        /// <summary>
        /// 本周期内用户累计支付宝付款金额
        /// </summary>
        /// <value>本周期内用户累计支付宝付款金额</value>
        [DataMember(Name = "total_real_pay_amount", EmitDefaultValue = false)]
        public string TotalRealPayAmount { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayPcreditHuabeiAuthAccumulationQueryResponseModel {\n");
            sb.Append("  PayAmount: ").Append(PayAmount).Append("\n");
            sb.Append("  TotalDiscountAmount: ").Append(TotalDiscountAmount).Append("\n");
            sb.Append("  TotalPayCount: ").Append(TotalPayCount).Append("\n");
            sb.Append("  TotalRealPayAmount: ").Append(TotalRealPayAmount).Append("\n");
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
            return this.Equals(input as AlipayPcreditHuabeiAuthAccumulationQueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayPcreditHuabeiAuthAccumulationQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayPcreditHuabeiAuthAccumulationQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayPcreditHuabeiAuthAccumulationQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.PayAmount == input.PayAmount ||
                    (this.PayAmount != null &&
                    this.PayAmount.Equals(input.PayAmount))
                ) && 
                (
                    this.TotalDiscountAmount == input.TotalDiscountAmount ||
                    (this.TotalDiscountAmount != null &&
                    this.TotalDiscountAmount.Equals(input.TotalDiscountAmount))
                ) && 
                (
                    this.TotalPayCount == input.TotalPayCount ||
                    (this.TotalPayCount != null &&
                    this.TotalPayCount.Equals(input.TotalPayCount))
                ) && 
                (
                    this.TotalRealPayAmount == input.TotalRealPayAmount ||
                    (this.TotalRealPayAmount != null &&
                    this.TotalRealPayAmount.Equals(input.TotalRealPayAmount))
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
                if (this.PayAmount != null)
                {
                    hashCode = (hashCode * 59) + this.PayAmount.GetHashCode();
                }
                if (this.TotalDiscountAmount != null)
                {
                    hashCode = (hashCode * 59) + this.TotalDiscountAmount.GetHashCode();
                }
                if (this.TotalPayCount != null)
                {
                    hashCode = (hashCode * 59) + this.TotalPayCount.GetHashCode();
                }
                if (this.TotalRealPayAmount != null)
                {
                    hashCode = (hashCode * 59) + this.TotalRealPayAmount.GetHashCode();
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
