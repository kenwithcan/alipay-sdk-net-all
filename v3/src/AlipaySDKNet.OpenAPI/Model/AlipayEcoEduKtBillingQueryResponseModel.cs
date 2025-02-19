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
    /// AlipayEcoEduKtBillingQueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayEcoEduKtBillingQueryResponseModel")]
    public partial class AlipayEcoEduKtBillingQueryResponseModel : IEquatable<AlipayEcoEduKtBillingQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayEcoEduKtBillingQueryResponseModel" /> class.
        /// </summary>
        /// <param name="orderStatus">NOT_PAY  待缴费  PAYING  支付中  PAY_SUCCESS 支付成功，处理中  BILLING_SUCCESS 缴费成功  TIMEOUT_CLOSED 逾期关闭账单  ISV_CLOSED 账单关闭.</param>
        /// <param name="outTradeNo">ISV发送账单时输入ISV端的账单号.</param>
        public AlipayEcoEduKtBillingQueryResponseModel(string orderStatus = default(string), string outTradeNo = default(string))
        {
            this.OrderStatus = orderStatus;
            this.OutTradeNo = outTradeNo;
        }

        /// <summary>
        /// NOT_PAY  待缴费  PAYING  支付中  PAY_SUCCESS 支付成功，处理中  BILLING_SUCCESS 缴费成功  TIMEOUT_CLOSED 逾期关闭账单  ISV_CLOSED 账单关闭
        /// </summary>
        /// <value>NOT_PAY  待缴费  PAYING  支付中  PAY_SUCCESS 支付成功，处理中  BILLING_SUCCESS 缴费成功  TIMEOUT_CLOSED 逾期关闭账单  ISV_CLOSED 账单关闭</value>
        [DataMember(Name = "order_status", EmitDefaultValue = false)]
        public string OrderStatus { get; set; }

        /// <summary>
        /// ISV发送账单时输入ISV端的账单号
        /// </summary>
        /// <value>ISV发送账单时输入ISV端的账单号</value>
        [DataMember(Name = "out_trade_no", EmitDefaultValue = false)]
        public string OutTradeNo { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayEcoEduKtBillingQueryResponseModel {\n");
            sb.Append("  OrderStatus: ").Append(OrderStatus).Append("\n");
            sb.Append("  OutTradeNo: ").Append(OutTradeNo).Append("\n");
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
            return this.Equals(input as AlipayEcoEduKtBillingQueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayEcoEduKtBillingQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayEcoEduKtBillingQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayEcoEduKtBillingQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.OrderStatus == input.OrderStatus ||
                    (this.OrderStatus != null &&
                    this.OrderStatus.Equals(input.OrderStatus))
                ) && 
                (
                    this.OutTradeNo == input.OutTradeNo ||
                    (this.OutTradeNo != null &&
                    this.OutTradeNo.Equals(input.OutTradeNo))
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
                if (this.OrderStatus != null)
                {
                    hashCode = (hashCode * 59) + this.OrderStatus.GetHashCode();
                }
                if (this.OutTradeNo != null)
                {
                    hashCode = (hashCode * 59) + this.OutTradeNo.GetHashCode();
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
