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
    /// AlipayTradeOrderPayModel
    /// </summary>
    [DataContract(Name = "AlipayTradeOrderPayModel")]
    public partial class AlipayTradeOrderPayModel : IEquatable<AlipayTradeOrderPayModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayTradeOrderPayModel" /> class.
        /// </summary>
        /// <param name="advancePaymentType">垫资支付模式。支付时需要垫资的场景才传入。具体传参需与支付宝约定。 CREDIT_FULFILLMENT_ZM 表示先用后付产品履约动作支持芝麻垫资。.</param>
        /// <param name="buyerId">买家的支付宝用户id    注：  1.用于校验与已存交易中的买家是否相等.</param>
        /// <param name="buyerOpenId">买家支付宝用户唯一标识  注： 1.用于校验与已存交易中的买家是否相等.</param>
        /// <param name="buyerPayDetail">买家支付明细    目前支持的支付渠道为：  - offline_pos：本次买家使用的是pos刷卡支付    注：  各支付工具金额总和&#x3D;订单总金额.</param>
        /// <param name="fulfillmentAmount">本次履约支付金额，单位为元，精确到小数点后两位。履约支付场景才需要传入。.</param>
        /// <param name="isAsyncPay">是否异步支付，传入true时，表明本次期望走异步支付，会先将支付请求受理下来，再异步推进。商户可以通过交易的异步通知或者轮询交易的状态来确定最终的交易结果.</param>
        /// <param name="orderPayMode">订单支付模式。特殊支付场景才需要传入。具体传参需与支付宝约定。 CREDIT_FULFILLMENT_ZM表示基于芝麻授信的履约支付模式，比如芝麻先用后付产品。.</param>
        /// <param name="outRequestNo">商户请求号，标识一次请求的唯一id，用于幂等控制。.</param>
        /// <param name="productCode">销售产品码.</param>
        /// <param name="totalAmount">订单总金额，单位为元，精确到小数点后两位，取值范围[0.01,100000000]    注：  1.用于校验与已存交易中的金额是否相等.</param>
        /// <param name="tradeNo">支付宝交易号.</param>
        public AlipayTradeOrderPayModel(string advancePaymentType = default(string), string buyerId = default(string), string buyerOpenId = default(string), List<BuyerPayDetail> buyerPayDetail = default(List<BuyerPayDetail>), string fulfillmentAmount = default(string), bool isAsyncPay = default(bool), string orderPayMode = default(string), string outRequestNo = default(string), string productCode = default(string), string totalAmount = default(string), string tradeNo = default(string))
        {
            this.AdvancePaymentType = advancePaymentType;
            this.BuyerId = buyerId;
            this.BuyerOpenId = buyerOpenId;
            this.BuyerPayDetail = buyerPayDetail;
            this.FulfillmentAmount = fulfillmentAmount;
            this.IsAsyncPay = isAsyncPay;
            this.OrderPayMode = orderPayMode;
            this.OutRequestNo = outRequestNo;
            this.ProductCode = productCode;
            this.TotalAmount = totalAmount;
            this.TradeNo = tradeNo;
        }

        /// <summary>
        /// 垫资支付模式。支付时需要垫资的场景才传入。具体传参需与支付宝约定。 CREDIT_FULFILLMENT_ZM 表示先用后付产品履约动作支持芝麻垫资。
        /// </summary>
        /// <value>垫资支付模式。支付时需要垫资的场景才传入。具体传参需与支付宝约定。 CREDIT_FULFILLMENT_ZM 表示先用后付产品履约动作支持芝麻垫资。</value>
        [DataMember(Name = "advance_payment_type", EmitDefaultValue = false)]
        public string AdvancePaymentType { get; set; }

        /// <summary>
        /// 买家的支付宝用户id    注：  1.用于校验与已存交易中的买家是否相等
        /// </summary>
        /// <value>买家的支付宝用户id    注：  1.用于校验与已存交易中的买家是否相等</value>
        [DataMember(Name = "buyer_id", EmitDefaultValue = false)]
        public string BuyerId { get; set; }

        /// <summary>
        /// 买家支付宝用户唯一标识  注： 1.用于校验与已存交易中的买家是否相等
        /// </summary>
        /// <value>买家支付宝用户唯一标识  注： 1.用于校验与已存交易中的买家是否相等</value>
        [DataMember(Name = "buyer_open_id", EmitDefaultValue = false)]
        public string BuyerOpenId { get; set; }

        /// <summary>
        /// 买家支付明细    目前支持的支付渠道为：  - offline_pos：本次买家使用的是pos刷卡支付    注：  各支付工具金额总和&#x3D;订单总金额
        /// </summary>
        /// <value>买家支付明细    目前支持的支付渠道为：  - offline_pos：本次买家使用的是pos刷卡支付    注：  各支付工具金额总和&#x3D;订单总金额</value>
        [DataMember(Name = "buyer_pay_detail", EmitDefaultValue = false)]
        public List<BuyerPayDetail> BuyerPayDetail { get; set; }

        /// <summary>
        /// 本次履约支付金额，单位为元，精确到小数点后两位。履约支付场景才需要传入。
        /// </summary>
        /// <value>本次履约支付金额，单位为元，精确到小数点后两位。履约支付场景才需要传入。</value>
        [DataMember(Name = "fulfillment_amount", EmitDefaultValue = false)]
        public string FulfillmentAmount { get; set; }

        /// <summary>
        /// 是否异步支付，传入true时，表明本次期望走异步支付，会先将支付请求受理下来，再异步推进。商户可以通过交易的异步通知或者轮询交易的状态来确定最终的交易结果
        /// </summary>
        /// <value>是否异步支付，传入true时，表明本次期望走异步支付，会先将支付请求受理下来，再异步推进。商户可以通过交易的异步通知或者轮询交易的状态来确定最终的交易结果</value>
        [DataMember(Name = "is_async_pay", EmitDefaultValue = true)]
        public bool IsAsyncPay { get; set; }

        /// <summary>
        /// 订单支付模式。特殊支付场景才需要传入。具体传参需与支付宝约定。 CREDIT_FULFILLMENT_ZM表示基于芝麻授信的履约支付模式，比如芝麻先用后付产品。
        /// </summary>
        /// <value>订单支付模式。特殊支付场景才需要传入。具体传参需与支付宝约定。 CREDIT_FULFILLMENT_ZM表示基于芝麻授信的履约支付模式，比如芝麻先用后付产品。</value>
        [DataMember(Name = "order_pay_mode", EmitDefaultValue = false)]
        public string OrderPayMode { get; set; }

        /// <summary>
        /// 商户请求号，标识一次请求的唯一id，用于幂等控制。
        /// </summary>
        /// <value>商户请求号，标识一次请求的唯一id，用于幂等控制。</value>
        [DataMember(Name = "out_request_no", EmitDefaultValue = false)]
        public string OutRequestNo { get; set; }

        /// <summary>
        /// 销售产品码
        /// </summary>
        /// <value>销售产品码</value>
        [DataMember(Name = "product_code", EmitDefaultValue = false)]
        public string ProductCode { get; set; }

        /// <summary>
        /// 订单总金额，单位为元，精确到小数点后两位，取值范围[0.01,100000000]    注：  1.用于校验与已存交易中的金额是否相等
        /// </summary>
        /// <value>订单总金额，单位为元，精确到小数点后两位，取值范围[0.01,100000000]    注：  1.用于校验与已存交易中的金额是否相等</value>
        [DataMember(Name = "total_amount", EmitDefaultValue = false)]
        public string TotalAmount { get; set; }

        /// <summary>
        /// 支付宝交易号
        /// </summary>
        /// <value>支付宝交易号</value>
        [DataMember(Name = "trade_no", EmitDefaultValue = false)]
        public string TradeNo { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayTradeOrderPayModel {\n");
            sb.Append("  AdvancePaymentType: ").Append(AdvancePaymentType).Append("\n");
            sb.Append("  BuyerId: ").Append(BuyerId).Append("\n");
            sb.Append("  BuyerOpenId: ").Append(BuyerOpenId).Append("\n");
            sb.Append("  BuyerPayDetail: ").Append(BuyerPayDetail).Append("\n");
            sb.Append("  FulfillmentAmount: ").Append(FulfillmentAmount).Append("\n");
            sb.Append("  IsAsyncPay: ").Append(IsAsyncPay).Append("\n");
            sb.Append("  OrderPayMode: ").Append(OrderPayMode).Append("\n");
            sb.Append("  OutRequestNo: ").Append(OutRequestNo).Append("\n");
            sb.Append("  ProductCode: ").Append(ProductCode).Append("\n");
            sb.Append("  TotalAmount: ").Append(TotalAmount).Append("\n");
            sb.Append("  TradeNo: ").Append(TradeNo).Append("\n");
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
            return this.Equals(input as AlipayTradeOrderPayModel);
        }

        /// <summary>
        /// Returns true if AlipayTradeOrderPayModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayTradeOrderPayModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayTradeOrderPayModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AdvancePaymentType == input.AdvancePaymentType ||
                    (this.AdvancePaymentType != null &&
                    this.AdvancePaymentType.Equals(input.AdvancePaymentType))
                ) && 
                (
                    this.BuyerId == input.BuyerId ||
                    (this.BuyerId != null &&
                    this.BuyerId.Equals(input.BuyerId))
                ) && 
                (
                    this.BuyerOpenId == input.BuyerOpenId ||
                    (this.BuyerOpenId != null &&
                    this.BuyerOpenId.Equals(input.BuyerOpenId))
                ) && 
                (
                    this.BuyerPayDetail == input.BuyerPayDetail ||
                    this.BuyerPayDetail != null &&
                    input.BuyerPayDetail != null &&
                    this.BuyerPayDetail.SequenceEqual(input.BuyerPayDetail)
                ) && 
                (
                    this.FulfillmentAmount == input.FulfillmentAmount ||
                    (this.FulfillmentAmount != null &&
                    this.FulfillmentAmount.Equals(input.FulfillmentAmount))
                ) && 
                (
                    this.IsAsyncPay == input.IsAsyncPay ||
                    this.IsAsyncPay.Equals(input.IsAsyncPay)
                ) && 
                (
                    this.OrderPayMode == input.OrderPayMode ||
                    (this.OrderPayMode != null &&
                    this.OrderPayMode.Equals(input.OrderPayMode))
                ) && 
                (
                    this.OutRequestNo == input.OutRequestNo ||
                    (this.OutRequestNo != null &&
                    this.OutRequestNo.Equals(input.OutRequestNo))
                ) && 
                (
                    this.ProductCode == input.ProductCode ||
                    (this.ProductCode != null &&
                    this.ProductCode.Equals(input.ProductCode))
                ) && 
                (
                    this.TotalAmount == input.TotalAmount ||
                    (this.TotalAmount != null &&
                    this.TotalAmount.Equals(input.TotalAmount))
                ) && 
                (
                    this.TradeNo == input.TradeNo ||
                    (this.TradeNo != null &&
                    this.TradeNo.Equals(input.TradeNo))
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
                if (this.AdvancePaymentType != null)
                {
                    hashCode = (hashCode * 59) + this.AdvancePaymentType.GetHashCode();
                }
                if (this.BuyerId != null)
                {
                    hashCode = (hashCode * 59) + this.BuyerId.GetHashCode();
                }
                if (this.BuyerOpenId != null)
                {
                    hashCode = (hashCode * 59) + this.BuyerOpenId.GetHashCode();
                }
                if (this.BuyerPayDetail != null)
                {
                    hashCode = (hashCode * 59) + this.BuyerPayDetail.GetHashCode();
                }
                if (this.FulfillmentAmount != null)
                {
                    hashCode = (hashCode * 59) + this.FulfillmentAmount.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.IsAsyncPay.GetHashCode();
                if (this.OrderPayMode != null)
                {
                    hashCode = (hashCode * 59) + this.OrderPayMode.GetHashCode();
                }
                if (this.OutRequestNo != null)
                {
                    hashCode = (hashCode * 59) + this.OutRequestNo.GetHashCode();
                }
                if (this.ProductCode != null)
                {
                    hashCode = (hashCode * 59) + this.ProductCode.GetHashCode();
                }
                if (this.TotalAmount != null)
                {
                    hashCode = (hashCode * 59) + this.TotalAmount.GetHashCode();
                }
                if (this.TradeNo != null)
                {
                    hashCode = (hashCode * 59) + this.TradeNo.GetHashCode();
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
