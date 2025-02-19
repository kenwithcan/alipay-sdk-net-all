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
    /// ZhimaCreditPeZmgoSettleUnfreezeModel
    /// </summary>
    [DataContract(Name = "ZhimaCreditPeZmgoSettleUnfreezeModel")]
    public partial class ZhimaCreditPeZmgoSettleUnfreezeModel : IEquatable<ZhimaCreditPeZmgoSettleUnfreezeModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ZhimaCreditPeZmgoSettleUnfreezeModel" /> class.
        /// </summary>
        /// <param name="agreementId">支付宝系统中用以唯一标识用户签约记录的编号，即花呗先享协议号.</param>
        /// <param name="alipayOpenId">买家在支付宝的用户id.</param>
        /// <param name="alipayUserId">买家在支付宝的用户id.</param>
        /// <param name="bizTime">解冻成功时间.</param>
        /// <param name="orderTitle">解冻的描述.</param>
        /// <param name="outRequestNo">商户本次操作的请求流水号，用于标识请求流水的唯一性，不能包含除中文、英文、数字以外的字符，需要保证在商户端不重复。由商户传入，最终返回给商户。.</param>
        /// <param name="partnerId">商户ID.</param>
        /// <param name="unfreezeAmount">解冻金额.</param>
        /// <param name="unfreezeExtendParams">unfreezeExtendParams.</param>
        public ZhimaCreditPeZmgoSettleUnfreezeModel(string agreementId = default(string), string alipayOpenId = default(string), string alipayUserId = default(string), string bizTime = default(string), string orderTitle = default(string), string outRequestNo = default(string), string partnerId = default(string), string unfreezeAmount = default(string), UnfreezeExtendParams unfreezeExtendParams = default(UnfreezeExtendParams))
        {
            this.AgreementId = agreementId;
            this.AlipayOpenId = alipayOpenId;
            this.AlipayUserId = alipayUserId;
            this.BizTime = bizTime;
            this.OrderTitle = orderTitle;
            this.OutRequestNo = outRequestNo;
            this.PartnerId = partnerId;
            this.UnfreezeAmount = unfreezeAmount;
            this.UnfreezeExtendParams = unfreezeExtendParams;
        }

        /// <summary>
        /// 支付宝系统中用以唯一标识用户签约记录的编号，即花呗先享协议号
        /// </summary>
        /// <value>支付宝系统中用以唯一标识用户签约记录的编号，即花呗先享协议号</value>
        [DataMember(Name = "agreement_id", EmitDefaultValue = false)]
        public string AgreementId { get; set; }

        /// <summary>
        /// 买家在支付宝的用户id
        /// </summary>
        /// <value>买家在支付宝的用户id</value>
        [DataMember(Name = "alipay_open_id", EmitDefaultValue = false)]
        public string AlipayOpenId { get; set; }

        /// <summary>
        /// 买家在支付宝的用户id
        /// </summary>
        /// <value>买家在支付宝的用户id</value>
        [DataMember(Name = "alipay_user_id", EmitDefaultValue = false)]
        public string AlipayUserId { get; set; }

        /// <summary>
        /// 解冻成功时间
        /// </summary>
        /// <value>解冻成功时间</value>
        [DataMember(Name = "biz_time", EmitDefaultValue = false)]
        public string BizTime { get; set; }

        /// <summary>
        /// 解冻的描述
        /// </summary>
        /// <value>解冻的描述</value>
        [DataMember(Name = "order_title", EmitDefaultValue = false)]
        public string OrderTitle { get; set; }

        /// <summary>
        /// 商户本次操作的请求流水号，用于标识请求流水的唯一性，不能包含除中文、英文、数字以外的字符，需要保证在商户端不重复。由商户传入，最终返回给商户。
        /// </summary>
        /// <value>商户本次操作的请求流水号，用于标识请求流水的唯一性，不能包含除中文、英文、数字以外的字符，需要保证在商户端不重复。由商户传入，最终返回给商户。</value>
        [DataMember(Name = "out_request_no", EmitDefaultValue = false)]
        public string OutRequestNo { get; set; }

        /// <summary>
        /// 商户ID
        /// </summary>
        /// <value>商户ID</value>
        [DataMember(Name = "partner_id", EmitDefaultValue = false)]
        public string PartnerId { get; set; }

        /// <summary>
        /// 解冻金额
        /// </summary>
        /// <value>解冻金额</value>
        [DataMember(Name = "unfreeze_amount", EmitDefaultValue = false)]
        public string UnfreezeAmount { get; set; }

        /// <summary>
        /// Gets or Sets UnfreezeExtendParams
        /// </summary>
        [DataMember(Name = "unfreeze_extend_params", EmitDefaultValue = false)]
        public UnfreezeExtendParams UnfreezeExtendParams { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ZhimaCreditPeZmgoSettleUnfreezeModel {\n");
            sb.Append("  AgreementId: ").Append(AgreementId).Append("\n");
            sb.Append("  AlipayOpenId: ").Append(AlipayOpenId).Append("\n");
            sb.Append("  AlipayUserId: ").Append(AlipayUserId).Append("\n");
            sb.Append("  BizTime: ").Append(BizTime).Append("\n");
            sb.Append("  OrderTitle: ").Append(OrderTitle).Append("\n");
            sb.Append("  OutRequestNo: ").Append(OutRequestNo).Append("\n");
            sb.Append("  PartnerId: ").Append(PartnerId).Append("\n");
            sb.Append("  UnfreezeAmount: ").Append(UnfreezeAmount).Append("\n");
            sb.Append("  UnfreezeExtendParams: ").Append(UnfreezeExtendParams).Append("\n");
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
            return this.Equals(input as ZhimaCreditPeZmgoSettleUnfreezeModel);
        }

        /// <summary>
        /// Returns true if ZhimaCreditPeZmgoSettleUnfreezeModel instances are equal
        /// </summary>
        /// <param name="input">Instance of ZhimaCreditPeZmgoSettleUnfreezeModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ZhimaCreditPeZmgoSettleUnfreezeModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AgreementId == input.AgreementId ||
                    (this.AgreementId != null &&
                    this.AgreementId.Equals(input.AgreementId))
                ) && 
                (
                    this.AlipayOpenId == input.AlipayOpenId ||
                    (this.AlipayOpenId != null &&
                    this.AlipayOpenId.Equals(input.AlipayOpenId))
                ) && 
                (
                    this.AlipayUserId == input.AlipayUserId ||
                    (this.AlipayUserId != null &&
                    this.AlipayUserId.Equals(input.AlipayUserId))
                ) && 
                (
                    this.BizTime == input.BizTime ||
                    (this.BizTime != null &&
                    this.BizTime.Equals(input.BizTime))
                ) && 
                (
                    this.OrderTitle == input.OrderTitle ||
                    (this.OrderTitle != null &&
                    this.OrderTitle.Equals(input.OrderTitle))
                ) && 
                (
                    this.OutRequestNo == input.OutRequestNo ||
                    (this.OutRequestNo != null &&
                    this.OutRequestNo.Equals(input.OutRequestNo))
                ) && 
                (
                    this.PartnerId == input.PartnerId ||
                    (this.PartnerId != null &&
                    this.PartnerId.Equals(input.PartnerId))
                ) && 
                (
                    this.UnfreezeAmount == input.UnfreezeAmount ||
                    (this.UnfreezeAmount != null &&
                    this.UnfreezeAmount.Equals(input.UnfreezeAmount))
                ) && 
                (
                    this.UnfreezeExtendParams == input.UnfreezeExtendParams ||
                    (this.UnfreezeExtendParams != null &&
                    this.UnfreezeExtendParams.Equals(input.UnfreezeExtendParams))
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
                if (this.AgreementId != null)
                {
                    hashCode = (hashCode * 59) + this.AgreementId.GetHashCode();
                }
                if (this.AlipayOpenId != null)
                {
                    hashCode = (hashCode * 59) + this.AlipayOpenId.GetHashCode();
                }
                if (this.AlipayUserId != null)
                {
                    hashCode = (hashCode * 59) + this.AlipayUserId.GetHashCode();
                }
                if (this.BizTime != null)
                {
                    hashCode = (hashCode * 59) + this.BizTime.GetHashCode();
                }
                if (this.OrderTitle != null)
                {
                    hashCode = (hashCode * 59) + this.OrderTitle.GetHashCode();
                }
                if (this.OutRequestNo != null)
                {
                    hashCode = (hashCode * 59) + this.OutRequestNo.GetHashCode();
                }
                if (this.PartnerId != null)
                {
                    hashCode = (hashCode * 59) + this.PartnerId.GetHashCode();
                }
                if (this.UnfreezeAmount != null)
                {
                    hashCode = (hashCode * 59) + this.UnfreezeAmount.GetHashCode();
                }
                if (this.UnfreezeExtendParams != null)
                {
                    hashCode = (hashCode * 59) + this.UnfreezeExtendParams.GetHashCode();
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
