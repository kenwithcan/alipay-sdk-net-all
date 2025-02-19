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
    /// AlipayEbppPdeductPayResponseModel
    /// </summary>
    [DataContract(Name = "AlipayEbppPdeductPayResponseModel")]
    public partial class AlipayEbppPdeductPayResponseModel : IEquatable<AlipayEbppPdeductPayResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayEbppPdeductPayResponseModel" /> class.
        /// </summary>
        /// <param name="agreementId">支付宝代扣协议ID.</param>
        /// <param name="billNo">支付宝订单流水号.</param>
        /// <param name="extendField">扩展参数.</param>
        /// <param name="outOrderNo">商户代扣业务流水.</param>
        /// <param name="resultCode">针对于支付失败时，给的对应错误明细，如果判断外围的错误码是INVOKE_PAYACCEPTANCE_EXCEPTION需要近一步再结合着结果模型中的result_code, result_msg来判断.</param>
        /// <param name="resultMsg">针对于支付失败时，给的对应错误明细，如果判断外围的错误码是INVOKE_PAYACCEPTANCE_EXCEPTION需要近一步再结合着结果模型中的result_code, result_msg来判断.</param>
        /// <param name="resultStatus">订单支付状态。  0：未知  1：成功  2：失败.</param>
        public AlipayEbppPdeductPayResponseModel(string agreementId = default(string), string billNo = default(string), string extendField = default(string), string outOrderNo = default(string), string resultCode = default(string), string resultMsg = default(string), string resultStatus = default(string))
        {
            this.AgreementId = agreementId;
            this.BillNo = billNo;
            this.ExtendField = extendField;
            this.OutOrderNo = outOrderNo;
            this.ResultCode = resultCode;
            this.ResultMsg = resultMsg;
            this.ResultStatus = resultStatus;
        }

        /// <summary>
        /// 支付宝代扣协议ID
        /// </summary>
        /// <value>支付宝代扣协议ID</value>
        [DataMember(Name = "agreement_id", EmitDefaultValue = false)]
        public string AgreementId { get; set; }

        /// <summary>
        /// 支付宝订单流水号
        /// </summary>
        /// <value>支付宝订单流水号</value>
        [DataMember(Name = "bill_no", EmitDefaultValue = false)]
        public string BillNo { get; set; }

        /// <summary>
        /// 扩展参数
        /// </summary>
        /// <value>扩展参数</value>
        [DataMember(Name = "extend_field", EmitDefaultValue = false)]
        public string ExtendField { get; set; }

        /// <summary>
        /// 商户代扣业务流水
        /// </summary>
        /// <value>商户代扣业务流水</value>
        [DataMember(Name = "out_order_no", EmitDefaultValue = false)]
        public string OutOrderNo { get; set; }

        /// <summary>
        /// 针对于支付失败时，给的对应错误明细，如果判断外围的错误码是INVOKE_PAYACCEPTANCE_EXCEPTION需要近一步再结合着结果模型中的result_code, result_msg来判断
        /// </summary>
        /// <value>针对于支付失败时，给的对应错误明细，如果判断外围的错误码是INVOKE_PAYACCEPTANCE_EXCEPTION需要近一步再结合着结果模型中的result_code, result_msg来判断</value>
        [DataMember(Name = "result_code", EmitDefaultValue = false)]
        public string ResultCode { get; set; }

        /// <summary>
        /// 针对于支付失败时，给的对应错误明细，如果判断外围的错误码是INVOKE_PAYACCEPTANCE_EXCEPTION需要近一步再结合着结果模型中的result_code, result_msg来判断
        /// </summary>
        /// <value>针对于支付失败时，给的对应错误明细，如果判断外围的错误码是INVOKE_PAYACCEPTANCE_EXCEPTION需要近一步再结合着结果模型中的result_code, result_msg来判断</value>
        [DataMember(Name = "result_msg", EmitDefaultValue = false)]
        public string ResultMsg { get; set; }

        /// <summary>
        /// 订单支付状态。  0：未知  1：成功  2：失败
        /// </summary>
        /// <value>订单支付状态。  0：未知  1：成功  2：失败</value>
        [DataMember(Name = "result_status", EmitDefaultValue = false)]
        public string ResultStatus { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayEbppPdeductPayResponseModel {\n");
            sb.Append("  AgreementId: ").Append(AgreementId).Append("\n");
            sb.Append("  BillNo: ").Append(BillNo).Append("\n");
            sb.Append("  ExtendField: ").Append(ExtendField).Append("\n");
            sb.Append("  OutOrderNo: ").Append(OutOrderNo).Append("\n");
            sb.Append("  ResultCode: ").Append(ResultCode).Append("\n");
            sb.Append("  ResultMsg: ").Append(ResultMsg).Append("\n");
            sb.Append("  ResultStatus: ").Append(ResultStatus).Append("\n");
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
            return this.Equals(input as AlipayEbppPdeductPayResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayEbppPdeductPayResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayEbppPdeductPayResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayEbppPdeductPayResponseModel input)
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
                    this.BillNo == input.BillNo ||
                    (this.BillNo != null &&
                    this.BillNo.Equals(input.BillNo))
                ) && 
                (
                    this.ExtendField == input.ExtendField ||
                    (this.ExtendField != null &&
                    this.ExtendField.Equals(input.ExtendField))
                ) && 
                (
                    this.OutOrderNo == input.OutOrderNo ||
                    (this.OutOrderNo != null &&
                    this.OutOrderNo.Equals(input.OutOrderNo))
                ) && 
                (
                    this.ResultCode == input.ResultCode ||
                    (this.ResultCode != null &&
                    this.ResultCode.Equals(input.ResultCode))
                ) && 
                (
                    this.ResultMsg == input.ResultMsg ||
                    (this.ResultMsg != null &&
                    this.ResultMsg.Equals(input.ResultMsg))
                ) && 
                (
                    this.ResultStatus == input.ResultStatus ||
                    (this.ResultStatus != null &&
                    this.ResultStatus.Equals(input.ResultStatus))
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
                if (this.BillNo != null)
                {
                    hashCode = (hashCode * 59) + this.BillNo.GetHashCode();
                }
                if (this.ExtendField != null)
                {
                    hashCode = (hashCode * 59) + this.ExtendField.GetHashCode();
                }
                if (this.OutOrderNo != null)
                {
                    hashCode = (hashCode * 59) + this.OutOrderNo.GetHashCode();
                }
                if (this.ResultCode != null)
                {
                    hashCode = (hashCode * 59) + this.ResultCode.GetHashCode();
                }
                if (this.ResultMsg != null)
                {
                    hashCode = (hashCode * 59) + this.ResultMsg.GetHashCode();
                }
                if (this.ResultStatus != null)
                {
                    hashCode = (hashCode * 59) + this.ResultStatus.GetHashCode();
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
