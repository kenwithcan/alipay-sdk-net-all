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
    /// AlipayTradeAdvanceConsultResponseModel
    /// </summary>
    [DataContract(Name = "AlipayTradeAdvanceConsultResponseModel")]
    public partial class AlipayTradeAdvanceConsultResponseModel : IEquatable<AlipayTradeAdvanceConsultResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayTradeAdvanceConsultResponseModel" /> class.
        /// </summary>
        /// <param name="referResult">true 代表当前时间点，用户允许垫资 false 代表当前时间，用户不允许垫资.</param>
        /// <param name="resultCode">用户被注销.</param>
        /// <param name="resultMessage">返回用户不准入原因.</param>
        /// <param name="riskLevel">订单风险评估等级，在单笔订单风险预评估时返回。当基础风险校验通过时，可通过该值获取业务风险评估等级。取值：2-高风险；1-低风险。.</param>
        /// <param name="userRiskPrediction">userRiskPrediction.</param>
        /// <param name="waitRepaymentAmount">用户剩余的总待还金额，无论当前用户是否允许垫资，都会返回该属性。.</param>
        /// <param name="waitRepaymentOrderCount">用户总的未还的垫资笔数，无论用户是否允许垫资，都会返回该属性.</param>
        /// <param name="waitRepaymentOrderInfos">待还订单列表，无论用户当前状态是否允许垫资，都会返回当前用户在商户下的待还订单信息.</param>
        public AlipayTradeAdvanceConsultResponseModel(bool referResult = default(bool), string resultCode = default(string), string resultMessage = default(string), string riskLevel = default(string), UserRiskPrediction userRiskPrediction = default(UserRiskPrediction), string waitRepaymentAmount = default(string), int waitRepaymentOrderCount = default(int), List<WaitRepaymentOrderInfo> waitRepaymentOrderInfos = default(List<WaitRepaymentOrderInfo>))
        {
            this.ReferResult = referResult;
            this.ResultCode = resultCode;
            this.ResultMessage = resultMessage;
            this.RiskLevel = riskLevel;
            this.UserRiskPrediction = userRiskPrediction;
            this.WaitRepaymentAmount = waitRepaymentAmount;
            this.WaitRepaymentOrderCount = waitRepaymentOrderCount;
            this.WaitRepaymentOrderInfos = waitRepaymentOrderInfos;
        }

        /// <summary>
        /// true 代表当前时间点，用户允许垫资 false 代表当前时间，用户不允许垫资
        /// </summary>
        /// <value>true 代表当前时间点，用户允许垫资 false 代表当前时间，用户不允许垫资</value>
        [DataMember(Name = "refer_result", EmitDefaultValue = true)]
        public bool ReferResult { get; set; }

        /// <summary>
        /// 用户被注销
        /// </summary>
        /// <value>用户被注销</value>
        [DataMember(Name = "result_code", EmitDefaultValue = false)]
        public string ResultCode { get; set; }

        /// <summary>
        /// 返回用户不准入原因
        /// </summary>
        /// <value>返回用户不准入原因</value>
        [DataMember(Name = "result_message", EmitDefaultValue = false)]
        public string ResultMessage { get; set; }

        /// <summary>
        /// 订单风险评估等级，在单笔订单风险预评估时返回。当基础风险校验通过时，可通过该值获取业务风险评估等级。取值：2-高风险；1-低风险。
        /// </summary>
        /// <value>订单风险评估等级，在单笔订单风险预评估时返回。当基础风险校验通过时，可通过该值获取业务风险评估等级。取值：2-高风险；1-低风险。</value>
        [DataMember(Name = "risk_level", EmitDefaultValue = false)]
        public string RiskLevel { get; set; }

        /// <summary>
        /// Gets or Sets UserRiskPrediction
        /// </summary>
        [DataMember(Name = "user_risk_prediction", EmitDefaultValue = false)]
        public UserRiskPrediction UserRiskPrediction { get; set; }

        /// <summary>
        /// 用户剩余的总待还金额，无论当前用户是否允许垫资，都会返回该属性。
        /// </summary>
        /// <value>用户剩余的总待还金额，无论当前用户是否允许垫资，都会返回该属性。</value>
        [DataMember(Name = "wait_repayment_amount", EmitDefaultValue = false)]
        public string WaitRepaymentAmount { get; set; }

        /// <summary>
        /// 用户总的未还的垫资笔数，无论用户是否允许垫资，都会返回该属性
        /// </summary>
        /// <value>用户总的未还的垫资笔数，无论用户是否允许垫资，都会返回该属性</value>
        [DataMember(Name = "wait_repayment_order_count", EmitDefaultValue = false)]
        public int WaitRepaymentOrderCount { get; set; }

        /// <summary>
        /// 待还订单列表，无论用户当前状态是否允许垫资，都会返回当前用户在商户下的待还订单信息
        /// </summary>
        /// <value>待还订单列表，无论用户当前状态是否允许垫资，都会返回当前用户在商户下的待还订单信息</value>
        [DataMember(Name = "wait_repayment_order_infos", EmitDefaultValue = false)]
        public List<WaitRepaymentOrderInfo> WaitRepaymentOrderInfos { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayTradeAdvanceConsultResponseModel {\n");
            sb.Append("  ReferResult: ").Append(ReferResult).Append("\n");
            sb.Append("  ResultCode: ").Append(ResultCode).Append("\n");
            sb.Append("  ResultMessage: ").Append(ResultMessage).Append("\n");
            sb.Append("  RiskLevel: ").Append(RiskLevel).Append("\n");
            sb.Append("  UserRiskPrediction: ").Append(UserRiskPrediction).Append("\n");
            sb.Append("  WaitRepaymentAmount: ").Append(WaitRepaymentAmount).Append("\n");
            sb.Append("  WaitRepaymentOrderCount: ").Append(WaitRepaymentOrderCount).Append("\n");
            sb.Append("  WaitRepaymentOrderInfos: ").Append(WaitRepaymentOrderInfos).Append("\n");
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
            return this.Equals(input as AlipayTradeAdvanceConsultResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayTradeAdvanceConsultResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayTradeAdvanceConsultResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayTradeAdvanceConsultResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ReferResult == input.ReferResult ||
                    this.ReferResult.Equals(input.ReferResult)
                ) && 
                (
                    this.ResultCode == input.ResultCode ||
                    (this.ResultCode != null &&
                    this.ResultCode.Equals(input.ResultCode))
                ) && 
                (
                    this.ResultMessage == input.ResultMessage ||
                    (this.ResultMessage != null &&
                    this.ResultMessage.Equals(input.ResultMessage))
                ) && 
                (
                    this.RiskLevel == input.RiskLevel ||
                    (this.RiskLevel != null &&
                    this.RiskLevel.Equals(input.RiskLevel))
                ) && 
                (
                    this.UserRiskPrediction == input.UserRiskPrediction ||
                    (this.UserRiskPrediction != null &&
                    this.UserRiskPrediction.Equals(input.UserRiskPrediction))
                ) && 
                (
                    this.WaitRepaymentAmount == input.WaitRepaymentAmount ||
                    (this.WaitRepaymentAmount != null &&
                    this.WaitRepaymentAmount.Equals(input.WaitRepaymentAmount))
                ) && 
                (
                    this.WaitRepaymentOrderCount == input.WaitRepaymentOrderCount ||
                    this.WaitRepaymentOrderCount.Equals(input.WaitRepaymentOrderCount)
                ) && 
                (
                    this.WaitRepaymentOrderInfos == input.WaitRepaymentOrderInfos ||
                    this.WaitRepaymentOrderInfos != null &&
                    input.WaitRepaymentOrderInfos != null &&
                    this.WaitRepaymentOrderInfos.SequenceEqual(input.WaitRepaymentOrderInfos)
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
                hashCode = (hashCode * 59) + this.ReferResult.GetHashCode();
                if (this.ResultCode != null)
                {
                    hashCode = (hashCode * 59) + this.ResultCode.GetHashCode();
                }
                if (this.ResultMessage != null)
                {
                    hashCode = (hashCode * 59) + this.ResultMessage.GetHashCode();
                }
                if (this.RiskLevel != null)
                {
                    hashCode = (hashCode * 59) + this.RiskLevel.GetHashCode();
                }
                if (this.UserRiskPrediction != null)
                {
                    hashCode = (hashCode * 59) + this.UserRiskPrediction.GetHashCode();
                }
                if (this.WaitRepaymentAmount != null)
                {
                    hashCode = (hashCode * 59) + this.WaitRepaymentAmount.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.WaitRepaymentOrderCount.GetHashCode();
                if (this.WaitRepaymentOrderInfos != null)
                {
                    hashCode = (hashCode * 59) + this.WaitRepaymentOrderInfos.GetHashCode();
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
