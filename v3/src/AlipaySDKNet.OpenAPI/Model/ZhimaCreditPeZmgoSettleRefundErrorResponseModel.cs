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
    /// ZhimaCreditPeZmgoSettleRefundErrorResponseModel
    /// </summary>
    [DataContract(Name = "ZhimaCreditPeZmgoSettleRefundErrorResponseModel")]
    public partial class ZhimaCreditPeZmgoSettleRefundErrorResponseModel : IEquatable<ZhimaCreditPeZmgoSettleRefundErrorResponseModel>, IValidatableObject
    {
        /// <summary>
        /// 错误码
        /// </summary>
        /// <value>错误码</value>
        [JsonConverter(typeof(StringEnumConverter))]
        public enum CodeEnum
        {
            /// <summary>
            /// Enum SYSTEMERROR for value: SYSTEM_ERROR
            /// </summary>
            [EnumMember(Value = "SYSTEM_ERROR")]
            SYSTEMERROR = 1,

            /// <summary>
            /// Enum INVALIDPARAMETER for value: INVALID_PARAMETER
            /// </summary>
            [EnumMember(Value = "INVALID_PARAMETER")]
            INVALIDPARAMETER = 2,

            /// <summary>
            /// Enum AGREEMENTNOTEXIST for value: AGREEMENT_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "AGREEMENT_NOT_EXIST")]
            AGREEMENTNOTEXIST = 3,

            /// <summary>
            /// Enum REFUNDAMOUNTCHECKERROR for value: REFUND_AMOUNT_CHECK_ERROR
            /// </summary>
            [EnumMember(Value = "REFUND_AMOUNT_CHECK_ERROR")]
            REFUNDAMOUNTCHECKERROR = 4,

            /// <summary>
            /// Enum REQUESTPARAMILLEGAL for value: REQUEST_PARAM_ILLEGAL
            /// </summary>
            [EnumMember(Value = "REQUEST_PARAM_ILLEGAL")]
            REQUESTPARAMILLEGAL = 5,

            /// <summary>
            /// Enum REQUESTACCESSILLEGAL for value: REQUEST_ACCESS_ILLEGAL
            /// </summary>
            [EnumMember(Value = "REQUEST_ACCESS_ILLEGAL")]
            REQUESTACCESSILLEGAL = 6,

            /// <summary>
            /// Enum REFUNDPARAMISERROR for value: REFUND_PARAM_IS_ERROR
            /// </summary>
            [EnumMember(Value = "REFUND_PARAM_IS_ERROR")]
            REFUNDPARAMISERROR = 7,

            /// <summary>
            /// Enum REFUNDAGREEMENTSTATUSNOTSUPPORT for value: REFUND_AGREEMENT_STATUS_NOT_SUPPORT
            /// </summary>
            [EnumMember(Value = "REFUND_AGREEMENT_STATUS_NOT_SUPPORT")]
            REFUNDAGREEMENTSTATUSNOTSUPPORT = 8,

            /// <summary>
            /// Enum AUTHOPTORDERNOTEXIST for value: AUTH_OPT_ORDER_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "AUTH_OPT_ORDER_NOT_EXIST")]
            AUTHOPTORDERNOTEXIST = 9,

            /// <summary>
            /// Enum REFUNDOPTORDERNOTUNIQUE for value: REFUND_OPT_ORDER_NOT_UNIQUE
            /// </summary>
            [EnumMember(Value = "REFUND_OPT_ORDER_NOT_UNIQUE")]
            REFUNDOPTORDERNOTUNIQUE = 10,

            /// <summary>
            /// Enum REFUNDOPTORDERNOTEXIST for value: REFUND_OPT_ORDER_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "REFUND_OPT_ORDER_NOT_EXIST")]
            REFUNDOPTORDERNOTEXIST = 11,

            /// <summary>
            /// Enum REFUNDTRADENONOTEXIST for value: REFUND_TRADE_NO_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "REFUND_TRADE_NO_NOT_EXIST")]
            REFUNDTRADENONOTEXIST = 12,

            /// <summary>
            /// Enum REFUNDREQUESTNOIDEMPOTENTFAIL for value: REFUND_REQUEST_NO_IDEMPOTENT_FAIL
            /// </summary>
            [EnumMember(Value = "REFUND_REQUEST_NO_IDEMPOTENT_FAIL")]
            REFUNDREQUESTNOIDEMPOTENTFAIL = 13,

            /// <summary>
            /// Enum AGREEMENTANDUSERNOTMATCH for value: AGREEMENT_AND_USER_NOT_MATCH
            /// </summary>
            [EnumMember(Value = "AGREEMENT_AND_USER_NOT_MATCH")]
            AGREEMENTANDUSERNOTMATCH = 14,

            /// <summary>
            /// Enum REFUNDAMOUNTISILLEGAL for value: REFUND_AMOUNT_IS_ILLEGAL
            /// </summary>
            [EnumMember(Value = "REFUND_AMOUNT_IS_ILLEGAL")]
            REFUNDAMOUNTISILLEGAL = 15,

            /// <summary>
            /// Enum REFUNDPAYAMOUNTISEMPTY for value: REFUND_PAY_AMOUNT_IS_EMPTY
            /// </summary>
            [EnumMember(Value = "REFUND_PAY_AMOUNT_IS_EMPTY")]
            REFUNDPAYAMOUNTISEMPTY = 16,

            /// <summary>
            /// Enum REFUNDAMOUNTISZERO for value: REFUND_AMOUNT_IS_ZERO
            /// </summary>
            [EnumMember(Value = "REFUND_AMOUNT_IS_ZERO")]
            REFUNDAMOUNTISZERO = 17,

            /// <summary>
            /// Enum TRADENOANDAUTHOPTNOTMATCH for value: TRADENO_AND_AUTHOPT_NOT_MATCH
            /// </summary>
            [EnumMember(Value = "TRADENO_AND_AUTHOPT_NOT_MATCH")]
            TRADENOANDAUTHOPTNOTMATCH = 18,

            /// <summary>
            /// Enum OPTIDANDTRADENOALLEMPTY for value: OPTID_AND_TRADENO_ALL_EMPTY
            /// </summary>
            [EnumMember(Value = "OPTID_AND_TRADENO_ALL_EMPTY")]
            OPTIDANDTRADENOALLEMPTY = 19,

            /// <summary>
            /// Enum AGREEMENTANDPARTNERNOTMATCH for value: AGREEMENT_AND_PARTNER_NOT_MATCH
            /// </summary>
            [EnumMember(Value = "AGREEMENT_AND_PARTNER_NOT_MATCH")]
            AGREEMENTANDPARTNERNOTMATCH = 20,

            /// <summary>
            /// Enum REFUNDLASTTIMESUCCESS for value: REFUND_LAST_TIME_SUCCESS
            /// </summary>
            [EnumMember(Value = "REFUND_LAST_TIME_SUCCESS")]
            REFUNDLASTTIMESUCCESS = 21,

            /// <summary>
            /// Enum REFUNDLASTTIMEFAIL for value: REFUND_LAST_TIME_FAIL
            /// </summary>
            [EnumMember(Value = "REFUND_LAST_TIME_FAIL")]
            REFUNDLASTTIMEFAIL = 22,

            /// <summary>
            /// Enum REFUNDLASTTIMEINIT for value: REFUND_LAST_TIME_INIT
            /// </summary>
            [EnumMember(Value = "REFUND_LAST_TIME_INIT")]
            REFUNDLASTTIMEINIT = 23,

            /// <summary>
            /// Enum REFUNDAGREEMENTNOTEXIST for value: REFUND_AGREEMENT_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "REFUND_AGREEMENT_NOT_EXIST")]
            REFUNDAGREEMENTNOTEXIST = 24,

            /// <summary>
            /// Enum UNITRADEPRODEXECUTEERROR for value: UNITRADEPROD_EXECUTE_ERROR
            /// </summary>
            [EnumMember(Value = "UNITRADEPROD_EXECUTE_ERROR")]
            UNITRADEPRODEXECUTEERROR = 25,

            /// <summary>
            /// Enum TRADEHASCLOSE for value: TRADE_HAS_CLOSE
            /// </summary>
            [EnumMember(Value = "TRADE_HAS_CLOSE")]
            TRADEHASCLOSE = 26,

            /// <summary>
            /// Enum SELLERBALANCENOTENOUGH for value: SELLER_BALANCE_NOT_ENOUGH
            /// </summary>
            [EnumMember(Value = "SELLER_BALANCE_NOT_ENOUGH")]
            SELLERBALANCENOTENOUGH = 27,

            /// <summary>
            /// Enum REFUNDAMTNOTEQUALTOTAL for value: REFUND_AMT_NOT_EQUAL_TOTAL
            /// </summary>
            [EnumMember(Value = "REFUND_AMT_NOT_EQUAL_TOTAL")]
            REFUNDAMTNOTEQUALTOTAL = 28,

            /// <summary>
            /// Enum TRADENOTEXIST for value: TRADE_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "TRADE_NOT_EXIST")]
            TRADENOTEXIST = 29,

            /// <summary>
            /// Enum TRADEHASFINISHED for value: TRADE_HAS_FINISHED
            /// </summary>
            [EnumMember(Value = "TRADE_HAS_FINISHED")]
            TRADEHASFINISHED = 30,

            /// <summary>
            /// Enum REASONTRADEREFUNDFEEERR for value: REASON_TRADE_REFUND_FEE_ERR
            /// </summary>
            [EnumMember(Value = "REASON_TRADE_REFUND_FEE_ERR")]
            REASONTRADEREFUNDFEEERR = 31,

            /// <summary>
            /// Enum TRADENOTALLOWREFUND for value: TRADE_NOT_ALLOW_REFUND
            /// </summary>
            [EnumMember(Value = "TRADE_NOT_ALLOW_REFUND")]
            TRADENOTALLOWREFUND = 32,

            /// <summary>
            /// Enum REFUNDFEEERROR for value: REFUND_FEE_ERROR
            /// </summary>
            [EnumMember(Value = "REFUND_FEE_ERROR")]
            REFUNDFEEERROR = 33,

            /// <summary>
            /// Enum REASONTRADEBEENFREEZEN for value: REASON_TRADE_BEEN_FREEZEN
            /// </summary>
            [EnumMember(Value = "REASON_TRADE_BEEN_FREEZEN")]
            REASONTRADEBEENFREEZEN = 34,

            /// <summary>
            /// Enum TRADESTATUSERROR for value: TRADE_STATUS_ERROR
            /// </summary>
            [EnumMember(Value = "TRADE_STATUS_ERROR")]
            TRADESTATUSERROR = 35,

            /// <summary>
            /// Enum REFUNDLASTTIMEACCEPT for value: REFUND_LAST_TIME_ACCEPT
            /// </summary>
            [EnumMember(Value = "REFUND_LAST_TIME_ACCEPT")]
            REFUNDLASTTIMEACCEPT = 36,

            /// <summary>
            /// Enum REFUNDPAYAMOUNTISZERO for value: REFUND_PAY_AMOUNT_IS_ZERO
            /// </summary>
            [EnumMember(Value = "REFUND_PAY_AMOUNT_IS_ZERO")]
            REFUNDPAYAMOUNTISZERO = 37,

            /// <summary>
            /// Enum SETTLEREFUNDERROR for value: SETTLE_REFUND_ERROR
            /// </summary>
            [EnumMember(Value = "SETTLE_REFUND_ERROR")]
            SETTLEREFUNDERROR = 38,

            /// <summary>
            /// Enum SETTLEREFUNDAMOUNTERROR for value: SETTLE_REFUND_AMOUNT_ERROR
            /// </summary>
            [EnumMember(Value = "SETTLE_REFUND_AMOUNT_ERROR")]
            SETTLEREFUNDAMOUNTERROR = 39,

            /// <summary>
            /// Enum SETTLEWITHHOLDPLANNOTEXIST for value: SETTLE_WITHHOLD_PLAN_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "SETTLE_WITHHOLD_PLAN_NOT_EXIST")]
            SETTLEWITHHOLDPLANNOTEXIST = 40,

            /// <summary>
            /// Enum SETTLEWITHHOLDPLANSTATUSERROR for value: SETTLE_WITHHOLD_PLAN_STATUS_ERROR
            /// </summary>
            [EnumMember(Value = "SETTLE_WITHHOLD_PLAN_STATUS_ERROR")]
            SETTLEWITHHOLDPLANSTATUSERROR = 41,

            /// <summary>
            /// Enum SETTLEREFUNDBALANCEERROR for value: SETTLE_REFUND_BALANCE_ERROR
            /// </summary>
            [EnumMember(Value = "SETTLE_REFUND_BALANCE_ERROR")]
            SETTLEREFUNDBALANCEERROR = 42,

            /// <summary>
            /// Enum SETTLEBIZAGREEMENTNOTEXIST for value: SETTLE_BIZ_AGREEMENT_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "SETTLE_BIZ_AGREEMENT_NOT_EXIST")]
            SETTLEBIZAGREEMENTNOTEXIST = 43,

            /// <summary>
            /// Enum SETTLEREFUNDREQUESTNOERROR for value: SETTLE_REFUND_REQUEST_NO_ERROR
            /// </summary>
            [EnumMember(Value = "SETTLE_REFUND_REQUEST_NO_ERROR")]
            SETTLEREFUNDREQUESTNOERROR = 44,

            /// <summary>
            /// Enum SETTLEREFUNDILLEGALACCESS for value: SETTLE_REFUND_ILLEGAL_ACCESS
            /// </summary>
            [EnumMember(Value = "SETTLE_REFUND_ILLEGAL_ACCESS")]
            SETTLEREFUNDILLEGALACCESS = 45,

            /// <summary>
            /// Enum SETTLEREFUNDTIMEERROR for value: SETTLE_REFUND_TIME_ERROR
            /// </summary>
            [EnumMember(Value = "SETTLE_REFUND_TIME_ERROR")]
            SETTLEREFUNDTIMEERROR = 46,

            /// <summary>
            /// Enum SETTLEREFUNDNOTSUPPORT for value: SETTLE_REFUND_NOT_SUPPORT
            /// </summary>
            [EnumMember(Value = "SETTLE_REFUND_NOT_SUPPORT")]
            SETTLEREFUNDNOTSUPPORT = 47

        }


        /// <summary>
        /// 错误码
        /// </summary>
        /// <value>错误码</value>
        [DataMember(Name = "code", EmitDefaultValue = false)]
        public CodeEnum Code { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="ZhimaCreditPeZmgoSettleRefundErrorResponseModel" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected ZhimaCreditPeZmgoSettleRefundErrorResponseModel() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="ZhimaCreditPeZmgoSettleRefundErrorResponseModel" /> class.
        /// </summary>
        /// <param name="code">错误码 (required).</param>
        /// <param name="links">解决方案链接.</param>
        /// <param name="message">错误描述 (required).</param>
        public ZhimaCreditPeZmgoSettleRefundErrorResponseModel(CodeEnum code = default(CodeEnum), string links = default(string), string message = default(string))
        {
            this.Code = code;
            // to ensure "message" is required (not null)
            // if (message == null)
            // {
            //     throw new ArgumentNullException("message is a required property for ZhimaCreditPeZmgoSettleRefundErrorResponseModel and cannot be null");
            // }
            this.Message = message;
            this.Links = links;
        }

        /// <summary>
        /// 解决方案链接
        /// </summary>
        /// <value>解决方案链接</value>
        [DataMember(Name = "links", EmitDefaultValue = false)]
        public string Links { get; set; }

        /// <summary>
        /// 错误描述
        /// </summary>
        /// <value>错误描述</value>
        [DataMember(Name = "message", EmitDefaultValue = false)]
        public string Message { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ZhimaCreditPeZmgoSettleRefundErrorResponseModel {\n");
            sb.Append("  Code: ").Append(Code).Append("\n");
            sb.Append("  Links: ").Append(Links).Append("\n");
            sb.Append("  Message: ").Append(Message).Append("\n");
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
            return this.Equals(input as ZhimaCreditPeZmgoSettleRefundErrorResponseModel);
        }

        /// <summary>
        /// Returns true if ZhimaCreditPeZmgoSettleRefundErrorResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of ZhimaCreditPeZmgoSettleRefundErrorResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ZhimaCreditPeZmgoSettleRefundErrorResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Code == input.Code ||
                    this.Code.Equals(input.Code)
                ) && 
                (
                    this.Links == input.Links ||
                    (this.Links != null &&
                    this.Links.Equals(input.Links))
                ) && 
                (
                    this.Message == input.Message ||
                    (this.Message != null &&
                    this.Message.Equals(input.Message))
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
                hashCode = (hashCode * 59) + this.Code.GetHashCode();
                if (this.Links != null)
                {
                    hashCode = (hashCode * 59) + this.Links.GetHashCode();
                }
                if (this.Message != null)
                {
                    hashCode = (hashCode * 59) + this.Message.GetHashCode();
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
