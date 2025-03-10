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
    /// AlipayMarketingCampaignCashTriggerErrorResponseModel
    /// </summary>
    [DataContract(Name = "AlipayMarketingCampaignCashTriggerErrorResponseModel")]
    public partial class AlipayMarketingCampaignCashTriggerErrorResponseModel : IEquatable<AlipayMarketingCampaignCashTriggerErrorResponseModel>, IValidatableObject
    {
        /// <summary>
        /// 错误码
        /// </summary>
        /// <value>错误码</value>
        [JsonConverter(typeof(StringEnumConverter))]
        public enum CodeEnum
        {
            /// <summary>
            /// Enum BIZCONTENTISEMPTY for value: BIZ_CONTENT_IS_EMPTY
            /// </summary>
            [EnumMember(Value = "BIZ_CONTENT_IS_EMPTY")]
            BIZCONTENTISEMPTY = 1,

            /// <summary>
            /// Enum BIZCONTENTFORMATERROR for value: BIZ_CONTENT_FORMAT_ERROR
            /// </summary>
            [EnumMember(Value = "BIZ_CONTENT_FORMAT_ERROR")]
            BIZCONTENTFORMATERROR = 2,

            /// <summary>
            /// Enum PRODUCTISNOTOPENED for value: PRODUCT_IS_NOT_OPENED
            /// </summary>
            [EnumMember(Value = "PRODUCT_IS_NOT_OPENED")]
            PRODUCTISNOTOPENED = 3,

            /// <summary>
            /// Enum CASHCROWDNOILLEGAL for value: CASH_CROWD_NO_ILLEGAL
            /// </summary>
            [EnumMember(Value = "CASH_CROWD_NO_ILLEGAL")]
            CASHCROWDNOILLEGAL = 4,

            /// <summary>
            /// Enum CASHCAMPAIGNNOTEXIST for value: CASH_CAMPAIGN_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "CASH_CAMPAIGN_NOT_EXIST")]
            CASHCAMPAIGNNOTEXIST = 5,

            /// <summary>
            /// Enum CASHCAMPAIGNNOTSTART for value: CASH_CAMPAIGN_NOT_START
            /// </summary>
            [EnumMember(Value = "CASH_CAMPAIGN_NOT_START")]
            CASHCAMPAIGNNOTSTART = 6,

            /// <summary>
            /// Enum CASHCAMPAIGNISOVER for value: CASH_CAMPAIGN_IS_OVER
            /// </summary>
            [EnumMember(Value = "CASH_CAMPAIGN_IS_OVER")]
            CASHCAMPAIGNISOVER = 7,

            /// <summary>
            /// Enum CASHCAMPBUDGETINSUFFICIENT for value: CASH_CAMP_BUDGET_INSUFFICIENT
            /// </summary>
            [EnumMember(Value = "CASH_CAMP_BUDGET_INSUFFICIENT")]
            CASHCAMPBUDGETINSUFFICIENT = 8,

            /// <summary>
            /// Enum CASHCAMPNOTALLOWTRIGGEROWN for value: CASH_CAMP_NOT_ALLOW_TRIGGER_OWN
            /// </summary>
            [EnumMember(Value = "CASH_CAMP_NOT_ALLOW_TRIGGER_OWN")]
            CASHCAMPNOTALLOWTRIGGEROWN = 9,

            /// <summary>
            /// Enum CASHCAMPAIGNSENDLOGILLEGAL for value: CASH_CAMPAIGN_SEND_LOG_ILLEGAL
            /// </summary>
            [EnumMember(Value = "CASH_CAMPAIGN_SEND_LOG_ILLEGAL")]
            CASHCAMPAIGNSENDLOGILLEGAL = 10,

            /// <summary>
            /// Enum UNKNOWSYSTEMERROR for value: UNKNOW_SYSTEM_ERROR
            /// </summary>
            [EnumMember(Value = "UNKNOW_SYSTEM_ERROR")]
            UNKNOWSYSTEMERROR = 11,

            /// <summary>
            /// Enum USERIDILLEGAL for value: USER_ID_ILLEGAL
            /// </summary>
            [EnumMember(Value = "USER_ID_ILLEGAL")]
            USERIDILLEGAL = 12,

            /// <summary>
            /// Enum USERNOTEXIST for value: USER_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "USER_NOT_EXIST")]
            USERNOTEXIST = 13,

            /// <summary>
            /// Enum ENTERPRISEUSERNOTSUPPORT for value: ENTERPRISE_USER_NOT_SUPPORT
            /// </summary>
            [EnumMember(Value = "ENTERPRISE_USER_NOT_SUPPORT")]
            ENTERPRISEUSERNOTSUPPORT = 14,

            /// <summary>
            /// Enum CASHCAMPAIGNEMERGENCYSTOP for value: CASH_CAMPAIGN_EMERGENCY_STOP
            /// </summary>
            [EnumMember(Value = "CASH_CAMPAIGN_EMERGENCY_STOP")]
            CASHCAMPAIGNEMERGENCYSTOP = 15,

            /// <summary>
            /// Enum CAMPOPERATORILLEGAL for value: CAMP_OPERATOR_ILLEGAL
            /// </summary>
            [EnumMember(Value = "CAMP_OPERATOR_ILLEGAL")]
            CAMPOPERATORILLEGAL = 16,

            /// <summary>
            /// Enum CTUHASRISK for value: CTU_HAS_RISK
            /// </summary>
            [EnumMember(Value = "CTU_HAS_RISK")]
            CTUHASRISK = 17,

            /// <summary>
            /// Enum USERACCESSTOTALLIMIT for value: USER_ACCESS_TOTAL_LIMIT
            /// </summary>
            [EnumMember(Value = "USER_ACCESS_TOTAL_LIMIT")]
            USERACCESSTOTALLIMIT = 18,

            /// <summary>
            /// Enum USERACCESSFREQUENCYLIMIT for value: USER_ACCESS_FREQUENCY_LIMIT
            /// </summary>
            [EnumMember(Value = "USER_ACCESS_FREQUENCY_LIMIT")]
            USERACCESSFREQUENCYLIMIT = 19,

            /// <summary>
            /// Enum OUTBIZNOILLEGAL for value: OUT_BIZ_NO_ILLEGAL
            /// </summary>
            [EnumMember(Value = "OUT_BIZ_NO_ILLEGAL")]
            OUTBIZNOILLEGAL = 20,

            /// <summary>
            /// Enum CALLTOOFREQUENCY for value: CALL_TOO_FREQUENCY
            /// </summary>
            [EnumMember(Value = "CALL_TOO_FREQUENCY")]
            CALLTOOFREQUENCY = 21,

            /// <summary>
            /// Enum USERCERTNOTPASS for value: USER_CERT_NOT_PASS
            /// </summary>
            [EnumMember(Value = "USER_CERT_NOT_PASS")]
            USERCERTNOTPASS = 22

        }


        /// <summary>
        /// 错误码
        /// </summary>
        /// <value>错误码</value>
        [DataMember(Name = "code", EmitDefaultValue = false)]
        public CodeEnum Code { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMarketingCampaignCashTriggerErrorResponseModel" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected AlipayMarketingCampaignCashTriggerErrorResponseModel() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMarketingCampaignCashTriggerErrorResponseModel" /> class.
        /// </summary>
        /// <param name="code">错误码 (required).</param>
        /// <param name="links">解决方案链接.</param>
        /// <param name="message">错误描述 (required).</param>
        public AlipayMarketingCampaignCashTriggerErrorResponseModel(CodeEnum code = default(CodeEnum), string links = default(string), string message = default(string))
        {
            this.Code = code;
            // to ensure "message" is required (not null)
            // if (message == null)
            // {
            //     throw new ArgumentNullException("message is a required property for AlipayMarketingCampaignCashTriggerErrorResponseModel and cannot be null");
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
            sb.Append("class AlipayMarketingCampaignCashTriggerErrorResponseModel {\n");
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
            return this.Equals(input as AlipayMarketingCampaignCashTriggerErrorResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayMarketingCampaignCashTriggerErrorResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayMarketingCampaignCashTriggerErrorResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayMarketingCampaignCashTriggerErrorResponseModel input)
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
