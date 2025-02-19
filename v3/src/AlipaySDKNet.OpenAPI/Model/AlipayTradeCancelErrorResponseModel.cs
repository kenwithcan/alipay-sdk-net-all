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
    /// AlipayTradeCancelErrorResponseModel
    /// </summary>
    [DataContract(Name = "AlipayTradeCancelErrorResponseModel")]
    public partial class AlipayTradeCancelErrorResponseModel : IEquatable<AlipayTradeCancelErrorResponseModel>, IValidatableObject
    {
        /// <summary>
        /// 错误码
        /// </summary>
        /// <value>错误码</value>
        [JsonConverter(typeof(StringEnumConverter))]
        public enum CodeEnum
        {
            /// <summary>
            /// Enum AQCSYSTEMERROR for value: AQC.SYSTEM_ERROR
            /// </summary>
            [EnumMember(Value = "AQC.SYSTEM_ERROR")]
            AQCSYSTEMERROR = 1,

            /// <summary>
            /// Enum ACQINVALIDPARAMETER for value: ACQ.INVALID_PARAMETER
            /// </summary>
            [EnumMember(Value = "ACQ.INVALID_PARAMETER")]
            ACQINVALIDPARAMETER = 2,

            /// <summary>
            /// Enum ACQSELLERBALANCENOTENOUGH for value: ACQ.SELLER_BALANCE_NOT_ENOUGH
            /// </summary>
            [EnumMember(Value = "ACQ.SELLER_BALANCE_NOT_ENOUGH")]
            ACQSELLERBALANCENOTENOUGH = 3,

            /// <summary>
            /// Enum ACQREASONTRADEBEENFREEZEN for value: ACQ.REASON_TRADE_BEEN_FREEZEN
            /// </summary>
            [EnumMember(Value = "ACQ.REASON_TRADE_BEEN_FREEZEN")]
            ACQREASONTRADEBEENFREEZEN = 4,

            /// <summary>
            /// Enum ACQSYSTEMERROR for value: ACQ.SYSTEM_ERROR
            /// </summary>
            [EnumMember(Value = "ACQ.SYSTEM_ERROR")]
            ACQSYSTEMERROR = 5,

            /// <summary>
            /// Enum ACQTRADEHASFINISHED for value: ACQ.TRADE_HAS_FINISHED
            /// </summary>
            [EnumMember(Value = "ACQ.TRADE_HAS_FINISHED")]
            ACQTRADEHASFINISHED = 6,

            /// <summary>
            /// Enum ACQTRADECANCELTIMEOUT for value: ACQ.TRADE_CANCEL_TIME_OUT
            /// </summary>
            [EnumMember(Value = "ACQ.TRADE_CANCEL_TIME_OUT")]
            ACQTRADECANCELTIMEOUT = 7,

            /// <summary>
            /// Enum ACQREASONTRADEREFUNDFEEERR for value: ACQ.REASON_TRADE_REFUND_FEE_ERR
            /// </summary>
            [EnumMember(Value = "ACQ.REASON_TRADE_REFUND_FEE_ERR")]
            ACQREASONTRADEREFUNDFEEERR = 8,

            /// <summary>
            /// Enum ACQCANCELNOTALLOWED for value: ACQ.CANCEL_NOT_ALLOWED
            /// </summary>
            [EnumMember(Value = "ACQ.CANCEL_NOT_ALLOWED")]
            ACQCANCELNOTALLOWED = 9

        }


        /// <summary>
        /// 错误码
        /// </summary>
        /// <value>错误码</value>
        [DataMember(Name = "code", EmitDefaultValue = false)]
        public CodeEnum Code { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayTradeCancelErrorResponseModel" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected AlipayTradeCancelErrorResponseModel() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayTradeCancelErrorResponseModel" /> class.
        /// </summary>
        /// <param name="code">错误码 (required).</param>
        /// <param name="links">解决方案链接.</param>
        /// <param name="message">错误描述 (required).</param>
        public AlipayTradeCancelErrorResponseModel(CodeEnum code = default(CodeEnum), string links = default(string), string message = default(string))
        {
            this.Code = code;
            // to ensure "message" is required (not null)
            // if (message == null)
            // {
            //     throw new ArgumentNullException("message is a required property for AlipayTradeCancelErrorResponseModel and cannot be null");
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
            sb.Append("class AlipayTradeCancelErrorResponseModel {\n");
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
            return this.Equals(input as AlipayTradeCancelErrorResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayTradeCancelErrorResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayTradeCancelErrorResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayTradeCancelErrorResponseModel input)
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
