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
    /// AlipayOpenPublicPersonalizedExtensionCreateErrorResponseModel
    /// </summary>
    [DataContract(Name = "AlipayOpenPublicPersonalizedExtensionCreateErrorResponseModel")]
    public partial class AlipayOpenPublicPersonalizedExtensionCreateErrorResponseModel : IEquatable<AlipayOpenPublicPersonalizedExtensionCreateErrorResponseModel>, IValidatableObject
    {
        /// <summary>
        /// 错误码
        /// </summary>
        /// <value>错误码</value>
        [JsonConverter(typeof(StringEnumConverter))]
        public enum CodeEnum
        {
            /// <summary>
            /// Enum EXTENSIONAREASISEMPTY for value: EXTENSION_AREAS_IS_EMPTY
            /// </summary>
            [EnumMember(Value = "EXTENSION_AREAS_IS_EMPTY")]
            EXTENSIONAREASISEMPTY = 1,

            /// <summary>
            /// Enum AREACOUNTINVALID for value: AREA_COUNT_INVALID
            /// </summary>
            [EnumMember(Value = "AREA_COUNT_INVALID")]
            AREACOUNTINVALID = 2,

            /// <summary>
            /// Enum LABELRULESISEMPTY for value: LABEL_RULES_IS_EMPTY
            /// </summary>
            [EnumMember(Value = "LABEL_RULES_IS_EMPTY")]
            LABELRULESISEMPTY = 3,

            /// <summary>
            /// Enum RULECOUNTINVALID for value: RULE_COUNT_INVALID
            /// </summary>
            [EnumMember(Value = "RULE_COUNT_INVALID")]
            RULECOUNTINVALID = 4,

            /// <summary>
            /// Enum ILLEGALBIZPARAMS for value: ILLEGAL_BIZ_PARAMS
            /// </summary>
            [EnumMember(Value = "ILLEGAL_BIZ_PARAMS")]
            ILLEGALBIZPARAMS = 5,

            /// <summary>
            /// Enum EXTENSIONPARAMURLERROR for value: EXTENSION_PARAM_URL_ERROR
            /// </summary>
            [EnumMember(Value = "EXTENSION_PARAM_URL_ERROR")]
            EXTENSIONPARAMURLERROR = 6,

            /// <summary>
            /// Enum EXTENSIONPARAMTYPEERROR for value: EXTENSION_PARAM_TYPE_ERROR
            /// </summary>
            [EnumMember(Value = "EXTENSION_PARAM_TYPE_ERROR")]
            EXTENSIONPARAMTYPEERROR = 7,

            /// <summary>
            /// Enum AREAHEIGHTISINVALID for value: AREA_HEIGHT_IS_INVALID
            /// </summary>
            [EnumMember(Value = "AREA_HEIGHT_IS_INVALID")]
            AREAHEIGHTISINVALID = 8,

            /// <summary>
            /// Enum GOTOURLISINVALID for value: GOTO_URL_IS_INVALID
            /// </summary>
            [EnumMember(Value = "GOTO_URL_IS_INVALID")]
            GOTOURLISINVALID = 9,

            /// <summary>
            /// Enum LABELIDISEMPTY for value: LABEL_ID_IS_EMPTY
            /// </summary>
            [EnumMember(Value = "LABEL_ID_IS_EMPTY")]
            LABELIDISEMPTY = 10,

            /// <summary>
            /// Enum LABELVALUEISEMPTY for value: LABEL_VALUE_IS_EMPTY
            /// </summary>
            [EnumMember(Value = "LABEL_VALUE_IS_EMPTY")]
            LABELVALUEISEMPTY = 11,

            /// <summary>
            /// Enum LABELVALUEINVALID for value: LABEL_VALUE_INVALID
            /// </summary>
            [EnumMember(Value = "LABEL_VALUE_INVALID")]
            LABELVALUEINVALID = 12,

            /// <summary>
            /// Enum LABELNOTEXISTS for value: LABEL_NOT_EXISTS
            /// </summary>
            [EnumMember(Value = "LABEL_NOT_EXISTS")]
            LABELNOTEXISTS = 13,

            /// <summary>
            /// Enum RULECONTENTINVALID for value: RULE_CONTENT_INVALID
            /// </summary>
            [EnumMember(Value = "RULE_CONTENT_INVALID")]
            RULECONTENTINVALID = 14,

            /// <summary>
            /// Enum OPERATORISINVALID for value: OPERATOR_IS_INVALID
            /// </summary>
            [EnumMember(Value = "OPERATOR_IS_INVALID")]
            OPERATORISINVALID = 15,

            /// <summary>
            /// Enum SYSTEMERROR for value: SYSTEM_ERROR
            /// </summary>
            [EnumMember(Value = "SYSTEM_ERROR")]
            SYSTEMERROR = 16,

            /// <summary>
            /// Enum EXTENSIONSTATUSINVALID for value: EXTENSION_STATUS_INVALID
            /// </summary>
            [EnumMember(Value = "EXTENSION_STATUS_INVALID")]
            EXTENSIONSTATUSINVALID = 17,

            /// <summary>
            /// Enum AUTHORIZENOTADMIT for value: AUTHORIZE_NOT_ADMIT
            /// </summary>
            [EnumMember(Value = "AUTHORIZE_NOT_ADMIT")]
            AUTHORIZENOTADMIT = 18

        }


        /// <summary>
        /// 错误码
        /// </summary>
        /// <value>错误码</value>
        [DataMember(Name = "code", EmitDefaultValue = false)]
        public CodeEnum Code { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenPublicPersonalizedExtensionCreateErrorResponseModel" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected AlipayOpenPublicPersonalizedExtensionCreateErrorResponseModel() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenPublicPersonalizedExtensionCreateErrorResponseModel" /> class.
        /// </summary>
        /// <param name="code">错误码 (required).</param>
        /// <param name="links">解决方案链接.</param>
        /// <param name="message">错误描述 (required).</param>
        public AlipayOpenPublicPersonalizedExtensionCreateErrorResponseModel(CodeEnum code = default(CodeEnum), string links = default(string), string message = default(string))
        {
            this.Code = code;
            // to ensure "message" is required (not null)
            // if (message == null)
            // {
            //     throw new ArgumentNullException("message is a required property for AlipayOpenPublicPersonalizedExtensionCreateErrorResponseModel and cannot be null");
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
            sb.Append("class AlipayOpenPublicPersonalizedExtensionCreateErrorResponseModel {\n");
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
            return this.Equals(input as AlipayOpenPublicPersonalizedExtensionCreateErrorResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenPublicPersonalizedExtensionCreateErrorResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenPublicPersonalizedExtensionCreateErrorResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenPublicPersonalizedExtensionCreateErrorResponseModel input)
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
