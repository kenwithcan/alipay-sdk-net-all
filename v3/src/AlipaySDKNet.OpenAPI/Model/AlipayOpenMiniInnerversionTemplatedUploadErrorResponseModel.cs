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
    /// AlipayOpenMiniInnerversionTemplatedUploadErrorResponseModel
    /// </summary>
    [DataContract(Name = "AlipayOpenMiniInnerversionTemplatedUploadErrorResponseModel")]
    public partial class AlipayOpenMiniInnerversionTemplatedUploadErrorResponseModel : IEquatable<AlipayOpenMiniInnerversionTemplatedUploadErrorResponseModel>, IValidatableObject
    {
        /// <summary>
        /// 错误码
        /// </summary>
        /// <value>错误码</value>
        [JsonConverter(typeof(StringEnumConverter))]
        public enum CodeEnum
        {
            /// <summary>
            /// Enum APPVERSIONISBLANK for value: APP_VERSION_IS_BLANK
            /// </summary>
            [EnumMember(Value = "APP_VERSION_IS_BLANK")]
            APPVERSIONISBLANK = 1,

            /// <summary>
            /// Enum TEMPLATEIDISBLANK for value: TEMPLATE_ID_IS_BLANK
            /// </summary>
            [EnumMember(Value = "TEMPLATE_ID_IS_BLANK")]
            TEMPLATEIDISBLANK = 2,

            /// <summary>
            /// Enum VERSIONHASEXISTED for value: VERSION_HAS_EXISTED
            /// </summary>
            [EnumMember(Value = "VERSION_HAS_EXISTED")]
            VERSIONHASEXISTED = 3,

            /// <summary>
            /// Enum LARGERVERSIONHASEXISTED for value: LARGER_VERSION_HAS_EXISTED
            /// </summary>
            [EnumMember(Value = "LARGER_VERSION_HAS_EXISTED")]
            LARGERVERSIONHASEXISTED = 4,

            /// <summary>
            /// Enum APPLICATIONTYPENOTMINIAPP for value: APPLICATION_TYPE_NOT_MINIAPP
            /// </summary>
            [EnumMember(Value = "APPLICATION_TYPE_NOT_MINIAPP")]
            APPLICATIONTYPENOTMINIAPP = 5,

            /// <summary>
            /// Enum INVALIDVERSION for value: INVALID_VERSION
            /// </summary>
            [EnumMember(Value = "INVALID_VERSION")]
            INVALIDVERSION = 6,

            /// <summary>
            /// Enum DEVVERSIONEXCEEDMAXCOUNT for value: DEV_VERSION_EXCEED_MAX_COUNT
            /// </summary>
            [EnumMember(Value = "DEV_VERSION_EXCEED_MAX_COUNT")]
            DEVVERSIONEXCEEDMAXCOUNT = 7,

            /// <summary>
            /// Enum TEMPLATENOTONLINEOROFFLINE for value: TEMPLATE_NOT_ONLINE_OR_OFFLINE
            /// </summary>
            [EnumMember(Value = "TEMPLATE_NOT_ONLINE_OR_OFFLINE")]
            TEMPLATENOTONLINEOROFFLINE = 8,

            /// <summary>
            /// Enum MINIAPPPACKAGEINFONOTEXIST for value: MINI_APP_PACKAGE_INFO_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "MINI_APP_PACKAGE_INFO_NOT_EXIST")]
            MINIAPPPACKAGEINFONOTEXIST = 9,

            /// <summary>
            /// Enum TEMPLATEMINIAPPNOTALLOWED for value: TEMPLATE_MINIAPP_NOT_ALLOWED
            /// </summary>
            [EnumMember(Value = "TEMPLATE_MINIAPP_NOT_ALLOWED")]
            TEMPLATEMINIAPPNOTALLOWED = 10,

            /// <summary>
            /// Enum VERSIONEXCEEDEDLENGTH for value: VERSION_EXCEEDED_LENGTH
            /// </summary>
            [EnumMember(Value = "VERSION_EXCEEDED_LENGTH")]
            VERSIONEXCEEDEDLENGTH = 11,

            /// <summary>
            /// Enum INVALIDEXTJSON for value: INVALID_EXT_JSON
            /// </summary>
            [EnumMember(Value = "INVALID_EXT_JSON")]
            INVALIDEXTJSON = 12,

            /// <summary>
            /// Enum TEMPLATEIDISVAPPIDNOTMATCH for value: TEMPLATE_ID_ISVAPPID_NOT_MATCH
            /// </summary>
            [EnumMember(Value = "TEMPLATE_ID_ISVAPPID_NOT_MATCH")]
            TEMPLATEIDISVAPPIDNOTMATCH = 13,

            /// <summary>
            /// Enum NOAUTHRELATION for value: NO_AUTH_RELATION
            /// </summary>
            [EnumMember(Value = "NO_AUTH_RELATION")]
            NOAUTHRELATION = 14

        }


        /// <summary>
        /// 错误码
        /// </summary>
        /// <value>错误码</value>
        [DataMember(Name = "code", EmitDefaultValue = false)]
        public CodeEnum Code { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenMiniInnerversionTemplatedUploadErrorResponseModel" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected AlipayOpenMiniInnerversionTemplatedUploadErrorResponseModel() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenMiniInnerversionTemplatedUploadErrorResponseModel" /> class.
        /// </summary>
        /// <param name="code">错误码 (required).</param>
        /// <param name="links">解决方案链接.</param>
        /// <param name="message">错误描述 (required).</param>
        public AlipayOpenMiniInnerversionTemplatedUploadErrorResponseModel(CodeEnum code = default(CodeEnum), string links = default(string), string message = default(string))
        {
            this.Code = code;
            // to ensure "message" is required (not null)
            // if (message == null)
            // {
            //     throw new ArgumentNullException("message is a required property for AlipayOpenMiniInnerversionTemplatedUploadErrorResponseModel and cannot be null");
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
            sb.Append("class AlipayOpenMiniInnerversionTemplatedUploadErrorResponseModel {\n");
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
            return this.Equals(input as AlipayOpenMiniInnerversionTemplatedUploadErrorResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenMiniInnerversionTemplatedUploadErrorResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenMiniInnerversionTemplatedUploadErrorResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenMiniInnerversionTemplatedUploadErrorResponseModel input)
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
