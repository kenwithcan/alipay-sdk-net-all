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
    /// AlipayOpenMiniVersionUploadErrorResponseModel
    /// </summary>
    [DataContract(Name = "AlipayOpenMiniVersionUploadErrorResponseModel")]
    public partial class AlipayOpenMiniVersionUploadErrorResponseModel : IEquatable<AlipayOpenMiniVersionUploadErrorResponseModel>, IValidatableObject
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
            /// Enum APPVERSIONISBLANK for value: APP_VERSION_IS_BLANK
            /// </summary>
            [EnumMember(Value = "APP_VERSION_IS_BLANK")]
            APPVERSIONISBLANK = 2,

            /// <summary>
            /// Enum TEMPLATEIDISBLANK for value: TEMPLATE_ID_IS_BLANK
            /// </summary>
            [EnumMember(Value = "TEMPLATE_ID_IS_BLANK")]
            TEMPLATEIDISBLANK = 3,

            /// <summary>
            /// Enum CODETEMPLATENOTEXIST for value: CODE_TEMPLATE_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "CODE_TEMPLATE_NOT_EXIST")]
            CODETEMPLATENOTEXIST = 4,

            /// <summary>
            /// Enum CODETEMPLATENOTSAFE for value: CODE_TEMPLATE_NOT_SAFE
            /// </summary>
            [EnumMember(Value = "CODE_TEMPLATE_NOT_SAFE")]
            CODETEMPLATENOTSAFE = 5,

            /// <summary>
            /// Enum CODETEMPLATEDELETED for value: CODE_TEMPLATE_DELETED
            /// </summary>
            [EnumMember(Value = "CODE_TEMPLATE_DELETED")]
            CODETEMPLATEDELETED = 6,

            /// <summary>
            /// Enum NOAUTHRELATION for value: NO_AUTH_RELATION
            /// </summary>
            [EnumMember(Value = "NO_AUTH_RELATION")]
            NOAUTHRELATION = 7,

            /// <summary>
            /// Enum VERSIONHASEXISTED for value: VERSION_HAS_EXISTED
            /// </summary>
            [EnumMember(Value = "VERSION_HAS_EXISTED")]
            VERSIONHASEXISTED = 8,

            /// <summary>
            /// Enum LARGERVERSIONHASEXISTED for value: LARGER_VERSION_HAS_EXISTED
            /// </summary>
            [EnumMember(Value = "LARGER_VERSION_HAS_EXISTED")]
            LARGERVERSIONHASEXISTED = 9,

            /// <summary>
            /// Enum APPLICATIONTYPENOTMINIAPP for value: APPLICATION_TYPE_NOT_MINIAPP
            /// </summary>
            [EnumMember(Value = "APPLICATION_TYPE_NOT_MINIAPP")]
            APPLICATIONTYPENOTMINIAPP = 10,

            /// <summary>
            /// Enum ISVAPPIDISBLANK for value: ISV_APP_ID_IS_BLANK
            /// </summary>
            [EnumMember(Value = "ISV_APP_ID_IS_BLANK")]
            ISVAPPIDISBLANK = 11,

            /// <summary>
            /// Enum INVALIDVERSION for value: INVALID_VERSION
            /// </summary>
            [EnumMember(Value = "INVALID_VERSION")]
            INVALIDVERSION = 12,

            /// <summary>
            /// Enum DEVVERSIONEXCEEDMAXCOUNT for value: DEV_VERSION_EXCEED_MAX_COUNT
            /// </summary>
            [EnumMember(Value = "DEV_VERSION_EXCEED_MAX_COUNT")]
            DEVVERSIONEXCEEDMAXCOUNT = 13,

            /// <summary>
            /// Enum TEMPLATENOTONLINEOROFFLINE for value: TEMPLATE_NOT_ONLINE_OR_OFFLINE
            /// </summary>
            [EnumMember(Value = "TEMPLATE_NOT_ONLINE_OR_OFFLINE")]
            TEMPLATENOTONLINEOROFFLINE = 14,

            /// <summary>
            /// Enum MINIAPPPACKAGEINFONOTEXIST for value: MINI_APP_PACKAGE_INFO_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "MINI_APP_PACKAGE_INFO_NOT_EXIST")]
            MINIAPPPACKAGEINFONOTEXIST = 15,

            /// <summary>
            /// Enum TEMPLATEMINIAPPNOTALLOWED for value: TEMPLATE_MINIAPP_NOT_ALLOWED
            /// </summary>
            [EnumMember(Value = "TEMPLATE_MINIAPP_NOT_ALLOWED")]
            TEMPLATEMINIAPPNOTALLOWED = 16,

            /// <summary>
            /// Enum VERSIONEXCEEDEDLENGTH for value: VERSION_EXCEEDED_LENGTH
            /// </summary>
            [EnumMember(Value = "VERSION_EXCEEDED_LENGTH")]
            VERSIONEXCEEDEDLENGTH = 17,

            /// <summary>
            /// Enum TEMPLATEIDISVAPPIDNOTMATCH for value: TEMPLATE_ID_ISVAPPID_NOT_MATCH
            /// </summary>
            [EnumMember(Value = "TEMPLATE_ID_ISVAPPID_NOT_MATCH")]
            TEMPLATEIDISVAPPIDNOTMATCH = 18,

            /// <summary>
            /// Enum BUNDLEIDNOTEXIST for value: BUNDLE_ID_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "BUNDLE_ID_NOT_EXIST")]
            BUNDLEIDNOTEXIST = 19,

            /// <summary>
            /// Enum INVALIDEXTJSON for value: INVALID_EXT_JSON
            /// </summary>
            [EnumMember(Value = "INVALID_EXT_JSON")]
            INVALIDEXTJSON = 20,

            /// <summary>
            /// Enum APPINFONOTEXIST for value: APP_INFO_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "APP_INFO_NOT_EXIST")]
            APPINFONOTEXIST = 21,

            /// <summary>
            /// Enum APPTYPEERROR for value: APP_TYPE_ERROR
            /// </summary>
            [EnumMember(Value = "APP_TYPE_ERROR")]
            APPTYPEERROR = 22,

            /// <summary>
            /// Enum TEMPLATESTATUSPUNISHED for value: TEMPLATE_STATUS_PUNISHED
            /// </summary>
            [EnumMember(Value = "TEMPLATE_STATUS_PUNISHED")]
            TEMPLATESTATUSPUNISHED = 23,

            /// <summary>
            /// Enum TEMPLATESTATUSCANNOTBUILD for value: TEMPLATE_STATUS_CAN_NOT_BUILD
            /// </summary>
            [EnumMember(Value = "TEMPLATE_STATUS_CAN_NOT_BUILD")]
            TEMPLATESTATUSCANNOTBUILD = 24,

            /// <summary>
            /// Enum INVALIDPARAMS for value: INVALID_PARAMS
            /// </summary>
            [EnumMember(Value = "INVALID_PARAMS")]
            INVALIDPARAMS = 25,

            /// <summary>
            /// Enum TEMPLATEEXTRAINFOINVALID for value: TEMPLATE_EXTRA_INFO_INVALID
            /// </summary>
            [EnumMember(Value = "TEMPLATE_EXTRA_INFO_INVALID")]
            TEMPLATEEXTRAINFOINVALID = 26,

            /// <summary>
            /// Enum APPTOAPPAUTHFAIL for value: APP_TO_APP_AUTH_FAIL
            /// </summary>
            [EnumMember(Value = "APP_TO_APP_AUTH_FAIL")]
            APPTOAPPAUTHFAIL = 27,

            /// <summary>
            /// Enum BUILDVERSIONCOMPAREERROR for value: BUILD_VERSION_COMPARE_ERROR
            /// </summary>
            [EnumMember(Value = "BUILD_VERSION_COMPARE_ERROR")]
            BUILDVERSIONCOMPAREERROR = 28,

            /// <summary>
            /// Enum UPDATEPLUGINSERVICEFAIL for value: UPDATE_PLUGIN_SERVICE_FAIL
            /// </summary>
            [EnumMember(Value = "UPDATE_PLUGIN_SERVICE_FAIL")]
            UPDATEPLUGINSERVICEFAIL = 29

        }


        /// <summary>
        /// 错误码
        /// </summary>
        /// <value>错误码</value>
        [DataMember(Name = "code", EmitDefaultValue = false)]
        public CodeEnum Code { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenMiniVersionUploadErrorResponseModel" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected AlipayOpenMiniVersionUploadErrorResponseModel() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenMiniVersionUploadErrorResponseModel" /> class.
        /// </summary>
        /// <param name="code">错误码 (required).</param>
        /// <param name="links">解决方案链接.</param>
        /// <param name="message">错误描述 (required).</param>
        public AlipayOpenMiniVersionUploadErrorResponseModel(CodeEnum code = default(CodeEnum), string links = default(string), string message = default(string))
        {
            this.Code = code;
            // to ensure "message" is required (not null)
            // if (message == null)
            // {
            //     throw new ArgumentNullException("message is a required property for AlipayOpenMiniVersionUploadErrorResponseModel and cannot be null");
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
            sb.Append("class AlipayOpenMiniVersionUploadErrorResponseModel {\n");
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
            return this.Equals(input as AlipayOpenMiniVersionUploadErrorResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenMiniVersionUploadErrorResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenMiniVersionUploadErrorResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenMiniVersionUploadErrorResponseModel input)
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
