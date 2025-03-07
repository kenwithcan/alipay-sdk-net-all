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
    /// AlipayCommerceEducateCampusInstitutionsAddErrorResponseModel
    /// </summary>
    [DataContract(Name = "AlipayCommerceEducateCampusInstitutionsAddErrorResponseModel")]
    public partial class AlipayCommerceEducateCampusInstitutionsAddErrorResponseModel : IEquatable<AlipayCommerceEducateCampusInstitutionsAddErrorResponseModel>, IValidatableObject
    {
        /// <summary>
        /// 错误码
        /// </summary>
        /// <value>错误码</value>
        [JsonConverter(typeof(StringEnumConverter))]
        public enum CodeEnum
        {
            /// <summary>
            /// Enum ISVDECLAREUPDATEUNAUTHORIZED for value: ISV_DECLARE_UPDATE_UNAUTHORIZED
            /// </summary>
            [EnumMember(Value = "ISV_DECLARE_UPDATE_UNAUTHORIZED")]
            ISVDECLAREUPDATEUNAUTHORIZED = 1,

            /// <summary>
            /// Enum ISVSCHOOLMAINTAINING for value: ISV_SCHOOL_MAINTAINING
            /// </summary>
            [EnumMember(Value = "ISV_SCHOOL_MAINTAINING")]
            ISVSCHOOLMAINTAINING = 2,

            /// <summary>
            /// Enum ILLEGALPARAM for value: ILLEGAL_PARAM
            /// </summary>
            [EnumMember(Value = "ILLEGAL_PARAM")]
            ILLEGALPARAM = 3,

            /// <summary>
            /// Enum SCHOOLNAMEILLEGAL for value: SCHOOL_NAME_ILLEGAL
            /// </summary>
            [EnumMember(Value = "SCHOOL_NAME_ILLEGAL")]
            SCHOOLNAMEILLEGAL = 4,

            /// <summary>
            /// Enum INVALIDPARAMETERPROVINCECODE for value: INVALID_PARAMETER_PROVINCE_CODE
            /// </summary>
            [EnumMember(Value = "INVALID_PARAMETER_PROVINCE_CODE")]
            INVALIDPARAMETERPROVINCECODE = 5,

            /// <summary>
            /// Enum INVALIDPARAMETERCITYCODE for value: INVALID_PARAMETER_CITY_CODE
            /// </summary>
            [EnumMember(Value = "INVALID_PARAMETER_CITY_CODE")]
            INVALIDPARAMETERCITYCODE = 6,

            /// <summary>
            /// Enum INVALIDPARAMETERSCHOOLSTDCODE for value: INVALID_PARAMETER_SCHOOL_STD_CODE
            /// </summary>
            [EnumMember(Value = "INVALID_PARAMETER_SCHOOL_STD_CODE")]
            INVALIDPARAMETERSCHOOLSTDCODE = 7,

            /// <summary>
            /// Enum LEARNINGSTAGEERROR for value: LEARNING_STAGE_ERROR
            /// </summary>
            [EnumMember(Value = "LEARNING_STAGE_ERROR")]
            LEARNINGSTAGEERROR = 8,

            /// <summary>
            /// Enum INVALIDPARAMETERSCHOOLPROPERTY for value: INVALID_PARAMETER_SCHOOL_PROPERTY
            /// </summary>
            [EnumMember(Value = "INVALID_PARAMETER_SCHOOL_PROPERTY")]
            INVALIDPARAMETERSCHOOLPROPERTY = 9,

            /// <summary>
            /// Enum SYSTEMERROR for value: SYSTEM_ERROR
            /// </summary>
            [EnumMember(Value = "SYSTEM_ERROR")]
            SYSTEMERROR = 10,

            /// <summary>
            /// Enum SCHOOLEXIST for value: SCHOOL_EXIST
            /// </summary>
            [EnumMember(Value = "SCHOOL_EXIST")]
            SCHOOLEXIST = 11,

            /// <summary>
            /// Enum INVALIDPARAMETER for value: INVALID_PARAMETER
            /// </summary>
            [EnumMember(Value = "INVALID_PARAMETER")]
            INVALIDPARAMETER = 12,

            /// <summary>
            /// Enum SCHOOLNOTSUBJECT for value: SCHOOL_NOT_SUBJECT
            /// </summary>
            [EnumMember(Value = "SCHOOL_NOT_SUBJECT")]
            SCHOOLNOTSUBJECT = 13

        }


        /// <summary>
        /// 错误码
        /// </summary>
        /// <value>错误码</value>
        [DataMember(Name = "code", EmitDefaultValue = false)]
        public CodeEnum Code { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayCommerceEducateCampusInstitutionsAddErrorResponseModel" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected AlipayCommerceEducateCampusInstitutionsAddErrorResponseModel() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayCommerceEducateCampusInstitutionsAddErrorResponseModel" /> class.
        /// </summary>
        /// <param name="code">错误码 (required).</param>
        /// <param name="links">解决方案链接.</param>
        /// <param name="message">错误描述 (required).</param>
        public AlipayCommerceEducateCampusInstitutionsAddErrorResponseModel(CodeEnum code = default(CodeEnum), string links = default(string), string message = default(string))
        {
            this.Code = code;
            // to ensure "message" is required (not null)
            // if (message == null)
            // {
            //     throw new ArgumentNullException("message is a required property for AlipayCommerceEducateCampusInstitutionsAddErrorResponseModel and cannot be null");
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
            sb.Append("class AlipayCommerceEducateCampusInstitutionsAddErrorResponseModel {\n");
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
            return this.Equals(input as AlipayCommerceEducateCampusInstitutionsAddErrorResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayCommerceEducateCampusInstitutionsAddErrorResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayCommerceEducateCampusInstitutionsAddErrorResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayCommerceEducateCampusInstitutionsAddErrorResponseModel input)
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
