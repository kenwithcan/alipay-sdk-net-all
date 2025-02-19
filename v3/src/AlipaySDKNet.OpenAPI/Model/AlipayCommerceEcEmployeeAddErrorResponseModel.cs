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
    /// AlipayCommerceEcEmployeeAddErrorResponseModel
    /// </summary>
    [DataContract(Name = "AlipayCommerceEcEmployeeAddErrorResponseModel")]
    public partial class AlipayCommerceEcEmployeeAddErrorResponseModel : IEquatable<AlipayCommerceEcEmployeeAddErrorResponseModel>, IValidatableObject
    {
        /// <summary>
        /// 错误码
        /// </summary>
        /// <value>错误码</value>
        [JsonConverter(typeof(StringEnumConverter))]
        public enum CodeEnum
        {
            /// <summary>
            /// Enum INVALIDPARAMETER for value: INVALID_PARAMETER
            /// </summary>
            [EnumMember(Value = "INVALID_PARAMETER")]
            INVALIDPARAMETER = 1,

            /// <summary>
            /// Enum SYSTEMERROR for value: SYSTEM_ERROR
            /// </summary>
            [EnumMember(Value = "SYSTEM_ERROR")]
            SYSTEMERROR = 2,

            /// <summary>
            /// Enum ENTERPRISENOTEXIST for value: ENTERPRISE_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "ENTERPRISE_NOT_EXIST")]
            ENTERPRISENOTEXIST = 3,

            /// <summary>
            /// Enum USERNOTEXIST for value: USER_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "USER_NOT_EXIST")]
            USERNOTEXIST = 4,

            /// <summary>
            /// Enum USERUNREALNAME for value: USER_UNREAL_NAME
            /// </summary>
            [EnumMember(Value = "USER_UNREAL_NAME")]
            USERUNREALNAME = 5,

            /// <summary>
            /// Enum ENTERPRISEMEMBERNUMEXCEEDMAX for value: ENTERPRISE_MEMBER_NUM_EXCEED_MAX
            /// </summary>
            [EnumMember(Value = "ENTERPRISE_MEMBER_NUM_EXCEED_MAX")]
            ENTERPRISEMEMBERNUMEXCEEDMAX = 6,

            /// <summary>
            /// Enum JOINEDACCOUNTNUMEXCEEDMAX for value: JOINED_ACCOUNT_NUM_EXCEED_MAX
            /// </summary>
            [EnumMember(Value = "JOINED_ACCOUNT_NUM_EXCEED_MAX")]
            JOINEDACCOUNTNUMEXCEEDMAX = 7,

            /// <summary>
            /// Enum NOAGREEMENT for value: NO_AGREEMENT
            /// </summary>
            [EnumMember(Value = "NO_AGREEMENT")]
            NOAGREEMENT = 8,

            /// <summary>
            /// Enum EMPLOYEEHASACTIVATED for value: EMPLOYEE_HAS_ACTIVATED
            /// </summary>
            [EnumMember(Value = "EMPLOYEE_HAS_ACTIVATED")]
            EMPLOYEEHASACTIVATED = 9,

            /// <summary>
            /// Enum ENTERPRISENOTSIGNED for value: ENTERPRISE_NOT_SIGNED
            /// </summary>
            [EnumMember(Value = "ENTERPRISE_NOT_SIGNED")]
            ENTERPRISENOTSIGNED = 10,

            /// <summary>
            /// Enum EMPLOYEENOEXIST for value: EMPLOYEE_NO_EXIST
            /// </summary>
            [EnumMember(Value = "EMPLOYEE_NO_EXIST")]
            EMPLOYEENOEXIST = 11,

            /// <summary>
            /// Enum EMPLOYEEALIPAYOCCUPIED for value: EMPLOYEE_ALIPAY_OCCUPIED
            /// </summary>
            [EnumMember(Value = "EMPLOYEE_ALIPAY_OCCUPIED")]
            EMPLOYEEALIPAYOCCUPIED = 12,

            /// <summary>
            /// Enum EMPLOYEEMOBILEEXIST for value: EMPLOYEE_MOBILE_EXIST
            /// </summary>
            [EnumMember(Value = "EMPLOYEE_MOBILE_EXIST")]
            EMPLOYEEMOBILEEXIST = 13,

            /// <summary>
            /// Enum EMPLOYEEFREQUENCYOVERLIMIT for value: EMPLOYEE_FREQUENCY_OVER_LIMIT
            /// </summary>
            [EnumMember(Value = "EMPLOYEE_FREQUENCY_OVER_LIMIT")]
            EMPLOYEEFREQUENCYOVERLIMIT = 14,

            /// <summary>
            /// Enum EMPLOYEEISSUPERADMIN for value: EMPLOYEE_IS_SUPER_ADMIN
            /// </summary>
            [EnumMember(Value = "EMPLOYEE_IS_SUPER_ADMIN")]
            EMPLOYEEISSUPERADMIN = 15,

            /// <summary>
            /// Enum EMPLOYEEOVERLIMIT for value: EMPLOYEE_OVER_LIMIT
            /// </summary>
            [EnumMember(Value = "EMPLOYEE_OVER_LIMIT")]
            EMPLOYEEOVERLIMIT = 16,

            /// <summary>
            /// Enum NODENOTEXIST for value: NODE_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "NODE_NOT_EXIST")]
            NODENOTEXIST = 17,

            /// <summary>
            /// Enum NEEDTOSETPPW for value: NEED_TO_SET_PPW
            /// </summary>
            [EnumMember(Value = "NEED_TO_SET_PPW")]
            NEEDTOSETPPW = 18,

            /// <summary>
            /// Enum ISVUSERIDNOTSUPPORT for value: ISV_USER_ID_NOT_SUPPORT
            /// </summary>
            [EnumMember(Value = "ISV_USER_ID_NOT_SUPPORT")]
            ISVUSERIDNOTSUPPORT = 19,

            /// <summary>
            /// Enum ACCOUNTNOTPERSONAL for value: ACCOUNT_NOT_PERSONAL
            /// </summary>
            [EnumMember(Value = "ACCOUNT_NOT_PERSONAL")]
            ACCOUNTNOTPERSONAL = 20,

            /// <summary>
            /// Enum EMPLOYEEEMAILEXIST for value: EMPLOYEE_EMAIL_EXIST
            /// </summary>
            [EnumMember(Value = "EMPLOYEE_EMAIL_EXIST")]
            EMPLOYEEEMAILEXIST = 21,

            /// <summary>
            /// Enum EMPLOYEEEXIST for value: EMPLOYEE_EXIST
            /// </summary>
            [EnumMember(Value = "EMPLOYEE_EXIST")]
            EMPLOYEEEXIST = 22,

            /// <summary>
            /// Enum EMPLOYEECERTEXIST for value: EMPLOYEE_CERT_EXIST
            /// </summary>
            [EnumMember(Value = "EMPLOYEE_CERT_EXIST")]
            EMPLOYEECERTEXIST = 23,

            /// <summary>
            /// Enum DEPTUPGRADING for value: DEPT_UPGRADING
            /// </summary>
            [EnumMember(Value = "DEPT_UPGRADING")]
            DEPTUPGRADING = 24,

            /// <summary>
            /// Enum MODIFYAGENCYOPERATIONFAIL for value: MODIFY_AGENCY_OPERATION_FAIL
            /// </summary>
            [EnumMember(Value = "MODIFY_AGENCY_OPERATION_FAIL")]
            MODIFYAGENCYOPERATIONFAIL = 25,

            /// <summary>
            /// Enum FREESIGNTOKENINVALID for value: FREE_SIGN_TOKEN_INVALID
            /// </summary>
            [EnumMember(Value = "FREE_SIGN_TOKEN_INVALID")]
            FREESIGNTOKENINVALID = 26,

            /// <summary>
            /// Enum FUNDACCOUNTWHITENOTEXIST for value: FUND_ACCOUNT_WHITE_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "FUND_ACCOUNT_WHITE_NOT_EXIST")]
            FUNDACCOUNTWHITENOTEXIST = 27,

            /// <summary>
            /// Enum FREESIGNEMPLOYEEEXISTED for value: FREE_SIGN_EMPLOYEE_EXISTED
            /// </summary>
            [EnumMember(Value = "FREE_SIGN_EMPLOYEE_EXISTED")]
            FREESIGNEMPLOYEEEXISTED = 28,

            /// <summary>
            /// Enum EMPMULTIACCOUNTNOTSUPPORT for value: EMP_MULTI_ACCOUNT_NOT_SUPPORT
            /// </summary>
            [EnumMember(Value = "EMP_MULTI_ACCOUNT_NOT_SUPPORT")]
            EMPMULTIACCOUNTNOTSUPPORT = 29,

            /// <summary>
            /// Enum IOTENTERPRISEUNSIGN for value: IOT_ENTERPRISE_UNSIGN
            /// </summary>
            [EnumMember(Value = "IOT_ENTERPRISE_UNSIGN")]
            IOTENTERPRISEUNSIGN = 30,

            /// <summary>
            /// Enum IOTUSERFACENOTEXIST for value: IOT_USER_FACE_NOT_EXIST
            /// </summary>
            [EnumMember(Value = "IOT_USER_FACE_NOT_EXIST")]
            IOTUSERFACENOTEXIST = 31,

            /// <summary>
            /// Enum IOTUSERFACEPAYOPENFAIL for value: IOT_USER_FACEPAY_OPEN_FAIL
            /// </summary>
            [EnumMember(Value = "IOT_USER_FACEPAY_OPEN_FAIL")]
            IOTUSERFACEPAYOPENFAIL = 32,

            /// <summary>
            /// Enum FUNDSYSTEMERROR for value: FUND_SYSTEM_ERROR
            /// </summary>
            [EnumMember(Value = "FUND_SYSTEM_ERROR")]
            FUNDSYSTEMERROR = 33,

            /// <summary>
            /// Enum FUNDDAILYJOINENTREACHEDLIMIT for value: FUND_DAILY_JOINENT_REACHED_LIMIT
            /// </summary>
            [EnumMember(Value = "FUND_DAILY_JOINENT_REACHED_LIMIT")]
            FUNDDAILYJOINENTREACHEDLIMIT = 34,

            /// <summary>
            /// Enum FUNDINVITEREPLYING for value: FUND_INVITE_REPLYING
            /// </summary>
            [EnumMember(Value = "FUND_INVITE_REPLYING")]
            FUNDINVITEREPLYING = 35,

            /// <summary>
            /// Enum FUNDSECURITYCHECKFAILED for value: FUND_SECURITY_CHECK_FAILED
            /// </summary>
            [EnumMember(Value = "FUND_SECURITY_CHECK_FAILED")]
            FUNDSECURITYCHECKFAILED = 36,

            /// <summary>
            /// Enum IOTSYSTEMERROR for value: IOT_SYSTEM_ERROR
            /// </summary>
            [EnumMember(Value = "IOT_SYSTEM_ERROR")]
            IOTSYSTEMERROR = 37,

            /// <summary>
            /// Enum IOTAPPUNSIGN for value: IOT_APP_UNSIGN
            /// </summary>
            [EnumMember(Value = "IOT_APP_UNSIGN")]
            IOTAPPUNSIGN = 38,

            /// <summary>
            /// Enum EMPLOYEECREATEING for value: EMPLOYEE_CREATE_ING
            /// </summary>
            [EnumMember(Value = "EMPLOYEE_CREATE_ING")]
            EMPLOYEECREATEING = 39

        }


        /// <summary>
        /// 错误码
        /// </summary>
        /// <value>错误码</value>
        [DataMember(Name = "code", EmitDefaultValue = false)]
        public CodeEnum Code { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayCommerceEcEmployeeAddErrorResponseModel" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected AlipayCommerceEcEmployeeAddErrorResponseModel() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayCommerceEcEmployeeAddErrorResponseModel" /> class.
        /// </summary>
        /// <param name="code">错误码 (required).</param>
        /// <param name="links">解决方案链接.</param>
        /// <param name="message">错误描述 (required).</param>
        public AlipayCommerceEcEmployeeAddErrorResponseModel(CodeEnum code = default(CodeEnum), string links = default(string), string message = default(string))
        {
            this.Code = code;
            // to ensure "message" is required (not null)
            // if (message == null)
            // {
            //     throw new ArgumentNullException("message is a required property for AlipayCommerceEcEmployeeAddErrorResponseModel and cannot be null");
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
            sb.Append("class AlipayCommerceEcEmployeeAddErrorResponseModel {\n");
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
            return this.Equals(input as AlipayCommerceEcEmployeeAddErrorResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayCommerceEcEmployeeAddErrorResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayCommerceEcEmployeeAddErrorResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayCommerceEcEmployeeAddErrorResponseModel input)
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
