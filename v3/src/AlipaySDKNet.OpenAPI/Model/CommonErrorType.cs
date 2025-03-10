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
    /// CommonErrorType
    /// </summary>
    [DataContract(Name = "CommonErrorType")]
    public partial class CommonErrorType : IEquatable<CommonErrorType>, IValidatableObject
    {
        /// <summary>
        /// 错误码
        /// </summary>
        /// <value>错误码</value>
        [JsonConverter(typeof(StringEnumConverter))]
        public enum CodeEnum
        {
            /// <summary>
            /// Enum InvalidParameter for value: invalid-parameter
            /// </summary>
            [EnumMember(Value = "invalid-parameter")]
            InvalidParameter = 1,

            /// <summary>
            /// Enum UploadFail for value: upload-fail
            /// </summary>
            [EnumMember(Value = "upload-fail")]
            UploadFail = 2,

            /// <summary>
            /// Enum InvalidFileExtension for value: invalid-file-extension
            /// </summary>
            [EnumMember(Value = "invalid-file-extension")]
            InvalidFileExtension = 3,

            /// <summary>
            /// Enum InvalidFileSize for value: invalid-file-size
            /// </summary>
            [EnumMember(Value = "invalid-file-size")]
            InvalidFileSize = 4,

            /// <summary>
            /// Enum FileCheckFail for value: file-check-fail
            /// </summary>
            [EnumMember(Value = "file-check-fail")]
            FileCheckFail = 5,

            /// <summary>
            /// Enum AppCallLimited for value: app-call-limited
            /// </summary>
            [EnumMember(Value = "app-call-limited")]
            AppCallLimited = 6,

            /// <summary>
            /// Enum MethodCallLimited for value: method-call-limited
            /// </summary>
            [EnumMember(Value = "method-call-limited")]
            MethodCallLimited = 7,

            /// <summary>
            /// Enum InsufficientIsvPermissions for value: insufficient-isv-permissions
            /// </summary>
            [EnumMember(Value = "insufficient-isv-permissions")]
            InsufficientIsvPermissions = 8,

            /// <summary>
            /// Enum IllegalClientIp for value: illegal-client-ip
            /// </summary>
            [EnumMember(Value = "illegal-client-ip")]
            IllegalClientIp = 9,

            /// <summary>
            /// Enum InsufficientUserPermissions for value: insufficient-user-permissions
            /// </summary>
            [EnumMember(Value = "insufficient-user-permissions")]
            InsufficientUserPermissions = 10,

            /// <summary>
            /// Enum SelfInvokeForbidden for value: self-invoke-forbidden
            /// </summary>
            [EnumMember(Value = "self-invoke-forbidden")]
            SelfInvokeForbidden = 11,

            /// <summary>
            /// Enum AppAuthInvokeLimit for value: app-auth-invoke-limit
            /// </summary>
            [EnumMember(Value = "app-auth-invoke-limit")]
            AppAuthInvokeLimit = 12,

            /// <summary>
            /// Enum AppApiPunished for value: app-api-punished
            /// </summary>
            [EnumMember(Value = "app-api-punished")]
            AppApiPunished = 13,

            /// <summary>
            /// Enum MissingMethod for value: missing-method
            /// </summary>
            [EnumMember(Value = "missing-method")]
            MissingMethod = 14,

            /// <summary>
            /// Enum MissingPlatform for value: missing-platform
            /// </summary>
            [EnumMember(Value = "missing-platform")]
            MissingPlatform = 15,

            /// <summary>
            /// Enum InvalidPlatform for value: invalid-platform
            /// </summary>
            [EnumMember(Value = "invalid-platform")]
            InvalidPlatform = 16,

            /// <summary>
            /// Enum InvalidMethod for value: invalid-method
            /// </summary>
            [EnumMember(Value = "invalid-method")]
            InvalidMethod = 17,

            /// <summary>
            /// Enum ForbiddenApi for value: forbidden-api
            /// </summary>
            [EnumMember(Value = "forbidden-api")]
            ForbiddenApi = 18,

            /// <summary>
            /// Enum InvalidFormat for value: invalid-format
            /// </summary>
            [EnumMember(Value = "invalid-format")]
            InvalidFormat = 19,

            /// <summary>
            /// Enum MissingSignature for value: missing-signature
            /// </summary>
            [EnumMember(Value = "missing-signature")]
            MissingSignature = 20,

            /// <summary>
            /// Enum MissingAppAccessToken for value: missing-app-access-token
            /// </summary>
            [EnumMember(Value = "missing-app-access-token")]
            MissingAppAccessToken = 21,

            /// <summary>
            /// Enum MissingSignatureType for value: missing-signature-type
            /// </summary>
            [EnumMember(Value = "missing-signature-type")]
            MissingSignatureType = 22,

            /// <summary>
            /// Enum MissingDefaultSignatureType for value: missing-default-signature-type
            /// </summary>
            [EnumMember(Value = "missing-default-signature-type")]
            MissingDefaultSignatureType = 23,

            /// <summary>
            /// Enum MissingSignatureKey for value: missing-signature-key
            /// </summary>
            [EnumMember(Value = "missing-signature-key")]
            MissingSignatureKey = 24,

            /// <summary>
            /// Enum InvalidSignatureType for value: invalid-signature-type
            /// </summary>
            [EnumMember(Value = "invalid-signature-type")]
            InvalidSignatureType = 25,

            /// <summary>
            /// Enum InvalidSignatureTypeSaidInterface for value: invalid-signature-type-said-interface
            /// </summary>
            [EnumMember(Value = "invalid-signature-type-said-interface")]
            InvalidSignatureTypeSaidInterface = 26,

            /// <summary>
            /// Enum InvalidSignature for value: invalid-signature
            /// </summary>
            [EnumMember(Value = "invalid-signature")]
            InvalidSignature = 27,

            /// <summary>
            /// Enum UnsupportedExpiredAppKeySign for value: unsupported-expired-app-key-sign
            /// </summary>
            [EnumMember(Value = "unsupported-expired-app-key-sign")]
            UnsupportedExpiredAppKeySign = 28,

            /// <summary>
            /// Enum AppKeySecurityRiskAppCertExpired for value: app-key-security-risk, app-cert-expired
            /// </summary>
            [EnumMember(Value = "app-key-security-risk, app-cert-expired")]
            AppKeySecurityRiskAppCertExpired = 29,

            /// <summary>
            /// Enum AppCertNotExist for value: app-cert-not-exist
            /// </summary>
            [EnumMember(Value = "app-cert-not-exist")]
            AppCertNotExist = 30,

            /// <summary>
            /// Enum AlipayCertNotExist for value: alipay-cert-not-exist
            /// </summary>
            [EnumMember(Value = "alipay-cert-not-exist")]
            AlipayCertNotExist = 31,

            /// <summary>
            /// Enum MissingAppCertSn for value: missing-app-cert-sn
            /// </summary>
            [EnumMember(Value = "missing-app-cert-sn")]
            MissingAppCertSn = 32,

            /// <summary>
            /// Enum MissingAlipayCertSn for value: missing-alipay-cert-sn
            /// </summary>
            [EnumMember(Value = "missing-alipay-cert-sn")]
            MissingAlipayCertSn = 33,

            /// <summary>
            /// Enum MissingAlipayRootCertSn for value: missing-alipay-root-cert-sn
            /// </summary>
            [EnumMember(Value = "missing-alipay-root-cert-sn")]
            MissingAlipayRootCertSn = 34,

            /// <summary>
            /// Enum InvalidAlipayRootCertSn for value: invalid-alipay-root-cert-sn
            /// </summary>
            [EnumMember(Value = "invalid-alipay-root-cert-sn")]
            InvalidAlipayRootCertSn = 35,

            /// <summary>
            /// Enum InvalidRequestData for value: invalid-request-data
            /// </summary>
            [EnumMember(Value = "invalid-request-data")]
            InvalidRequestData = 36,

            /// <summary>
            /// Enum InvalidResponseData for value: invalid-response-data
            /// </summary>
            [EnumMember(Value = "invalid-response-data")]
            InvalidResponseData = 37,

            /// <summary>
            /// Enum MissingEncryptType for value: missing-encrypt-type
            /// </summary>
            [EnumMember(Value = "missing-encrypt-type")]
            MissingEncryptType = 38,

            /// <summary>
            /// Enum MissingEncryptKey for value: missing-encrypt-key
            /// </summary>
            [EnumMember(Value = "missing-encrypt-key")]
            MissingEncryptKey = 39,

            /// <summary>
            /// Enum InvalidEncryptType for value: invalid-encrypt-type
            /// </summary>
            [EnumMember(Value = "invalid-encrypt-type")]
            InvalidEncryptType = 40,

            /// <summary>
            /// Enum InvalidEncrypt for value: invalid-encrypt
            /// </summary>
            [EnumMember(Value = "invalid-encrypt")]
            InvalidEncrypt = 41,

            /// <summary>
            /// Enum MissingSession for value: missing-session
            /// </summary>
            [EnumMember(Value = "missing-session")]
            MissingSession = 42,

            /// <summary>
            /// Enum MissingAppId for value: missing-app-id
            /// </summary>
            [EnumMember(Value = "missing-app-id")]
            MissingAppId = 43,

            /// <summary>
            /// Enum InvalidAppId for value: invalid-app-id
            /// </summary>
            [EnumMember(Value = "invalid-app-id")]
            InvalidAppId = 44,

            /// <summary>
            /// Enum MissingTimestamp for value: missing-timestamp
            /// </summary>
            [EnumMember(Value = "missing-timestamp")]
            MissingTimestamp = 45,

            /// <summary>
            /// Enum InvalidTimestamp for value: invalid-timestamp
            /// </summary>
            [EnumMember(Value = "invalid-timestamp")]
            InvalidTimestamp = 46,

            /// <summary>
            /// Enum IllegalTimestamp for value: illegal-timestamp
            /// </summary>
            [EnumMember(Value = "illegal-timestamp")]
            IllegalTimestamp = 47,

            /// <summary>
            /// Enum MissingVersion for value: missing-version
            /// </summary>
            [EnumMember(Value = "missing-version")]
            MissingVersion = 48,

            /// <summary>
            /// Enum InvalidVersion for value: invalid-version
            /// </summary>
            [EnumMember(Value = "invalid-version")]
            InvalidVersion = 49,

            /// <summary>
            /// Enum UnsupportedVersion for value: unsupported-version
            /// </summary>
            [EnumMember(Value = "unsupported-version")]
            UnsupportedVersion = 50,

            /// <summary>
            /// Enum InvalidEncoding for value: invalid-encoding
            /// </summary>
            [EnumMember(Value = "invalid-encoding")]
            InvalidEncoding = 51,

            /// <summary>
            /// Enum InvalidCharset for value: invalid-charset
            /// </summary>
            [EnumMember(Value = "invalid-charset")]
            InvalidCharset = 52,

            /// <summary>
            /// Enum InvalidDigestType for value: invalid-digest-type
            /// </summary>
            [EnumMember(Value = "invalid-digest-type")]
            InvalidDigestType = 53,

            /// <summary>
            /// Enum InvalidDigest for value: invalid-digest
            /// </summary>
            [EnumMember(Value = "invalid-digest")]
            InvalidDigest = 54,

            /// <summary>
            /// Enum InvalidAppState for value: invalid-app-state
            /// </summary>
            [EnumMember(Value = "invalid-app-state")]
            InvalidAppState = 55,

            /// <summary>
            /// Enum InvalidSubscribeRelations for value: invalid-subscribe-relations
            /// </summary>
            [EnumMember(Value = "invalid-subscribe-relations")]
            InvalidSubscribeRelations = 56,

            /// <summary>
            /// Enum InvalidAuthToken for value: invalid-auth-token
            /// </summary>
            [EnumMember(Value = "invalid-auth-token")]
            InvalidAuthToken = 57,

            /// <summary>
            /// Enum AuthTokenTimeOut for value: auth-token-time-out
            /// </summary>
            [EnumMember(Value = "auth-token-time-out")]
            AuthTokenTimeOut = 58,

            /// <summary>
            /// Enum InvalidAppAuthToken for value: invalid-app-auth-token
            /// </summary>
            [EnumMember(Value = "invalid-app-auth-token")]
            InvalidAppAuthToken = 59,

            /// <summary>
            /// Enum InvalidAppAuthTokenNoApi for value: invalid-app-auth-token-no-api
            /// </summary>
            [EnumMember(Value = "invalid-app-auth-token-no-api")]
            InvalidAppAuthTokenNoApi = 60,

            /// <summary>
            /// Enum AppAuthTokenTimeOut for value: app-auth-token-time-out
            /// </summary>
            [EnumMember(Value = "app-auth-token-time-out")]
            AppAuthTokenTimeOut = 61,

            /// <summary>
            /// Enum NotSupportAppAuth for value: not-support-app-auth
            /// </summary>
            [EnumMember(Value = "not-support-app-auth")]
            NotSupportAppAuth = 62,

            /// <summary>
            /// Enum AccessDataTimeOut for value: access-data-time-out
            /// </summary>
            [EnumMember(Value = "access-data-time-out")]
            AccessDataTimeOut = 63,

            /// <summary>
            /// Enum UnsupportOperation for value: unsupport-operation
            /// </summary>
            [EnumMember(Value = "unsupport-operation")]
            UnsupportOperation = 64,

            /// <summary>
            /// Enum OpenidError for value: openid-error
            /// </summary>
            [EnumMember(Value = "openid-error")]
            OpenidError = 65,

            /// <summary>
            /// Enum UnknowError for value: unknow-error
            /// </summary>
            [EnumMember(Value = "unknow-error")]
            UnknowError = 66,

            /// <summary>
            /// Enum InvalidAppMethod for value: invalid-app-method
            /// </summary>
            [EnumMember(Value = "invalid-app-method")]
            InvalidAppMethod = 67,

            /// <summary>
            /// Enum MissingAppUid for value: missing-app-uid
            /// </summary>
            [EnumMember(Value = "missing-app-uid")]
            MissingAppUid = 68,

            /// <summary>
            /// Enum IllegalJson for value: illegal-json
            /// </summary>
            [EnumMember(Value = "illegal-json")]
            IllegalJson = 69,

            /// <summary>
            /// Enum IllegalCardNo for value: illegal-card-no
            /// </summary>
            [EnumMember(Value = "illegal-card-no")]
            IllegalCardNo = 70,

            /// <summary>
            /// Enum InvalidPartnerid for value: invalid-partnerid
            /// </summary>
            [EnumMember(Value = "invalid-partnerid")]
            InvalidPartnerid = 71,

            /// <summary>
            /// Enum NoProductRegByPartner for value: no-product-reg-by-partner
            /// </summary>
            [EnumMember(Value = "no-product-reg-by-partner")]
            NoProductRegByPartner = 72,

            /// <summary>
            /// Enum DecryptionError for value: decryption-error
            /// </summary>
            [EnumMember(Value = "decryption-error")]
            DecryptionError = 73,

            /// <summary>
            /// Enum DecryptionErrorMissingEncryptType for value: decryption-error-missing-encrypt-type
            /// </summary>
            [EnumMember(Value = "decryption-error-missing-encrypt-type")]
            DecryptionErrorMissingEncryptType = 74,

            /// <summary>
            /// Enum DecryptionErrorNotValidEncryptType for value: decryption-error-not-valid-encrypt-type
            /// </summary>
            [EnumMember(Value = "decryption-error-not-valid-encrypt-type")]
            DecryptionErrorNotValidEncryptType = 75,

            /// <summary>
            /// Enum DecryptionErrorNotValidEncryptKey for value: decryption-error-not-valid-encrypt-key
            /// </summary>
            [EnumMember(Value = "decryption-error-not-valid-encrypt-key")]
            DecryptionErrorNotValidEncryptKey = 76,

            /// <summary>
            /// Enum DecryptionErrorUnknown for value: decryption-error-unknown
            /// </summary>
            [EnumMember(Value = "decryption-error-unknown")]
            DecryptionErrorUnknown = 77,

            /// <summary>
            /// Enum MissingSignatureConfig for value: missing-signature-config
            /// </summary>
            [EnumMember(Value = "missing-signature-config")]
            MissingSignatureConfig = 78,

            /// <summary>
            /// Enum SeviceNotBeenSubscribedTo for value: sevice-not-been-subscribed-to
            /// </summary>
            [EnumMember(Value = "sevice-not-been-subscribed-to")]
            SeviceNotBeenSubscribedTo = 79,

            /// <summary>
            /// Enum UnknownSubCode for value: unknown-sub-code
            /// </summary>
            [EnumMember(Value = "unknown-sub-code")]
            UnknownSubCode = 80,

            /// <summary>
            /// Enum SuspectedAttack for value: suspected-attack
            /// </summary>
            [EnumMember(Value = "suspected-attack")]
            SuspectedAttack = 81,

            /// <summary>
            /// Enum InvalidAuthRelations for value: invalid-auth-relations
            /// </summary>
            [EnumMember(Value = "invalid-auth-relations")]
            InvalidAuthRelations = 82,

            /// <summary>
            /// Enum InvalidProduct for value: invalid-product
            /// </summary>
            [EnumMember(Value = "invalid-product")]
            InvalidProduct = 83,

            /// <summary>
            /// Enum MethodForbiddenBatchInvoke for value: method-forbidden-batch-invoke
            /// </summary>
            [EnumMember(Value = "method-forbidden-batch-invoke")]
            MethodForbiddenBatchInvoke = 84,

            /// <summary>
            /// Enum ExistBlankSubRequestId for value: exist-blank-sub-request-id
            /// </summary>
            [EnumMember(Value = "exist-blank-sub-request-id")]
            ExistBlankSubRequestId = 85,

            /// <summary>
            /// Enum ExistRepeatedSubRequestId for value: exist-repeated-sub-request-id
            /// </summary>
            [EnumMember(Value = "exist-repeated-sub-request-id")]
            ExistRepeatedSubRequestId = 86,

            /// <summary>
            /// Enum InvalidAppAuthRelations for value: invalid-app-auth-relations
            /// </summary>
            [EnumMember(Value = "invalid-app-auth-relations")]
            InvalidAppAuthRelations = 87,

            /// <summary>
            /// Enum AppUnbindPartner for value: app-unbind-partner
            /// </summary>
            [EnumMember(Value = "app-unbind-partner")]
            AppUnbindPartner = 88,

            /// <summary>
            /// Enum AppInvalidOid for value: app-invalid-oid
            /// </summary>
            [EnumMember(Value = "app-invalid-oid")]
            AppInvalidOid = 89,

            /// <summary>
            /// Enum ExceedApiBalance for value: exceed-api-balance
            /// </summary>
            [EnumMember(Value = "exceed-api-balance")]
            ExceedApiBalance = 90,

            /// <summary>
            /// Enum InnerAppNoAccess for value: inner-app-no-access
            /// </summary>
            [EnumMember(Value = "inner-app-no-access")]
            InnerAppNoAccess = 91,

            /// <summary>
            /// Enum InvalidInnerInvokeScene for value: invalid-inner-invoke-scene
            /// </summary>
            [EnumMember(Value = "invalid-inner-invoke-scene")]
            InvalidInnerInvokeScene = 92,

            /// <summary>
            /// Enum InvalidAppApiFieldConfig for value: invalid-app-api-field-config
            /// </summary>
            [EnumMember(Value = "invalid-app-api-field-config")]
            InvalidAppApiFieldConfig = 93

        }


        /// <summary>
        /// 错误码
        /// </summary>
        /// <value>错误码</value>
        [DataMember(Name = "code", EmitDefaultValue = false)]
        public CodeEnum Code { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="CommonErrorType" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected CommonErrorType() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="CommonErrorType" /> class.
        /// </summary>
        /// <param name="code">错误码 (required).</param>
        /// <param name="links">解决方案链接.</param>
        /// <param name="message">错误描述 (required).</param>
        public CommonErrorType(CodeEnum code = default(CodeEnum), string links = default(string), string message = default(string))
        {
            this.Code = code;
            // to ensure "message" is required (not null)
            // if (message == null)
            // {
            //     throw new ArgumentNullException("message is a required property for CommonErrorType and cannot be null");
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
            sb.Append("class CommonErrorType {\n");
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
            return this.Equals(input as CommonErrorType);
        }

        /// <summary>
        /// Returns true if CommonErrorType instances are equal
        /// </summary>
        /// <param name="input">Instance of CommonErrorType to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(CommonErrorType input)
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
