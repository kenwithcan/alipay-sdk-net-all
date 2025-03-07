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
    /// AlipayUserAgreementQueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayUserAgreementQueryResponseModel")]
    public partial class AlipayUserAgreementQueryResponseModel : IEquatable<AlipayUserAgreementQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayUserAgreementQueryResponseModel" /> class.
        /// </summary>
        /// <param name="agreementNo">用户签约成功后的协议号.</param>
        /// <param name="alipayLogonId">返回脱敏的支付宝账号.</param>
        /// <param name="creditAuthMode">授信模式，目前只在花芝代扣（即花芝go）协议时才会返回.</param>
        /// <param name="deviceId">设备Id.</param>
        /// <param name="executionPlans">还款计划列表.</param>
        /// <param name="externalAgreementNo">代扣协议中标示用户的唯一签约号(确保在商户系统中唯一)。当入参中传了此参数时返回。.</param>
        /// <param name="externalLogonId">外部登录Id。当入参中传了此参数时返回。.</param>
        /// <param name="invalidTime">协议失效时间，格式为 yyyy-MM-dd HH:mm:ss。.</param>
        /// <param name="lastDeductTime">周期扣协议，上次扣款成功时间.</param>
        /// <param name="nextDeductTime">周期扣协议，预计下次扣款时间.</param>
        /// <param name="personalProductCode">协议产品码，商户和支付宝签约时确定，不同业务场景对应不同的签约产品码。.</param>
        /// <param name="pricipalType">签约主体类型。.</param>
        /// <param name="principalId">签约主体标识。 当principal_type为CARD 时，该字段为支付宝用户号;.</param>
        /// <param name="principalOpenId">签约主体标识。 当principal_type为CARD 时，该字段为支付宝用户号;.</param>
        /// <param name="signScene">签约协议的场景。.</param>
        /// <param name="signTime">协议签约时间，格式为 yyyy-MM-dd HH:mm:ss。.</param>
        /// <param name="singleQuota">单笔代扣额度.</param>
        /// <param name="status">协议当前状态  1. TEMP：暂存，协议未生效过；  2. NORMAL：正常；  3. STOP：暂停.</param>
        /// <param name="thirdPartyType">签约第三方主体类型。对于三方协议，表示当前用户和哪一类的第三方主体进行签约。 默认为PARTNER。.</param>
        /// <param name="validTime">协议生效时间，格式为 yyyy-MM-dd HH:mm:ss。.</param>
        /// <param name="zmOpenId">用户的芝麻信用 openId，供商 户查询用户芝麻信用使用。.</param>
        public AlipayUserAgreementQueryResponseModel(string agreementNo = default(string), string alipayLogonId = default(string), string creditAuthMode = default(string), string deviceId = default(string), List<ExecutionPlan> executionPlans = default(List<ExecutionPlan>), string externalAgreementNo = default(string), string externalLogonId = default(string), string invalidTime = default(string), string lastDeductTime = default(string), string nextDeductTime = default(string), string personalProductCode = default(string), string pricipalType = default(string), string principalId = default(string), string principalOpenId = default(string), string signScene = default(string), string signTime = default(string), string singleQuota = default(string), string status = default(string), string thirdPartyType = default(string), string validTime = default(string), string zmOpenId = default(string))
        {
            this.AgreementNo = agreementNo;
            this.AlipayLogonId = alipayLogonId;
            this.CreditAuthMode = creditAuthMode;
            this.DeviceId = deviceId;
            this.ExecutionPlans = executionPlans;
            this.ExternalAgreementNo = externalAgreementNo;
            this.ExternalLogonId = externalLogonId;
            this.InvalidTime = invalidTime;
            this.LastDeductTime = lastDeductTime;
            this.NextDeductTime = nextDeductTime;
            this.PersonalProductCode = personalProductCode;
            this.PricipalType = pricipalType;
            this.PrincipalId = principalId;
            this.PrincipalOpenId = principalOpenId;
            this.SignScene = signScene;
            this.SignTime = signTime;
            this.SingleQuota = singleQuota;
            this.Status = status;
            this.ThirdPartyType = thirdPartyType;
            this.ValidTime = validTime;
            this.ZmOpenId = zmOpenId;
        }

        /// <summary>
        /// 用户签约成功后的协议号
        /// </summary>
        /// <value>用户签约成功后的协议号</value>
        [DataMember(Name = "agreement_no", EmitDefaultValue = false)]
        public string AgreementNo { get; set; }

        /// <summary>
        /// 返回脱敏的支付宝账号
        /// </summary>
        /// <value>返回脱敏的支付宝账号</value>
        [DataMember(Name = "alipay_logon_id", EmitDefaultValue = false)]
        public string AlipayLogonId { get; set; }

        /// <summary>
        /// 授信模式，目前只在花芝代扣（即花芝go）协议时才会返回
        /// </summary>
        /// <value>授信模式，目前只在花芝代扣（即花芝go）协议时才会返回</value>
        [DataMember(Name = "credit_auth_mode", EmitDefaultValue = false)]
        public string CreditAuthMode { get; set; }

        /// <summary>
        /// 设备Id
        /// </summary>
        /// <value>设备Id</value>
        [DataMember(Name = "device_id", EmitDefaultValue = false)]
        public string DeviceId { get; set; }

        /// <summary>
        /// 还款计划列表
        /// </summary>
        /// <value>还款计划列表</value>
        [DataMember(Name = "execution_plans", EmitDefaultValue = false)]
        public List<ExecutionPlan> ExecutionPlans { get; set; }

        /// <summary>
        /// 代扣协议中标示用户的唯一签约号(确保在商户系统中唯一)。当入参中传了此参数时返回。
        /// </summary>
        /// <value>代扣协议中标示用户的唯一签约号(确保在商户系统中唯一)。当入参中传了此参数时返回。</value>
        [DataMember(Name = "external_agreement_no", EmitDefaultValue = false)]
        public string ExternalAgreementNo { get; set; }

        /// <summary>
        /// 外部登录Id。当入参中传了此参数时返回。
        /// </summary>
        /// <value>外部登录Id。当入参中传了此参数时返回。</value>
        [DataMember(Name = "external_logon_id", EmitDefaultValue = false)]
        public string ExternalLogonId { get; set; }

        /// <summary>
        /// 协议失效时间，格式为 yyyy-MM-dd HH:mm:ss。
        /// </summary>
        /// <value>协议失效时间，格式为 yyyy-MM-dd HH:mm:ss。</value>
        [DataMember(Name = "invalid_time", EmitDefaultValue = false)]
        public string InvalidTime { get; set; }

        /// <summary>
        /// 周期扣协议，上次扣款成功时间
        /// </summary>
        /// <value>周期扣协议，上次扣款成功时间</value>
        [DataMember(Name = "last_deduct_time", EmitDefaultValue = false)]
        public string LastDeductTime { get; set; }

        /// <summary>
        /// 周期扣协议，预计下次扣款时间
        /// </summary>
        /// <value>周期扣协议，预计下次扣款时间</value>
        [DataMember(Name = "next_deduct_time", EmitDefaultValue = false)]
        public string NextDeductTime { get; set; }

        /// <summary>
        /// 协议产品码，商户和支付宝签约时确定，不同业务场景对应不同的签约产品码。
        /// </summary>
        /// <value>协议产品码，商户和支付宝签约时确定，不同业务场景对应不同的签约产品码。</value>
        [DataMember(Name = "personal_product_code", EmitDefaultValue = false)]
        public string PersonalProductCode { get; set; }

        /// <summary>
        /// 签约主体类型。
        /// </summary>
        /// <value>签约主体类型。</value>
        [DataMember(Name = "pricipal_type", EmitDefaultValue = false)]
        public string PricipalType { get; set; }

        /// <summary>
        /// 签约主体标识。 当principal_type为CARD 时，该字段为支付宝用户号;
        /// </summary>
        /// <value>签约主体标识。 当principal_type为CARD 时，该字段为支付宝用户号;</value>
        [DataMember(Name = "principal_id", EmitDefaultValue = false)]
        public string PrincipalId { get; set; }

        /// <summary>
        /// 签约主体标识。 当principal_type为CARD 时，该字段为支付宝用户号;
        /// </summary>
        /// <value>签约主体标识。 当principal_type为CARD 时，该字段为支付宝用户号;</value>
        [DataMember(Name = "principal_open_id", EmitDefaultValue = false)]
        public string PrincipalOpenId { get; set; }

        /// <summary>
        /// 签约协议的场景。
        /// </summary>
        /// <value>签约协议的场景。</value>
        [DataMember(Name = "sign_scene", EmitDefaultValue = false)]
        public string SignScene { get; set; }

        /// <summary>
        /// 协议签约时间，格式为 yyyy-MM-dd HH:mm:ss。
        /// </summary>
        /// <value>协议签约时间，格式为 yyyy-MM-dd HH:mm:ss。</value>
        [DataMember(Name = "sign_time", EmitDefaultValue = false)]
        public string SignTime { get; set; }

        /// <summary>
        /// 单笔代扣额度
        /// </summary>
        /// <value>单笔代扣额度</value>
        [DataMember(Name = "single_quota", EmitDefaultValue = false)]
        public string SingleQuota { get; set; }

        /// <summary>
        /// 协议当前状态  1. TEMP：暂存，协议未生效过；  2. NORMAL：正常；  3. STOP：暂停
        /// </summary>
        /// <value>协议当前状态  1. TEMP：暂存，协议未生效过；  2. NORMAL：正常；  3. STOP：暂停</value>
        [DataMember(Name = "status", EmitDefaultValue = false)]
        public string Status { get; set; }

        /// <summary>
        /// 签约第三方主体类型。对于三方协议，表示当前用户和哪一类的第三方主体进行签约。 默认为PARTNER。
        /// </summary>
        /// <value>签约第三方主体类型。对于三方协议，表示当前用户和哪一类的第三方主体进行签约。 默认为PARTNER。</value>
        [DataMember(Name = "third_party_type", EmitDefaultValue = false)]
        public string ThirdPartyType { get; set; }

        /// <summary>
        /// 协议生效时间，格式为 yyyy-MM-dd HH:mm:ss。
        /// </summary>
        /// <value>协议生效时间，格式为 yyyy-MM-dd HH:mm:ss。</value>
        [DataMember(Name = "valid_time", EmitDefaultValue = false)]
        public string ValidTime { get; set; }

        /// <summary>
        /// 用户的芝麻信用 openId，供商 户查询用户芝麻信用使用。
        /// </summary>
        /// <value>用户的芝麻信用 openId，供商 户查询用户芝麻信用使用。</value>
        [DataMember(Name = "zm_open_id", EmitDefaultValue = false)]
        public string ZmOpenId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayUserAgreementQueryResponseModel {\n");
            sb.Append("  AgreementNo: ").Append(AgreementNo).Append("\n");
            sb.Append("  AlipayLogonId: ").Append(AlipayLogonId).Append("\n");
            sb.Append("  CreditAuthMode: ").Append(CreditAuthMode).Append("\n");
            sb.Append("  DeviceId: ").Append(DeviceId).Append("\n");
            sb.Append("  ExecutionPlans: ").Append(ExecutionPlans).Append("\n");
            sb.Append("  ExternalAgreementNo: ").Append(ExternalAgreementNo).Append("\n");
            sb.Append("  ExternalLogonId: ").Append(ExternalLogonId).Append("\n");
            sb.Append("  InvalidTime: ").Append(InvalidTime).Append("\n");
            sb.Append("  LastDeductTime: ").Append(LastDeductTime).Append("\n");
            sb.Append("  NextDeductTime: ").Append(NextDeductTime).Append("\n");
            sb.Append("  PersonalProductCode: ").Append(PersonalProductCode).Append("\n");
            sb.Append("  PricipalType: ").Append(PricipalType).Append("\n");
            sb.Append("  PrincipalId: ").Append(PrincipalId).Append("\n");
            sb.Append("  PrincipalOpenId: ").Append(PrincipalOpenId).Append("\n");
            sb.Append("  SignScene: ").Append(SignScene).Append("\n");
            sb.Append("  SignTime: ").Append(SignTime).Append("\n");
            sb.Append("  SingleQuota: ").Append(SingleQuota).Append("\n");
            sb.Append("  Status: ").Append(Status).Append("\n");
            sb.Append("  ThirdPartyType: ").Append(ThirdPartyType).Append("\n");
            sb.Append("  ValidTime: ").Append(ValidTime).Append("\n");
            sb.Append("  ZmOpenId: ").Append(ZmOpenId).Append("\n");
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
            return this.Equals(input as AlipayUserAgreementQueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayUserAgreementQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayUserAgreementQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayUserAgreementQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AgreementNo == input.AgreementNo ||
                    (this.AgreementNo != null &&
                    this.AgreementNo.Equals(input.AgreementNo))
                ) && 
                (
                    this.AlipayLogonId == input.AlipayLogonId ||
                    (this.AlipayLogonId != null &&
                    this.AlipayLogonId.Equals(input.AlipayLogonId))
                ) && 
                (
                    this.CreditAuthMode == input.CreditAuthMode ||
                    (this.CreditAuthMode != null &&
                    this.CreditAuthMode.Equals(input.CreditAuthMode))
                ) && 
                (
                    this.DeviceId == input.DeviceId ||
                    (this.DeviceId != null &&
                    this.DeviceId.Equals(input.DeviceId))
                ) && 
                (
                    this.ExecutionPlans == input.ExecutionPlans ||
                    this.ExecutionPlans != null &&
                    input.ExecutionPlans != null &&
                    this.ExecutionPlans.SequenceEqual(input.ExecutionPlans)
                ) && 
                (
                    this.ExternalAgreementNo == input.ExternalAgreementNo ||
                    (this.ExternalAgreementNo != null &&
                    this.ExternalAgreementNo.Equals(input.ExternalAgreementNo))
                ) && 
                (
                    this.ExternalLogonId == input.ExternalLogonId ||
                    (this.ExternalLogonId != null &&
                    this.ExternalLogonId.Equals(input.ExternalLogonId))
                ) && 
                (
                    this.InvalidTime == input.InvalidTime ||
                    (this.InvalidTime != null &&
                    this.InvalidTime.Equals(input.InvalidTime))
                ) && 
                (
                    this.LastDeductTime == input.LastDeductTime ||
                    (this.LastDeductTime != null &&
                    this.LastDeductTime.Equals(input.LastDeductTime))
                ) && 
                (
                    this.NextDeductTime == input.NextDeductTime ||
                    (this.NextDeductTime != null &&
                    this.NextDeductTime.Equals(input.NextDeductTime))
                ) && 
                (
                    this.PersonalProductCode == input.PersonalProductCode ||
                    (this.PersonalProductCode != null &&
                    this.PersonalProductCode.Equals(input.PersonalProductCode))
                ) && 
                (
                    this.PricipalType == input.PricipalType ||
                    (this.PricipalType != null &&
                    this.PricipalType.Equals(input.PricipalType))
                ) && 
                (
                    this.PrincipalId == input.PrincipalId ||
                    (this.PrincipalId != null &&
                    this.PrincipalId.Equals(input.PrincipalId))
                ) && 
                (
                    this.PrincipalOpenId == input.PrincipalOpenId ||
                    (this.PrincipalOpenId != null &&
                    this.PrincipalOpenId.Equals(input.PrincipalOpenId))
                ) && 
                (
                    this.SignScene == input.SignScene ||
                    (this.SignScene != null &&
                    this.SignScene.Equals(input.SignScene))
                ) && 
                (
                    this.SignTime == input.SignTime ||
                    (this.SignTime != null &&
                    this.SignTime.Equals(input.SignTime))
                ) && 
                (
                    this.SingleQuota == input.SingleQuota ||
                    (this.SingleQuota != null &&
                    this.SingleQuota.Equals(input.SingleQuota))
                ) && 
                (
                    this.Status == input.Status ||
                    (this.Status != null &&
                    this.Status.Equals(input.Status))
                ) && 
                (
                    this.ThirdPartyType == input.ThirdPartyType ||
                    (this.ThirdPartyType != null &&
                    this.ThirdPartyType.Equals(input.ThirdPartyType))
                ) && 
                (
                    this.ValidTime == input.ValidTime ||
                    (this.ValidTime != null &&
                    this.ValidTime.Equals(input.ValidTime))
                ) && 
                (
                    this.ZmOpenId == input.ZmOpenId ||
                    (this.ZmOpenId != null &&
                    this.ZmOpenId.Equals(input.ZmOpenId))
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
                if (this.AgreementNo != null)
                {
                    hashCode = (hashCode * 59) + this.AgreementNo.GetHashCode();
                }
                if (this.AlipayLogonId != null)
                {
                    hashCode = (hashCode * 59) + this.AlipayLogonId.GetHashCode();
                }
                if (this.CreditAuthMode != null)
                {
                    hashCode = (hashCode * 59) + this.CreditAuthMode.GetHashCode();
                }
                if (this.DeviceId != null)
                {
                    hashCode = (hashCode * 59) + this.DeviceId.GetHashCode();
                }
                if (this.ExecutionPlans != null)
                {
                    hashCode = (hashCode * 59) + this.ExecutionPlans.GetHashCode();
                }
                if (this.ExternalAgreementNo != null)
                {
                    hashCode = (hashCode * 59) + this.ExternalAgreementNo.GetHashCode();
                }
                if (this.ExternalLogonId != null)
                {
                    hashCode = (hashCode * 59) + this.ExternalLogonId.GetHashCode();
                }
                if (this.InvalidTime != null)
                {
                    hashCode = (hashCode * 59) + this.InvalidTime.GetHashCode();
                }
                if (this.LastDeductTime != null)
                {
                    hashCode = (hashCode * 59) + this.LastDeductTime.GetHashCode();
                }
                if (this.NextDeductTime != null)
                {
                    hashCode = (hashCode * 59) + this.NextDeductTime.GetHashCode();
                }
                if (this.PersonalProductCode != null)
                {
                    hashCode = (hashCode * 59) + this.PersonalProductCode.GetHashCode();
                }
                if (this.PricipalType != null)
                {
                    hashCode = (hashCode * 59) + this.PricipalType.GetHashCode();
                }
                if (this.PrincipalId != null)
                {
                    hashCode = (hashCode * 59) + this.PrincipalId.GetHashCode();
                }
                if (this.PrincipalOpenId != null)
                {
                    hashCode = (hashCode * 59) + this.PrincipalOpenId.GetHashCode();
                }
                if (this.SignScene != null)
                {
                    hashCode = (hashCode * 59) + this.SignScene.GetHashCode();
                }
                if (this.SignTime != null)
                {
                    hashCode = (hashCode * 59) + this.SignTime.GetHashCode();
                }
                if (this.SingleQuota != null)
                {
                    hashCode = (hashCode * 59) + this.SingleQuota.GetHashCode();
                }
                if (this.Status != null)
                {
                    hashCode = (hashCode * 59) + this.Status.GetHashCode();
                }
                if (this.ThirdPartyType != null)
                {
                    hashCode = (hashCode * 59) + this.ThirdPartyType.GetHashCode();
                }
                if (this.ValidTime != null)
                {
                    hashCode = (hashCode * 59) + this.ValidTime.GetHashCode();
                }
                if (this.ZmOpenId != null)
                {
                    hashCode = (hashCode * 59) + this.ZmOpenId.GetHashCode();
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
