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
    /// AlipayOpenSpIsvSignauthCreateModel
    /// </summary>
    [DataContract(Name = "AlipayOpenSpIsvSignauthCreateModel")]
    public partial class AlipayOpenSpIsvSignauthCreateModel : IEquatable<AlipayOpenSpIsvSignauthCreateModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenSpIsvSignauthCreateModel" /> class.
        /// </summary>
        /// <param name="isvAuthSceneInfos">代运营授权场景信息.</param>
        /// <param name="merchantLogonId">商户登录账号 支持手机号和邮箱账号；不支持pid.</param>
        /// <param name="needAppAuth">1表示需要，0表示不需要 不传参数默认是需要（1） 是否创建三方应用授权子任务，也就是是否需要给三方应用授权.</param>
        /// <param name="signOrderNo">签约单号 可通过alipay.open.agent.confirm接口获取签约单号.</param>
        public AlipayOpenSpIsvSignauthCreateModel(List<IsvAuthSceneInfo> isvAuthSceneInfos = default(List<IsvAuthSceneInfo>), string merchantLogonId = default(string), string needAppAuth = default(string), string signOrderNo = default(string))
        {
            this.IsvAuthSceneInfos = isvAuthSceneInfos;
            this.MerchantLogonId = merchantLogonId;
            this.NeedAppAuth = needAppAuth;
            this.SignOrderNo = signOrderNo;
        }

        /// <summary>
        /// 代运营授权场景信息
        /// </summary>
        /// <value>代运营授权场景信息</value>
        [DataMember(Name = "isv_auth_scene_infos", EmitDefaultValue = false)]
        public List<IsvAuthSceneInfo> IsvAuthSceneInfos { get; set; }

        /// <summary>
        /// 商户登录账号 支持手机号和邮箱账号；不支持pid
        /// </summary>
        /// <value>商户登录账号 支持手机号和邮箱账号；不支持pid</value>
        [DataMember(Name = "merchant_logon_id", EmitDefaultValue = false)]
        public string MerchantLogonId { get; set; }

        /// <summary>
        /// 1表示需要，0表示不需要 不传参数默认是需要（1） 是否创建三方应用授权子任务，也就是是否需要给三方应用授权
        /// </summary>
        /// <value>1表示需要，0表示不需要 不传参数默认是需要（1） 是否创建三方应用授权子任务，也就是是否需要给三方应用授权</value>
        [DataMember(Name = "need_app_auth", EmitDefaultValue = false)]
        public string NeedAppAuth { get; set; }

        /// <summary>
        /// 签约单号 可通过alipay.open.agent.confirm接口获取签约单号
        /// </summary>
        /// <value>签约单号 可通过alipay.open.agent.confirm接口获取签约单号</value>
        [DataMember(Name = "sign_order_no", EmitDefaultValue = false)]
        public string SignOrderNo { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenSpIsvSignauthCreateModel {\n");
            sb.Append("  IsvAuthSceneInfos: ").Append(IsvAuthSceneInfos).Append("\n");
            sb.Append("  MerchantLogonId: ").Append(MerchantLogonId).Append("\n");
            sb.Append("  NeedAppAuth: ").Append(NeedAppAuth).Append("\n");
            sb.Append("  SignOrderNo: ").Append(SignOrderNo).Append("\n");
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
            return this.Equals(input as AlipayOpenSpIsvSignauthCreateModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenSpIsvSignauthCreateModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenSpIsvSignauthCreateModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenSpIsvSignauthCreateModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.IsvAuthSceneInfos == input.IsvAuthSceneInfos ||
                    this.IsvAuthSceneInfos != null &&
                    input.IsvAuthSceneInfos != null &&
                    this.IsvAuthSceneInfos.SequenceEqual(input.IsvAuthSceneInfos)
                ) && 
                (
                    this.MerchantLogonId == input.MerchantLogonId ||
                    (this.MerchantLogonId != null &&
                    this.MerchantLogonId.Equals(input.MerchantLogonId))
                ) && 
                (
                    this.NeedAppAuth == input.NeedAppAuth ||
                    (this.NeedAppAuth != null &&
                    this.NeedAppAuth.Equals(input.NeedAppAuth))
                ) && 
                (
                    this.SignOrderNo == input.SignOrderNo ||
                    (this.SignOrderNo != null &&
                    this.SignOrderNo.Equals(input.SignOrderNo))
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
                if (this.IsvAuthSceneInfos != null)
                {
                    hashCode = (hashCode * 59) + this.IsvAuthSceneInfos.GetHashCode();
                }
                if (this.MerchantLogonId != null)
                {
                    hashCode = (hashCode * 59) + this.MerchantLogonId.GetHashCode();
                }
                if (this.NeedAppAuth != null)
                {
                    hashCode = (hashCode * 59) + this.NeedAppAuth.GetHashCode();
                }
                if (this.SignOrderNo != null)
                {
                    hashCode = (hashCode * 59) + this.SignOrderNo.GetHashCode();
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
