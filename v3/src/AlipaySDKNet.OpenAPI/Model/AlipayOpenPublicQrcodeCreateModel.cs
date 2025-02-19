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
    /// AlipayOpenPublicQrcodeCreateModel
    /// </summary>
    [DataContract(Name = "AlipayOpenPublicQrcodeCreateModel")]
    public partial class AlipayOpenPublicQrcodeCreateModel : IEquatable<AlipayOpenPublicQrcodeCreateModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenPublicQrcodeCreateModel" /> class.
        /// </summary>
        /// <param name="codeInfo">codeInfo.</param>
        /// <param name="codeType">二维码类型，目前只支持两种类型：  TEMP：临时的（默认）；  PERM：永久的.</param>
        /// <param name="expireSecond">临时码过期时间，以秒为单位，最大不超过1800秒；  永久码置空.</param>
        /// <param name="showLogo">二维码中间是否显示服务窗logo，Y：显示；N：不显示（默认）.</param>
        public AlipayOpenPublicQrcodeCreateModel(CodeInfo codeInfo = default(CodeInfo), string codeType = default(string), string expireSecond = default(string), string showLogo = default(string))
        {
            this.CodeInfo = codeInfo;
            this.CodeType = codeType;
            this.ExpireSecond = expireSecond;
            this.ShowLogo = showLogo;
        }

        /// <summary>
        /// Gets or Sets CodeInfo
        /// </summary>
        [DataMember(Name = "code_info", EmitDefaultValue = false)]
        public CodeInfo CodeInfo { get; set; }

        /// <summary>
        /// 二维码类型，目前只支持两种类型：  TEMP：临时的（默认）；  PERM：永久的
        /// </summary>
        /// <value>二维码类型，目前只支持两种类型：  TEMP：临时的（默认）；  PERM：永久的</value>
        [DataMember(Name = "code_type", EmitDefaultValue = false)]
        public string CodeType { get; set; }

        /// <summary>
        /// 临时码过期时间，以秒为单位，最大不超过1800秒；  永久码置空
        /// </summary>
        /// <value>临时码过期时间，以秒为单位，最大不超过1800秒；  永久码置空</value>
        [DataMember(Name = "expire_second", EmitDefaultValue = false)]
        public string ExpireSecond { get; set; }

        /// <summary>
        /// 二维码中间是否显示服务窗logo，Y：显示；N：不显示（默认）
        /// </summary>
        /// <value>二维码中间是否显示服务窗logo，Y：显示；N：不显示（默认）</value>
        [DataMember(Name = "show_logo", EmitDefaultValue = false)]
        public string ShowLogo { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenPublicQrcodeCreateModel {\n");
            sb.Append("  CodeInfo: ").Append(CodeInfo).Append("\n");
            sb.Append("  CodeType: ").Append(CodeType).Append("\n");
            sb.Append("  ExpireSecond: ").Append(ExpireSecond).Append("\n");
            sb.Append("  ShowLogo: ").Append(ShowLogo).Append("\n");
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
            return this.Equals(input as AlipayOpenPublicQrcodeCreateModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenPublicQrcodeCreateModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenPublicQrcodeCreateModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenPublicQrcodeCreateModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.CodeInfo == input.CodeInfo ||
                    (this.CodeInfo != null &&
                    this.CodeInfo.Equals(input.CodeInfo))
                ) && 
                (
                    this.CodeType == input.CodeType ||
                    (this.CodeType != null &&
                    this.CodeType.Equals(input.CodeType))
                ) && 
                (
                    this.ExpireSecond == input.ExpireSecond ||
                    (this.ExpireSecond != null &&
                    this.ExpireSecond.Equals(input.ExpireSecond))
                ) && 
                (
                    this.ShowLogo == input.ShowLogo ||
                    (this.ShowLogo != null &&
                    this.ShowLogo.Equals(input.ShowLogo))
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
                if (this.CodeInfo != null)
                {
                    hashCode = (hashCode * 59) + this.CodeInfo.GetHashCode();
                }
                if (this.CodeType != null)
                {
                    hashCode = (hashCode * 59) + this.CodeType.GetHashCode();
                }
                if (this.ExpireSecond != null)
                {
                    hashCode = (hashCode * 59) + this.ExpireSecond.GetHashCode();
                }
                if (this.ShowLogo != null)
                {
                    hashCode = (hashCode * 59) + this.ShowLogo.GetHashCode();
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
