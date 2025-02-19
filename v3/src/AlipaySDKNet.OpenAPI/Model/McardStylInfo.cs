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
    /// McardStylInfo
    /// </summary>
    [DataContract(Name = "McardStylInfo")]
    public partial class McardStylInfo : IEquatable<McardStylInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="McardStylInfo" /> class.
        /// </summary>
        /// <param name="backgroundId">背景图片Id，通过接口（alipay.offline.material.image.upload）上传图片    图片说明：2M以内，格式：bmp、png、jpeg、jpg、gif；  尺寸不小于1020*643px；  图片不得有圆角，不得拉伸变形.</param>
        /// <param name="bgColor">背景色.</param>
        /// <param name="logoId">logo的图片ID，通过接口（alipay.offline.material.image.upload）上传图片    图片说明：1M以内，格式bmp、png、jpeg、jpg、gif；  尺寸不小于500*500px的正方形；  请优先使用商家LOGO；.</param>
        public McardStylInfo(string backgroundId = default(string), string bgColor = default(string), string logoId = default(string))
        {
            this.BackgroundId = backgroundId;
            this.BgColor = bgColor;
            this.LogoId = logoId;
        }

        /// <summary>
        /// 背景图片Id，通过接口（alipay.offline.material.image.upload）上传图片    图片说明：2M以内，格式：bmp、png、jpeg、jpg、gif；  尺寸不小于1020*643px；  图片不得有圆角，不得拉伸变形
        /// </summary>
        /// <value>背景图片Id，通过接口（alipay.offline.material.image.upload）上传图片    图片说明：2M以内，格式：bmp、png、jpeg、jpg、gif；  尺寸不小于1020*643px；  图片不得有圆角，不得拉伸变形</value>
        [DataMember(Name = "background_id", EmitDefaultValue = false)]
        public string BackgroundId { get; set; }

        /// <summary>
        /// 背景色
        /// </summary>
        /// <value>背景色</value>
        [DataMember(Name = "bg_color", EmitDefaultValue = false)]
        public string BgColor { get; set; }

        /// <summary>
        /// logo的图片ID，通过接口（alipay.offline.material.image.upload）上传图片    图片说明：1M以内，格式bmp、png、jpeg、jpg、gif；  尺寸不小于500*500px的正方形；  请优先使用商家LOGO；
        /// </summary>
        /// <value>logo的图片ID，通过接口（alipay.offline.material.image.upload）上传图片    图片说明：1M以内，格式bmp、png、jpeg、jpg、gif；  尺寸不小于500*500px的正方形；  请优先使用商家LOGO；</value>
        [DataMember(Name = "logo_id", EmitDefaultValue = false)]
        public string LogoId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class McardStylInfo {\n");
            sb.Append("  BackgroundId: ").Append(BackgroundId).Append("\n");
            sb.Append("  BgColor: ").Append(BgColor).Append("\n");
            sb.Append("  LogoId: ").Append(LogoId).Append("\n");
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
            return this.Equals(input as McardStylInfo);
        }

        /// <summary>
        /// Returns true if McardStylInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of McardStylInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(McardStylInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.BackgroundId == input.BackgroundId ||
                    (this.BackgroundId != null &&
                    this.BackgroundId.Equals(input.BackgroundId))
                ) && 
                (
                    this.BgColor == input.BgColor ||
                    (this.BgColor != null &&
                    this.BgColor.Equals(input.BgColor))
                ) && 
                (
                    this.LogoId == input.LogoId ||
                    (this.LogoId != null &&
                    this.LogoId.Equals(input.LogoId))
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
                if (this.BackgroundId != null)
                {
                    hashCode = (hashCode * 59) + this.BackgroundId.GetHashCode();
                }
                if (this.BgColor != null)
                {
                    hashCode = (hashCode * 59) + this.BgColor.GetHashCode();
                }
                if (this.LogoId != null)
                {
                    hashCode = (hashCode * 59) + this.LogoId.GetHashCode();
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
