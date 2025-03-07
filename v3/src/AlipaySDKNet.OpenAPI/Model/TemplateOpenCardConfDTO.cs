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
    /// TemplateOpenCardConfDTO
    /// </summary>
    [DataContract(Name = "TemplateOpenCardConfDTO")]
    public partial class TemplateOpenCardConfDTO : IEquatable<TemplateOpenCardConfDTO>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TemplateOpenCardConfDTO" /> class.
        /// </summary>
        /// <param name="cardRights">领卡权益信息.</param>
        /// <param name="conf">配置，预留字段，暂时不用.</param>
        /// <param name="openCardSourceType">开卡渠道类型 外部系统：ISV （代理运营） 商户直连对接：MER （商家自运营）.</param>
        /// <param name="openCardUrl">开卡链接，必须http、https开头.</param>
        /// <param name="sourceAppId">渠道APPID，提供领卡页面的服务提供方.</param>
        public TemplateOpenCardConfDTO(List<TemplateRightsContentDTO> cardRights = default(List<TemplateRightsContentDTO>), string conf = default(string), string openCardSourceType = default(string), string openCardUrl = default(string), string sourceAppId = default(string))
        {
            this.CardRights = cardRights;
            this.Conf = conf;
            this.OpenCardSourceType = openCardSourceType;
            this.OpenCardUrl = openCardUrl;
            this.SourceAppId = sourceAppId;
        }

        /// <summary>
        /// 领卡权益信息
        /// </summary>
        /// <value>领卡权益信息</value>
        [DataMember(Name = "card_rights", EmitDefaultValue = false)]
        public List<TemplateRightsContentDTO> CardRights { get; set; }

        /// <summary>
        /// 配置，预留字段，暂时不用
        /// </summary>
        /// <value>配置，预留字段，暂时不用</value>
        [DataMember(Name = "conf", EmitDefaultValue = false)]
        public string Conf { get; set; }

        /// <summary>
        /// 开卡渠道类型 外部系统：ISV （代理运营） 商户直连对接：MER （商家自运营）
        /// </summary>
        /// <value>开卡渠道类型 外部系统：ISV （代理运营） 商户直连对接：MER （商家自运营）</value>
        [DataMember(Name = "open_card_source_type", EmitDefaultValue = false)]
        public string OpenCardSourceType { get; set; }

        /// <summary>
        /// 开卡链接，必须http、https开头
        /// </summary>
        /// <value>开卡链接，必须http、https开头</value>
        [DataMember(Name = "open_card_url", EmitDefaultValue = false)]
        public string OpenCardUrl { get; set; }

        /// <summary>
        /// 渠道APPID，提供领卡页面的服务提供方
        /// </summary>
        /// <value>渠道APPID，提供领卡页面的服务提供方</value>
        [DataMember(Name = "source_app_id", EmitDefaultValue = false)]
        public string SourceAppId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class TemplateOpenCardConfDTO {\n");
            sb.Append("  CardRights: ").Append(CardRights).Append("\n");
            sb.Append("  Conf: ").Append(Conf).Append("\n");
            sb.Append("  OpenCardSourceType: ").Append(OpenCardSourceType).Append("\n");
            sb.Append("  OpenCardUrl: ").Append(OpenCardUrl).Append("\n");
            sb.Append("  SourceAppId: ").Append(SourceAppId).Append("\n");
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
            return this.Equals(input as TemplateOpenCardConfDTO);
        }

        /// <summary>
        /// Returns true if TemplateOpenCardConfDTO instances are equal
        /// </summary>
        /// <param name="input">Instance of TemplateOpenCardConfDTO to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(TemplateOpenCardConfDTO input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.CardRights == input.CardRights ||
                    this.CardRights != null &&
                    input.CardRights != null &&
                    this.CardRights.SequenceEqual(input.CardRights)
                ) && 
                (
                    this.Conf == input.Conf ||
                    (this.Conf != null &&
                    this.Conf.Equals(input.Conf))
                ) && 
                (
                    this.OpenCardSourceType == input.OpenCardSourceType ||
                    (this.OpenCardSourceType != null &&
                    this.OpenCardSourceType.Equals(input.OpenCardSourceType))
                ) && 
                (
                    this.OpenCardUrl == input.OpenCardUrl ||
                    (this.OpenCardUrl != null &&
                    this.OpenCardUrl.Equals(input.OpenCardUrl))
                ) && 
                (
                    this.SourceAppId == input.SourceAppId ||
                    (this.SourceAppId != null &&
                    this.SourceAppId.Equals(input.SourceAppId))
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
                if (this.CardRights != null)
                {
                    hashCode = (hashCode * 59) + this.CardRights.GetHashCode();
                }
                if (this.Conf != null)
                {
                    hashCode = (hashCode * 59) + this.Conf.GetHashCode();
                }
                if (this.OpenCardSourceType != null)
                {
                    hashCode = (hashCode * 59) + this.OpenCardSourceType.GetHashCode();
                }
                if (this.OpenCardUrl != null)
                {
                    hashCode = (hashCode * 59) + this.OpenCardUrl.GetHashCode();
                }
                if (this.SourceAppId != null)
                {
                    hashCode = (hashCode * 59) + this.SourceAppId.GetHashCode();
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
