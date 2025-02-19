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
    /// AlipayMerchantLiveChannelQueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayMerchantLiveChannelQueryResponseModel")]
    public partial class AlipayMerchantLiveChannelQueryResponseModel : IEquatable<AlipayMerchantLiveChannelQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMerchantLiveChannelQueryResponseModel" /> class.
        /// </summary>
        /// <param name="channelContent">渠道内容，包含主播、文章的上游信息。字符串内容为Map，需要转换.</param>
        /// <param name="channelIdentity">渠道业务标识.</param>
        /// <param name="channelSecret">渠道密文.</param>
        /// <param name="channelType">渠道类型.</param>
        public AlipayMerchantLiveChannelQueryResponseModel(string channelContent = default(string), string channelIdentity = default(string), string channelSecret = default(string), string channelType = default(string))
        {
            this.ChannelContent = channelContent;
            this.ChannelIdentity = channelIdentity;
            this.ChannelSecret = channelSecret;
            this.ChannelType = channelType;
        }

        /// <summary>
        /// 渠道内容，包含主播、文章的上游信息。字符串内容为Map，需要转换
        /// </summary>
        /// <value>渠道内容，包含主播、文章的上游信息。字符串内容为Map，需要转换</value>
        [DataMember(Name = "channel_content", EmitDefaultValue = false)]
        public string ChannelContent { get; set; }

        /// <summary>
        /// 渠道业务标识
        /// </summary>
        /// <value>渠道业务标识</value>
        [DataMember(Name = "channel_identity", EmitDefaultValue = false)]
        public string ChannelIdentity { get; set; }

        /// <summary>
        /// 渠道密文
        /// </summary>
        /// <value>渠道密文</value>
        [DataMember(Name = "channel_secret", EmitDefaultValue = false)]
        public string ChannelSecret { get; set; }

        /// <summary>
        /// 渠道类型
        /// </summary>
        /// <value>渠道类型</value>
        [DataMember(Name = "channel_type", EmitDefaultValue = false)]
        public string ChannelType { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayMerchantLiveChannelQueryResponseModel {\n");
            sb.Append("  ChannelContent: ").Append(ChannelContent).Append("\n");
            sb.Append("  ChannelIdentity: ").Append(ChannelIdentity).Append("\n");
            sb.Append("  ChannelSecret: ").Append(ChannelSecret).Append("\n");
            sb.Append("  ChannelType: ").Append(ChannelType).Append("\n");
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
            return this.Equals(input as AlipayMerchantLiveChannelQueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayMerchantLiveChannelQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayMerchantLiveChannelQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayMerchantLiveChannelQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ChannelContent == input.ChannelContent ||
                    (this.ChannelContent != null &&
                    this.ChannelContent.Equals(input.ChannelContent))
                ) && 
                (
                    this.ChannelIdentity == input.ChannelIdentity ||
                    (this.ChannelIdentity != null &&
                    this.ChannelIdentity.Equals(input.ChannelIdentity))
                ) && 
                (
                    this.ChannelSecret == input.ChannelSecret ||
                    (this.ChannelSecret != null &&
                    this.ChannelSecret.Equals(input.ChannelSecret))
                ) && 
                (
                    this.ChannelType == input.ChannelType ||
                    (this.ChannelType != null &&
                    this.ChannelType.Equals(input.ChannelType))
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
                if (this.ChannelContent != null)
                {
                    hashCode = (hashCode * 59) + this.ChannelContent.GetHashCode();
                }
                if (this.ChannelIdentity != null)
                {
                    hashCode = (hashCode * 59) + this.ChannelIdentity.GetHashCode();
                }
                if (this.ChannelSecret != null)
                {
                    hashCode = (hashCode * 59) + this.ChannelSecret.GetHashCode();
                }
                if (this.ChannelType != null)
                {
                    hashCode = (hashCode * 59) + this.ChannelType.GetHashCode();
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
