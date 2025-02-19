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
    /// AlipayOpenMiniResourcePromotionsourceNotifyModel
    /// </summary>
    [DataContract(Name = "AlipayOpenMiniResourcePromotionsourceNotifyModel")]
    public partial class AlipayOpenMiniResourcePromotionsourceNotifyModel : IEquatable<AlipayOpenMiniResourcePromotionsourceNotifyModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenMiniResourcePromotionsourceNotifyModel" /> class.
        /// </summary>
        /// <param name="authorId">媒体唤起时传入的支付宝id.</param>
        /// <param name="_params">媒体唤起时提供的额外参数值列表，这里可能有多个值，打平以后拼入。即url_decode(authcbparams).</param>
        /// <param name="promotionId">推广位id.</param>
        /// <param name="promotionName">推广位名称.</param>
        /// <param name="source">媒体来源，标识调用方.</param>
        public AlipayOpenMiniResourcePromotionsourceNotifyModel(string authorId = default(string), string _params = default(string), string promotionId = default(string), string promotionName = default(string), string source = default(string))
        {
            this.AuthorId = authorId;
            this.Params = _params;
            this.PromotionId = promotionId;
            this.PromotionName = promotionName;
            this.Source = source;
        }

        /// <summary>
        /// 媒体唤起时传入的支付宝id
        /// </summary>
        /// <value>媒体唤起时传入的支付宝id</value>
        [DataMember(Name = "author_id", EmitDefaultValue = false)]
        public string AuthorId { get; set; }

        /// <summary>
        /// 媒体唤起时提供的额外参数值列表，这里可能有多个值，打平以后拼入。即url_decode(authcbparams)
        /// </summary>
        /// <value>媒体唤起时提供的额外参数值列表，这里可能有多个值，打平以后拼入。即url_decode(authcbparams)</value>
        [DataMember(Name = "params", EmitDefaultValue = false)]
        public string Params { get; set; }

        /// <summary>
        /// 推广位id
        /// </summary>
        /// <value>推广位id</value>
        [DataMember(Name = "promotion_id", EmitDefaultValue = false)]
        public string PromotionId { get; set; }

        /// <summary>
        /// 推广位名称
        /// </summary>
        /// <value>推广位名称</value>
        [DataMember(Name = "promotion_name", EmitDefaultValue = false)]
        public string PromotionName { get; set; }

        /// <summary>
        /// 媒体来源，标识调用方
        /// </summary>
        /// <value>媒体来源，标识调用方</value>
        [DataMember(Name = "source", EmitDefaultValue = false)]
        public string Source { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenMiniResourcePromotionsourceNotifyModel {\n");
            sb.Append("  AuthorId: ").Append(AuthorId).Append("\n");
            sb.Append("  Params: ").Append(Params).Append("\n");
            sb.Append("  PromotionId: ").Append(PromotionId).Append("\n");
            sb.Append("  PromotionName: ").Append(PromotionName).Append("\n");
            sb.Append("  Source: ").Append(Source).Append("\n");
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
            return this.Equals(input as AlipayOpenMiniResourcePromotionsourceNotifyModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenMiniResourcePromotionsourceNotifyModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenMiniResourcePromotionsourceNotifyModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenMiniResourcePromotionsourceNotifyModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AuthorId == input.AuthorId ||
                    (this.AuthorId != null &&
                    this.AuthorId.Equals(input.AuthorId))
                ) && 
                (
                    this.Params == input.Params ||
                    (this.Params != null &&
                    this.Params.Equals(input.Params))
                ) && 
                (
                    this.PromotionId == input.PromotionId ||
                    (this.PromotionId != null &&
                    this.PromotionId.Equals(input.PromotionId))
                ) && 
                (
                    this.PromotionName == input.PromotionName ||
                    (this.PromotionName != null &&
                    this.PromotionName.Equals(input.PromotionName))
                ) && 
                (
                    this.Source == input.Source ||
                    (this.Source != null &&
                    this.Source.Equals(input.Source))
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
                if (this.AuthorId != null)
                {
                    hashCode = (hashCode * 59) + this.AuthorId.GetHashCode();
                }
                if (this.Params != null)
                {
                    hashCode = (hashCode * 59) + this.Params.GetHashCode();
                }
                if (this.PromotionId != null)
                {
                    hashCode = (hashCode * 59) + this.PromotionId.GetHashCode();
                }
                if (this.PromotionName != null)
                {
                    hashCode = (hashCode * 59) + this.PromotionName.GetHashCode();
                }
                if (this.Source != null)
                {
                    hashCode = (hashCode * 59) + this.Source.GetHashCode();
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
