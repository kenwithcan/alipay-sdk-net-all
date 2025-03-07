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
    /// SpuDetail
    /// </summary>
    [DataContract(Name = "SpuDetail")]
    public partial class SpuDetail : IEquatable<SpuDetail>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SpuDetail" /> class.
        /// </summary>
        /// <param name="brand">商品品牌.</param>
        /// <param name="category">商品类目.</param>
        /// <param name="dimension">商品规格.</param>
        /// <param name="icon">商品图片地址.</param>
        /// <param name="linkUrl">商品链接.</param>
        /// <param name="spuId">商品ID.</param>
        /// <param name="title">商品名称.</param>
        public SpuDetail(string brand = default(string), string category = default(string), string dimension = default(string), string icon = default(string), string linkUrl = default(string), string spuId = default(string), string title = default(string))
        {
            this.Brand = brand;
            this.Category = category;
            this.Dimension = dimension;
            this.Icon = icon;
            this.LinkUrl = linkUrl;
            this.SpuId = spuId;
            this.Title = title;
        }

        /// <summary>
        /// 商品品牌
        /// </summary>
        /// <value>商品品牌</value>
        [DataMember(Name = "brand", EmitDefaultValue = false)]
        public string Brand { get; set; }

        /// <summary>
        /// 商品类目
        /// </summary>
        /// <value>商品类目</value>
        [DataMember(Name = "category", EmitDefaultValue = false)]
        public string Category { get; set; }

        /// <summary>
        /// 商品规格
        /// </summary>
        /// <value>商品规格</value>
        [DataMember(Name = "dimension", EmitDefaultValue = false)]
        public string Dimension { get; set; }

        /// <summary>
        /// 商品图片地址
        /// </summary>
        /// <value>商品图片地址</value>
        [DataMember(Name = "icon", EmitDefaultValue = false)]
        public string Icon { get; set; }

        /// <summary>
        /// 商品链接
        /// </summary>
        /// <value>商品链接</value>
        [DataMember(Name = "link_url", EmitDefaultValue = false)]
        public string LinkUrl { get; set; }

        /// <summary>
        /// 商品ID
        /// </summary>
        /// <value>商品ID</value>
        [DataMember(Name = "spu_id", EmitDefaultValue = false)]
        public string SpuId { get; set; }

        /// <summary>
        /// 商品名称
        /// </summary>
        /// <value>商品名称</value>
        [DataMember(Name = "title", EmitDefaultValue = false)]
        public string Title { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class SpuDetail {\n");
            sb.Append("  Brand: ").Append(Brand).Append("\n");
            sb.Append("  Category: ").Append(Category).Append("\n");
            sb.Append("  Dimension: ").Append(Dimension).Append("\n");
            sb.Append("  Icon: ").Append(Icon).Append("\n");
            sb.Append("  LinkUrl: ").Append(LinkUrl).Append("\n");
            sb.Append("  SpuId: ").Append(SpuId).Append("\n");
            sb.Append("  Title: ").Append(Title).Append("\n");
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
            return this.Equals(input as SpuDetail);
        }

        /// <summary>
        /// Returns true if SpuDetail instances are equal
        /// </summary>
        /// <param name="input">Instance of SpuDetail to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(SpuDetail input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Brand == input.Brand ||
                    (this.Brand != null &&
                    this.Brand.Equals(input.Brand))
                ) && 
                (
                    this.Category == input.Category ||
                    (this.Category != null &&
                    this.Category.Equals(input.Category))
                ) && 
                (
                    this.Dimension == input.Dimension ||
                    (this.Dimension != null &&
                    this.Dimension.Equals(input.Dimension))
                ) && 
                (
                    this.Icon == input.Icon ||
                    (this.Icon != null &&
                    this.Icon.Equals(input.Icon))
                ) && 
                (
                    this.LinkUrl == input.LinkUrl ||
                    (this.LinkUrl != null &&
                    this.LinkUrl.Equals(input.LinkUrl))
                ) && 
                (
                    this.SpuId == input.SpuId ||
                    (this.SpuId != null &&
                    this.SpuId.Equals(input.SpuId))
                ) && 
                (
                    this.Title == input.Title ||
                    (this.Title != null &&
                    this.Title.Equals(input.Title))
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
                if (this.Brand != null)
                {
                    hashCode = (hashCode * 59) + this.Brand.GetHashCode();
                }
                if (this.Category != null)
                {
                    hashCode = (hashCode * 59) + this.Category.GetHashCode();
                }
                if (this.Dimension != null)
                {
                    hashCode = (hashCode * 59) + this.Dimension.GetHashCode();
                }
                if (this.Icon != null)
                {
                    hashCode = (hashCode * 59) + this.Icon.GetHashCode();
                }
                if (this.LinkUrl != null)
                {
                    hashCode = (hashCode * 59) + this.LinkUrl.GetHashCode();
                }
                if (this.SpuId != null)
                {
                    hashCode = (hashCode * 59) + this.SpuId.GetHashCode();
                }
                if (this.Title != null)
                {
                    hashCode = (hashCode * 59) + this.Title.GetHashCode();
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
