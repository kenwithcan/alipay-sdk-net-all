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
    /// ConsumerNotifyIstd
    /// </summary>
    [DataContract(Name = "ConsumerNotifyIstd")]
    public partial class ConsumerNotifyIstd : IEquatable<ConsumerNotifyIstd>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ConsumerNotifyIstd" /> class.
        /// </summary>
        /// <param name="goodsCount">商品数量.</param>
        /// <param name="goodsImg">商品缩略图url，支持格式：bmp、jpg、jpeg、png、gif.</param>
        /// <param name="goodsName">商品名称.</param>
        /// <param name="merchantMobile">商家电话.</param>
        /// <param name="merchantName">商家名称，tiny_app_id和merchant_name不能同时为空.</param>
        /// <param name="tinyAppId">商家小程序appid.</param>
        /// <param name="tinyAppUrl">商家小程序的路径，建议为订单页面.</param>
        public ConsumerNotifyIstd(int goodsCount = default(int), string goodsImg = default(string), string goodsName = default(string), string merchantMobile = default(string), string merchantName = default(string), string tinyAppId = default(string), string tinyAppUrl = default(string))
        {
            this.GoodsCount = goodsCount;
            this.GoodsImg = goodsImg;
            this.GoodsName = goodsName;
            this.MerchantMobile = merchantMobile;
            this.MerchantName = merchantName;
            this.TinyAppId = tinyAppId;
            this.TinyAppUrl = tinyAppUrl;
        }

        /// <summary>
        /// 商品数量
        /// </summary>
        /// <value>商品数量</value>
        [DataMember(Name = "goods_count", EmitDefaultValue = false)]
        public int GoodsCount { get; set; }

        /// <summary>
        /// 商品缩略图url，支持格式：bmp、jpg、jpeg、png、gif
        /// </summary>
        /// <value>商品缩略图url，支持格式：bmp、jpg、jpeg、png、gif</value>
        [DataMember(Name = "goods_img", EmitDefaultValue = false)]
        public string GoodsImg { get; set; }

        /// <summary>
        /// 商品名称
        /// </summary>
        /// <value>商品名称</value>
        [DataMember(Name = "goods_name", EmitDefaultValue = false)]
        public string GoodsName { get; set; }

        /// <summary>
        /// 商家电话
        /// </summary>
        /// <value>商家电话</value>
        [DataMember(Name = "merchant_mobile", EmitDefaultValue = false)]
        public string MerchantMobile { get; set; }

        /// <summary>
        /// 商家名称，tiny_app_id和merchant_name不能同时为空
        /// </summary>
        /// <value>商家名称，tiny_app_id和merchant_name不能同时为空</value>
        [DataMember(Name = "merchant_name", EmitDefaultValue = false)]
        public string MerchantName { get; set; }

        /// <summary>
        /// 商家小程序appid
        /// </summary>
        /// <value>商家小程序appid</value>
        [DataMember(Name = "tiny_app_id", EmitDefaultValue = false)]
        public string TinyAppId { get; set; }

        /// <summary>
        /// 商家小程序的路径，建议为订单页面
        /// </summary>
        /// <value>商家小程序的路径，建议为订单页面</value>
        [DataMember(Name = "tiny_app_url", EmitDefaultValue = false)]
        public string TinyAppUrl { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ConsumerNotifyIstd {\n");
            sb.Append("  GoodsCount: ").Append(GoodsCount).Append("\n");
            sb.Append("  GoodsImg: ").Append(GoodsImg).Append("\n");
            sb.Append("  GoodsName: ").Append(GoodsName).Append("\n");
            sb.Append("  MerchantMobile: ").Append(MerchantMobile).Append("\n");
            sb.Append("  MerchantName: ").Append(MerchantName).Append("\n");
            sb.Append("  TinyAppId: ").Append(TinyAppId).Append("\n");
            sb.Append("  TinyAppUrl: ").Append(TinyAppUrl).Append("\n");
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
            return this.Equals(input as ConsumerNotifyIstd);
        }

        /// <summary>
        /// Returns true if ConsumerNotifyIstd instances are equal
        /// </summary>
        /// <param name="input">Instance of ConsumerNotifyIstd to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ConsumerNotifyIstd input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.GoodsCount == input.GoodsCount ||
                    this.GoodsCount.Equals(input.GoodsCount)
                ) && 
                (
                    this.GoodsImg == input.GoodsImg ||
                    (this.GoodsImg != null &&
                    this.GoodsImg.Equals(input.GoodsImg))
                ) && 
                (
                    this.GoodsName == input.GoodsName ||
                    (this.GoodsName != null &&
                    this.GoodsName.Equals(input.GoodsName))
                ) && 
                (
                    this.MerchantMobile == input.MerchantMobile ||
                    (this.MerchantMobile != null &&
                    this.MerchantMobile.Equals(input.MerchantMobile))
                ) && 
                (
                    this.MerchantName == input.MerchantName ||
                    (this.MerchantName != null &&
                    this.MerchantName.Equals(input.MerchantName))
                ) && 
                (
                    this.TinyAppId == input.TinyAppId ||
                    (this.TinyAppId != null &&
                    this.TinyAppId.Equals(input.TinyAppId))
                ) && 
                (
                    this.TinyAppUrl == input.TinyAppUrl ||
                    (this.TinyAppUrl != null &&
                    this.TinyAppUrl.Equals(input.TinyAppUrl))
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
                hashCode = (hashCode * 59) + this.GoodsCount.GetHashCode();
                if (this.GoodsImg != null)
                {
                    hashCode = (hashCode * 59) + this.GoodsImg.GetHashCode();
                }
                if (this.GoodsName != null)
                {
                    hashCode = (hashCode * 59) + this.GoodsName.GetHashCode();
                }
                if (this.MerchantMobile != null)
                {
                    hashCode = (hashCode * 59) + this.MerchantMobile.GetHashCode();
                }
                if (this.MerchantName != null)
                {
                    hashCode = (hashCode * 59) + this.MerchantName.GetHashCode();
                }
                if (this.TinyAppId != null)
                {
                    hashCode = (hashCode * 59) + this.TinyAppId.GetHashCode();
                }
                if (this.TinyAppUrl != null)
                {
                    hashCode = (hashCode * 59) + this.TinyAppUrl.GetHashCode();
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
