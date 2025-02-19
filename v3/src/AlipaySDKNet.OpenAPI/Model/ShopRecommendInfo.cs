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
    /// ShopRecommendInfo
    /// </summary>
    [DataContract(Name = "ShopRecommendInfo")]
    public partial class ShopRecommendInfo : IEquatable<ShopRecommendInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ShopRecommendInfo" /> class.
        /// </summary>
        /// <param name="recommend">门店修改建议.</param>
        /// <param name="recommendAddress">推荐详细地址.</param>
        /// <param name="recommendLatitude">推荐纬度，单位度.</param>
        /// <param name="recommendLongtitude">推荐经度，单位为度.</param>
        /// <param name="recommendName">推荐门店名称.</param>
        /// <param name="unconfidenceReason">门店不置信原因.</param>
        public ShopRecommendInfo(string recommend = default(string), string recommendAddress = default(string), string recommendLatitude = default(string), string recommendLongtitude = default(string), string recommendName = default(string), string unconfidenceReason = default(string))
        {
            this.Recommend = recommend;
            this.RecommendAddress = recommendAddress;
            this.RecommendLatitude = recommendLatitude;
            this.RecommendLongtitude = recommendLongtitude;
            this.RecommendName = recommendName;
            this.UnconfidenceReason = unconfidenceReason;
        }

        /// <summary>
        /// 门店修改建议
        /// </summary>
        /// <value>门店修改建议</value>
        [DataMember(Name = "recommend", EmitDefaultValue = false)]
        public string Recommend { get; set; }

        /// <summary>
        /// 推荐详细地址
        /// </summary>
        /// <value>推荐详细地址</value>
        [DataMember(Name = "recommend_address", EmitDefaultValue = false)]
        public string RecommendAddress { get; set; }

        /// <summary>
        /// 推荐纬度，单位度
        /// </summary>
        /// <value>推荐纬度，单位度</value>
        [DataMember(Name = "recommend_latitude", EmitDefaultValue = false)]
        public string RecommendLatitude { get; set; }

        /// <summary>
        /// 推荐经度，单位为度
        /// </summary>
        /// <value>推荐经度，单位为度</value>
        [DataMember(Name = "recommend_longtitude", EmitDefaultValue = false)]
        public string RecommendLongtitude { get; set; }

        /// <summary>
        /// 推荐门店名称
        /// </summary>
        /// <value>推荐门店名称</value>
        [DataMember(Name = "recommend_name", EmitDefaultValue = false)]
        public string RecommendName { get; set; }

        /// <summary>
        /// 门店不置信原因
        /// </summary>
        /// <value>门店不置信原因</value>
        [DataMember(Name = "unconfidence_reason", EmitDefaultValue = false)]
        public string UnconfidenceReason { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ShopRecommendInfo {\n");
            sb.Append("  Recommend: ").Append(Recommend).Append("\n");
            sb.Append("  RecommendAddress: ").Append(RecommendAddress).Append("\n");
            sb.Append("  RecommendLatitude: ").Append(RecommendLatitude).Append("\n");
            sb.Append("  RecommendLongtitude: ").Append(RecommendLongtitude).Append("\n");
            sb.Append("  RecommendName: ").Append(RecommendName).Append("\n");
            sb.Append("  UnconfidenceReason: ").Append(UnconfidenceReason).Append("\n");
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
            return this.Equals(input as ShopRecommendInfo);
        }

        /// <summary>
        /// Returns true if ShopRecommendInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of ShopRecommendInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ShopRecommendInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Recommend == input.Recommend ||
                    (this.Recommend != null &&
                    this.Recommend.Equals(input.Recommend))
                ) && 
                (
                    this.RecommendAddress == input.RecommendAddress ||
                    (this.RecommendAddress != null &&
                    this.RecommendAddress.Equals(input.RecommendAddress))
                ) && 
                (
                    this.RecommendLatitude == input.RecommendLatitude ||
                    (this.RecommendLatitude != null &&
                    this.RecommendLatitude.Equals(input.RecommendLatitude))
                ) && 
                (
                    this.RecommendLongtitude == input.RecommendLongtitude ||
                    (this.RecommendLongtitude != null &&
                    this.RecommendLongtitude.Equals(input.RecommendLongtitude))
                ) && 
                (
                    this.RecommendName == input.RecommendName ||
                    (this.RecommendName != null &&
                    this.RecommendName.Equals(input.RecommendName))
                ) && 
                (
                    this.UnconfidenceReason == input.UnconfidenceReason ||
                    (this.UnconfidenceReason != null &&
                    this.UnconfidenceReason.Equals(input.UnconfidenceReason))
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
                if (this.Recommend != null)
                {
                    hashCode = (hashCode * 59) + this.Recommend.GetHashCode();
                }
                if (this.RecommendAddress != null)
                {
                    hashCode = (hashCode * 59) + this.RecommendAddress.GetHashCode();
                }
                if (this.RecommendLatitude != null)
                {
                    hashCode = (hashCode * 59) + this.RecommendLatitude.GetHashCode();
                }
                if (this.RecommendLongtitude != null)
                {
                    hashCode = (hashCode * 59) + this.RecommendLongtitude.GetHashCode();
                }
                if (this.RecommendName != null)
                {
                    hashCode = (hashCode * 59) + this.RecommendName.GetHashCode();
                }
                if (this.UnconfidenceReason != null)
                {
                    hashCode = (hashCode * 59) + this.UnconfidenceReason.GetHashCode();
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
