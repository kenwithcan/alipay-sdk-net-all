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
    /// SearchBoxBasicInfo
    /// </summary>
    [DataContract(Name = "SearchBoxBasicInfo")]
    public partial class SearchBoxBasicInfo : IEquatable<SearchBoxBasicInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SearchBoxBasicInfo" /> class.
        /// </summary>
        /// <param name="boxId">搜索直达配置id.</param>
        /// <param name="brandId">品牌id.</param>
        /// <param name="name">搜索直达名称.</param>
        /// <param name="status">搜索直达配置状态，INITIAL-初始/ONLINE-已上架/EXPIRE-已失效/OFFLINE-已下架.</param>
        /// <param name="targetAppid">小程序id.</param>
        public SearchBoxBasicInfo(string boxId = default(string), string brandId = default(string), string name = default(string), string status = default(string), string targetAppid = default(string))
        {
            this.BoxId = boxId;
            this.BrandId = brandId;
            this.Name = name;
            this.Status = status;
            this.TargetAppid = targetAppid;
        }

        /// <summary>
        /// 搜索直达配置id
        /// </summary>
        /// <value>搜索直达配置id</value>
        [DataMember(Name = "box_id", EmitDefaultValue = false)]
        public string BoxId { get; set; }

        /// <summary>
        /// 品牌id
        /// </summary>
        /// <value>品牌id</value>
        [DataMember(Name = "brand_id", EmitDefaultValue = false)]
        public string BrandId { get; set; }

        /// <summary>
        /// 搜索直达名称
        /// </summary>
        /// <value>搜索直达名称</value>
        [DataMember(Name = "name", EmitDefaultValue = false)]
        public string Name { get; set; }

        /// <summary>
        /// 搜索直达配置状态，INITIAL-初始/ONLINE-已上架/EXPIRE-已失效/OFFLINE-已下架
        /// </summary>
        /// <value>搜索直达配置状态，INITIAL-初始/ONLINE-已上架/EXPIRE-已失效/OFFLINE-已下架</value>
        [DataMember(Name = "status", EmitDefaultValue = false)]
        public string Status { get; set; }

        /// <summary>
        /// 小程序id
        /// </summary>
        /// <value>小程序id</value>
        [DataMember(Name = "target_appid", EmitDefaultValue = false)]
        public string TargetAppid { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class SearchBoxBasicInfo {\n");
            sb.Append("  BoxId: ").Append(BoxId).Append("\n");
            sb.Append("  BrandId: ").Append(BrandId).Append("\n");
            sb.Append("  Name: ").Append(Name).Append("\n");
            sb.Append("  Status: ").Append(Status).Append("\n");
            sb.Append("  TargetAppid: ").Append(TargetAppid).Append("\n");
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
            return this.Equals(input as SearchBoxBasicInfo);
        }

        /// <summary>
        /// Returns true if SearchBoxBasicInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of SearchBoxBasicInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(SearchBoxBasicInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.BoxId == input.BoxId ||
                    (this.BoxId != null &&
                    this.BoxId.Equals(input.BoxId))
                ) && 
                (
                    this.BrandId == input.BrandId ||
                    (this.BrandId != null &&
                    this.BrandId.Equals(input.BrandId))
                ) && 
                (
                    this.Name == input.Name ||
                    (this.Name != null &&
                    this.Name.Equals(input.Name))
                ) && 
                (
                    this.Status == input.Status ||
                    (this.Status != null &&
                    this.Status.Equals(input.Status))
                ) && 
                (
                    this.TargetAppid == input.TargetAppid ||
                    (this.TargetAppid != null &&
                    this.TargetAppid.Equals(input.TargetAppid))
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
                if (this.BoxId != null)
                {
                    hashCode = (hashCode * 59) + this.BoxId.GetHashCode();
                }
                if (this.BrandId != null)
                {
                    hashCode = (hashCode * 59) + this.BrandId.GetHashCode();
                }
                if (this.Name != null)
                {
                    hashCode = (hashCode * 59) + this.Name.GetHashCode();
                }
                if (this.Status != null)
                {
                    hashCode = (hashCode * 59) + this.Status.GetHashCode();
                }
                if (this.TargetAppid != null)
                {
                    hashCode = (hashCode * 59) + this.TargetAppid.GetHashCode();
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
