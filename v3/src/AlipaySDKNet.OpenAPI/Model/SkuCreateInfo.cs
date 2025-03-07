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
    /// SkuCreateInfo
    /// </summary>
    [DataContract(Name = "SkuCreateInfo")]
    public partial class SkuCreateInfo : IEquatable<SkuCreateInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SkuCreateInfo" /> class.
        /// </summary>
        /// <param name="inventory">库存.</param>
        /// <param name="materialList">SKU素材列表（最多3个）.</param>
        /// <param name="originalPrice">标价，单位分.</param>
        /// <param name="price">售价，单位分.</param>
        /// <param name="propertyList">SKU属性列表.</param>
        public SkuCreateInfo(int inventory = default(int), List<MaterialCreateInfo> materialList = default(List<MaterialCreateInfo>), int originalPrice = default(int), int price = default(int), List<ItemSkuPropertyInfo> propertyList = default(List<ItemSkuPropertyInfo>))
        {
            this.Inventory = inventory;
            this.MaterialList = materialList;
            this.OriginalPrice = originalPrice;
            this.Price = price;
            this.PropertyList = propertyList;
        }

        /// <summary>
        /// 库存
        /// </summary>
        /// <value>库存</value>
        [DataMember(Name = "inventory", EmitDefaultValue = false)]
        public int Inventory { get; set; }

        /// <summary>
        /// SKU素材列表（最多3个）
        /// </summary>
        /// <value>SKU素材列表（最多3个）</value>
        [DataMember(Name = "material_list", EmitDefaultValue = false)]
        public List<MaterialCreateInfo> MaterialList { get; set; }

        /// <summary>
        /// 标价，单位分
        /// </summary>
        /// <value>标价，单位分</value>
        [DataMember(Name = "original_price", EmitDefaultValue = false)]
        public int OriginalPrice { get; set; }

        /// <summary>
        /// 售价，单位分
        /// </summary>
        /// <value>售价，单位分</value>
        [DataMember(Name = "price", EmitDefaultValue = false)]
        public int Price { get; set; }

        /// <summary>
        /// SKU属性列表
        /// </summary>
        /// <value>SKU属性列表</value>
        [DataMember(Name = "property_list", EmitDefaultValue = false)]
        public List<ItemSkuPropertyInfo> PropertyList { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class SkuCreateInfo {\n");
            sb.Append("  Inventory: ").Append(Inventory).Append("\n");
            sb.Append("  MaterialList: ").Append(MaterialList).Append("\n");
            sb.Append("  OriginalPrice: ").Append(OriginalPrice).Append("\n");
            sb.Append("  Price: ").Append(Price).Append("\n");
            sb.Append("  PropertyList: ").Append(PropertyList).Append("\n");
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
            return this.Equals(input as SkuCreateInfo);
        }

        /// <summary>
        /// Returns true if SkuCreateInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of SkuCreateInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(SkuCreateInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Inventory == input.Inventory ||
                    this.Inventory.Equals(input.Inventory)
                ) && 
                (
                    this.MaterialList == input.MaterialList ||
                    this.MaterialList != null &&
                    input.MaterialList != null &&
                    this.MaterialList.SequenceEqual(input.MaterialList)
                ) && 
                (
                    this.OriginalPrice == input.OriginalPrice ||
                    this.OriginalPrice.Equals(input.OriginalPrice)
                ) && 
                (
                    this.Price == input.Price ||
                    this.Price.Equals(input.Price)
                ) && 
                (
                    this.PropertyList == input.PropertyList ||
                    this.PropertyList != null &&
                    input.PropertyList != null &&
                    this.PropertyList.SequenceEqual(input.PropertyList)
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
                hashCode = (hashCode * 59) + this.Inventory.GetHashCode();
                if (this.MaterialList != null)
                {
                    hashCode = (hashCode * 59) + this.MaterialList.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.OriginalPrice.GetHashCode();
                hashCode = (hashCode * 59) + this.Price.GetHashCode();
                if (this.PropertyList != null)
                {
                    hashCode = (hashCode * 59) + this.PropertyList.GetHashCode();
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
