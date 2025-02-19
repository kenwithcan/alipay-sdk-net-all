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
    /// PromotePagePropertyInstance
    /// </summary>
    [DataContract(Name = "PromotePagePropertyInstance")]
    public partial class PromotePagePropertyInstance : IEquatable<PromotePagePropertyInstance>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PromotePagePropertyInstance" /> class.
        /// </summary>
        /// <param name="key">留资属性key, 如: 1. principal_name: 商家名称 2. market_target_name: 营销目标 3. plan_name: 计划名称 4. plan_id: 计划id 5. group_name: 单元名称 6. group_id:  单元id 7. ad_name: 创意名称 8. creative_id: 创意id 9. click_id: 点击id 等.</param>
        /// <param name="name">留资属性名称.</param>
        /// <param name="type">自建站留资字段的类型.</param>
        /// <param name="value">留资属性实例值.</param>
        public PromotePagePropertyInstance(string key = default(string), string name = default(string), string type = default(string), string value = default(string))
        {
            this.Key = key;
            this.Name = name;
            this.Type = type;
            this.Value = value;
        }

        /// <summary>
        /// 留资属性key, 如: 1. principal_name: 商家名称 2. market_target_name: 营销目标 3. plan_name: 计划名称 4. plan_id: 计划id 5. group_name: 单元名称 6. group_id:  单元id 7. ad_name: 创意名称 8. creative_id: 创意id 9. click_id: 点击id 等
        /// </summary>
        /// <value>留资属性key, 如: 1. principal_name: 商家名称 2. market_target_name: 营销目标 3. plan_name: 计划名称 4. plan_id: 计划id 5. group_name: 单元名称 6. group_id:  单元id 7. ad_name: 创意名称 8. creative_id: 创意id 9. click_id: 点击id 等</value>
        [DataMember(Name = "key", EmitDefaultValue = false)]
        public string Key { get; set; }

        /// <summary>
        /// 留资属性名称
        /// </summary>
        /// <value>留资属性名称</value>
        [DataMember(Name = "name", EmitDefaultValue = false)]
        public string Name { get; set; }

        /// <summary>
        /// 自建站留资字段的类型
        /// </summary>
        /// <value>自建站留资字段的类型</value>
        [DataMember(Name = "type", EmitDefaultValue = false)]
        public string Type { get; set; }

        /// <summary>
        /// 留资属性实例值
        /// </summary>
        /// <value>留资属性实例值</value>
        [DataMember(Name = "value", EmitDefaultValue = false)]
        public string Value { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class PromotePagePropertyInstance {\n");
            sb.Append("  Key: ").Append(Key).Append("\n");
            sb.Append("  Name: ").Append(Name).Append("\n");
            sb.Append("  Type: ").Append(Type).Append("\n");
            sb.Append("  Value: ").Append(Value).Append("\n");
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
            return this.Equals(input as PromotePagePropertyInstance);
        }

        /// <summary>
        /// Returns true if PromotePagePropertyInstance instances are equal
        /// </summary>
        /// <param name="input">Instance of PromotePagePropertyInstance to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(PromotePagePropertyInstance input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Key == input.Key ||
                    (this.Key != null &&
                    this.Key.Equals(input.Key))
                ) && 
                (
                    this.Name == input.Name ||
                    (this.Name != null &&
                    this.Name.Equals(input.Name))
                ) && 
                (
                    this.Type == input.Type ||
                    (this.Type != null &&
                    this.Type.Equals(input.Type))
                ) && 
                (
                    this.Value == input.Value ||
                    (this.Value != null &&
                    this.Value.Equals(input.Value))
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
                if (this.Key != null)
                {
                    hashCode = (hashCode * 59) + this.Key.GetHashCode();
                }
                if (this.Name != null)
                {
                    hashCode = (hashCode * 59) + this.Name.GetHashCode();
                }
                if (this.Type != null)
                {
                    hashCode = (hashCode * 59) + this.Type.GetHashCode();
                }
                if (this.Value != null)
                {
                    hashCode = (hashCode * 59) + this.Value.GetHashCode();
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
