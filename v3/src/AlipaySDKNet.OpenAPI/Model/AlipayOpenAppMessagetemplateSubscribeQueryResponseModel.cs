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
    /// AlipayOpenAppMessagetemplateSubscribeQueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayOpenAppMessagetemplateSubscribeQueryResponseModel")]
    public partial class AlipayOpenAppMessagetemplateSubscribeQueryResponseModel : IEquatable<AlipayOpenAppMessagetemplateSubscribeQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenAppMessagetemplateSubscribeQueryResponseModel" /> class.
        /// </summary>
        /// <param name="showComponent">是否显示订阅组件.</param>
        /// <param name="subscribeRelations">用户对消息模板的订阅关系列表，为入参中的用户id对消息模板id的订阅关系。 限制：用户未订阅消息，该参数不返回。.</param>
        public AlipayOpenAppMessagetemplateSubscribeQueryResponseModel(bool showComponent = default(bool), List<SubscribeRelation> subscribeRelations = default(List<SubscribeRelation>))
        {
            this.ShowComponent = showComponent;
            this.SubscribeRelations = subscribeRelations;
        }

        /// <summary>
        /// 是否显示订阅组件
        /// </summary>
        /// <value>是否显示订阅组件</value>
        [DataMember(Name = "show_component", EmitDefaultValue = true)]
        public bool ShowComponent { get; set; }

        /// <summary>
        /// 用户对消息模板的订阅关系列表，为入参中的用户id对消息模板id的订阅关系。 限制：用户未订阅消息，该参数不返回。
        /// </summary>
        /// <value>用户对消息模板的订阅关系列表，为入参中的用户id对消息模板id的订阅关系。 限制：用户未订阅消息，该参数不返回。</value>
        [DataMember(Name = "subscribe_relations", EmitDefaultValue = false)]
        public List<SubscribeRelation> SubscribeRelations { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenAppMessagetemplateSubscribeQueryResponseModel {\n");
            sb.Append("  ShowComponent: ").Append(ShowComponent).Append("\n");
            sb.Append("  SubscribeRelations: ").Append(SubscribeRelations).Append("\n");
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
            return this.Equals(input as AlipayOpenAppMessagetemplateSubscribeQueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenAppMessagetemplateSubscribeQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenAppMessagetemplateSubscribeQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenAppMessagetemplateSubscribeQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ShowComponent == input.ShowComponent ||
                    this.ShowComponent.Equals(input.ShowComponent)
                ) && 
                (
                    this.SubscribeRelations == input.SubscribeRelations ||
                    this.SubscribeRelations != null &&
                    input.SubscribeRelations != null &&
                    this.SubscribeRelations.SequenceEqual(input.SubscribeRelations)
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
                hashCode = (hashCode * 59) + this.ShowComponent.GetHashCode();
                if (this.SubscribeRelations != null)
                {
                    hashCode = (hashCode * 59) + this.SubscribeRelations.GetHashCode();
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
