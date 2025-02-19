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
    /// AlipayOpenAppApiSceneQueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayOpenAppApiSceneQueryResponseModel")]
    public partial class AlipayOpenAppApiSceneQueryResponseModel : IEquatable<AlipayOpenAppApiSceneQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenAppApiSceneQueryResponseModel" /> class.
        /// </summary>
        /// <param name="authFieldScene">接口信息字段应用场景.</param>
        public AlipayOpenAppApiSceneQueryResponseModel(List<AuthFieldSceneDTO> authFieldScene = default(List<AuthFieldSceneDTO>))
        {
            this.AuthFieldScene = authFieldScene;
        }

        /// <summary>
        /// 接口信息字段应用场景
        /// </summary>
        /// <value>接口信息字段应用场景</value>
        [DataMember(Name = "auth_field_scene", EmitDefaultValue = false)]
        public List<AuthFieldSceneDTO> AuthFieldScene { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenAppApiSceneQueryResponseModel {\n");
            sb.Append("  AuthFieldScene: ").Append(AuthFieldScene).Append("\n");
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
            return this.Equals(input as AlipayOpenAppApiSceneQueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenAppApiSceneQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenAppApiSceneQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenAppApiSceneQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AuthFieldScene == input.AuthFieldScene ||
                    this.AuthFieldScene != null &&
                    input.AuthFieldScene != null &&
                    this.AuthFieldScene.SequenceEqual(input.AuthFieldScene)
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
                if (this.AuthFieldScene != null)
                {
                    hashCode = (hashCode * 59) + this.AuthFieldScene.GetHashCode();
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
