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
    /// SearchBoxServiceModule
    /// </summary>
    [DataContract(Name = "SearchBoxServiceModule")]
    public partial class SearchBoxServiceModule : IEquatable<SearchBoxServiceModule>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SearchBoxServiceModule" /> class.
        /// </summary>
        /// <param name="moduleId">模块配置ID.</param>
        /// <param name="moduleType">搜索直达模块类型.</param>
        /// <param name="serviceInfos">服务信息列表.</param>
        public SearchBoxServiceModule(string moduleId = default(string), string moduleType = default(string), List<SearchBoxServiceInfo> serviceInfos = default(List<SearchBoxServiceInfo>))
        {
            this.ModuleId = moduleId;
            this.ModuleType = moduleType;
            this.ServiceInfos = serviceInfos;
        }

        /// <summary>
        /// 模块配置ID
        /// </summary>
        /// <value>模块配置ID</value>
        [DataMember(Name = "module_id", EmitDefaultValue = false)]
        public string ModuleId { get; set; }

        /// <summary>
        /// 搜索直达模块类型
        /// </summary>
        /// <value>搜索直达模块类型</value>
        [DataMember(Name = "module_type", EmitDefaultValue = false)]
        public string ModuleType { get; set; }

        /// <summary>
        /// 服务信息列表
        /// </summary>
        /// <value>服务信息列表</value>
        [DataMember(Name = "service_infos", EmitDefaultValue = false)]
        public List<SearchBoxServiceInfo> ServiceInfos { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class SearchBoxServiceModule {\n");
            sb.Append("  ModuleId: ").Append(ModuleId).Append("\n");
            sb.Append("  ModuleType: ").Append(ModuleType).Append("\n");
            sb.Append("  ServiceInfos: ").Append(ServiceInfos).Append("\n");
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
            return this.Equals(input as SearchBoxServiceModule);
        }

        /// <summary>
        /// Returns true if SearchBoxServiceModule instances are equal
        /// </summary>
        /// <param name="input">Instance of SearchBoxServiceModule to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(SearchBoxServiceModule input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ModuleId == input.ModuleId ||
                    (this.ModuleId != null &&
                    this.ModuleId.Equals(input.ModuleId))
                ) && 
                (
                    this.ModuleType == input.ModuleType ||
                    (this.ModuleType != null &&
                    this.ModuleType.Equals(input.ModuleType))
                ) && 
                (
                    this.ServiceInfos == input.ServiceInfos ||
                    this.ServiceInfos != null &&
                    input.ServiceInfos != null &&
                    this.ServiceInfos.SequenceEqual(input.ServiceInfos)
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
                if (this.ModuleId != null)
                {
                    hashCode = (hashCode * 59) + this.ModuleId.GetHashCode();
                }
                if (this.ModuleType != null)
                {
                    hashCode = (hashCode * 59) + this.ModuleType.GetHashCode();
                }
                if (this.ServiceInfos != null)
                {
                    hashCode = (hashCode * 59) + this.ServiceInfos.GetHashCode();
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
