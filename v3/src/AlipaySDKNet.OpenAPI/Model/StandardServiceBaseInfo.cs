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
    /// StandardServiceBaseInfo
    /// </summary>
    [DataContract(Name = "StandardServiceBaseInfo")]
    public partial class StandardServiceBaseInfo : IEquatable<StandardServiceBaseInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="StandardServiceBaseInfo" /> class.
        /// </summary>
        /// <param name="bizStatus">服务状态.</param>
        /// <param name="categoryId">类目id.</param>
        /// <param name="serviceCode">服务code.</param>
        /// <param name="serviceName">服务名称.</param>
        public StandardServiceBaseInfo(string bizStatus = default(string), string categoryId = default(string), string serviceCode = default(string), string serviceName = default(string))
        {
            this.BizStatus = bizStatus;
            this.CategoryId = categoryId;
            this.ServiceCode = serviceCode;
            this.ServiceName = serviceName;
        }

        /// <summary>
        /// 服务状态
        /// </summary>
        /// <value>服务状态</value>
        [DataMember(Name = "biz_status", EmitDefaultValue = false)]
        public string BizStatus { get; set; }

        /// <summary>
        /// 类目id
        /// </summary>
        /// <value>类目id</value>
        [DataMember(Name = "category_id", EmitDefaultValue = false)]
        public string CategoryId { get; set; }

        /// <summary>
        /// 服务code
        /// </summary>
        /// <value>服务code</value>
        [DataMember(Name = "service_code", EmitDefaultValue = false)]
        public string ServiceCode { get; set; }

        /// <summary>
        /// 服务名称
        /// </summary>
        /// <value>服务名称</value>
        [DataMember(Name = "service_name", EmitDefaultValue = false)]
        public string ServiceName { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class StandardServiceBaseInfo {\n");
            sb.Append("  BizStatus: ").Append(BizStatus).Append("\n");
            sb.Append("  CategoryId: ").Append(CategoryId).Append("\n");
            sb.Append("  ServiceCode: ").Append(ServiceCode).Append("\n");
            sb.Append("  ServiceName: ").Append(ServiceName).Append("\n");
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
            return this.Equals(input as StandardServiceBaseInfo);
        }

        /// <summary>
        /// Returns true if StandardServiceBaseInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of StandardServiceBaseInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(StandardServiceBaseInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.BizStatus == input.BizStatus ||
                    (this.BizStatus != null &&
                    this.BizStatus.Equals(input.BizStatus))
                ) && 
                (
                    this.CategoryId == input.CategoryId ||
                    (this.CategoryId != null &&
                    this.CategoryId.Equals(input.CategoryId))
                ) && 
                (
                    this.ServiceCode == input.ServiceCode ||
                    (this.ServiceCode != null &&
                    this.ServiceCode.Equals(input.ServiceCode))
                ) && 
                (
                    this.ServiceName == input.ServiceName ||
                    (this.ServiceName != null &&
                    this.ServiceName.Equals(input.ServiceName))
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
                if (this.BizStatus != null)
                {
                    hashCode = (hashCode * 59) + this.BizStatus.GetHashCode();
                }
                if (this.CategoryId != null)
                {
                    hashCode = (hashCode * 59) + this.CategoryId.GetHashCode();
                }
                if (this.ServiceCode != null)
                {
                    hashCode = (hashCode * 59) + this.ServiceCode.GetHashCode();
                }
                if (this.ServiceName != null)
                {
                    hashCode = (hashCode * 59) + this.ServiceName.GetHashCode();
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
