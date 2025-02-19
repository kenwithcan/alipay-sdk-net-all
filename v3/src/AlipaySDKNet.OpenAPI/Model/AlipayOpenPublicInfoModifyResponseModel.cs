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
    /// AlipayOpenPublicInfoModifyResponseModel
    /// </summary>
    [DataContract(Name = "AlipayOpenPublicInfoModifyResponseModel")]
    public partial class AlipayOpenPublicInfoModifyResponseModel : IEquatable<AlipayOpenPublicInfoModifyResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenPublicInfoModifyResponseModel" /> class.
        /// </summary>
        /// <param name="auditDesc">服务窗审核状态描述.</param>
        /// <param name="auditStatus">服务窗审核状态，申请成功后返回AUDITING，等待风控审核.</param>
        public AlipayOpenPublicInfoModifyResponseModel(string auditDesc = default(string), string auditStatus = default(string))
        {
            this.AuditDesc = auditDesc;
            this.AuditStatus = auditStatus;
        }

        /// <summary>
        /// 服务窗审核状态描述
        /// </summary>
        /// <value>服务窗审核状态描述</value>
        [DataMember(Name = "audit_desc", EmitDefaultValue = false)]
        public string AuditDesc { get; set; }

        /// <summary>
        /// 服务窗审核状态，申请成功后返回AUDITING，等待风控审核
        /// </summary>
        /// <value>服务窗审核状态，申请成功后返回AUDITING，等待风控审核</value>
        [DataMember(Name = "audit_status", EmitDefaultValue = false)]
        public string AuditStatus { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenPublicInfoModifyResponseModel {\n");
            sb.Append("  AuditDesc: ").Append(AuditDesc).Append("\n");
            sb.Append("  AuditStatus: ").Append(AuditStatus).Append("\n");
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
            return this.Equals(input as AlipayOpenPublicInfoModifyResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenPublicInfoModifyResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenPublicInfoModifyResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenPublicInfoModifyResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AuditDesc == input.AuditDesc ||
                    (this.AuditDesc != null &&
                    this.AuditDesc.Equals(input.AuditDesc))
                ) && 
                (
                    this.AuditStatus == input.AuditStatus ||
                    (this.AuditStatus != null &&
                    this.AuditStatus.Equals(input.AuditStatus))
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
                if (this.AuditDesc != null)
                {
                    hashCode = (hashCode * 59) + this.AuditDesc.GetHashCode();
                }
                if (this.AuditStatus != null)
                {
                    hashCode = (hashCode * 59) + this.AuditStatus.GetHashCode();
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
