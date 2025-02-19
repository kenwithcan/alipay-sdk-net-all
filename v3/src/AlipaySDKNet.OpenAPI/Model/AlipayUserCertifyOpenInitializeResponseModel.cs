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
    /// AlipayUserCertifyOpenInitializeResponseModel
    /// </summary>
    [DataContract(Name = "AlipayUserCertifyOpenInitializeResponseModel")]
    public partial class AlipayUserCertifyOpenInitializeResponseModel : IEquatable<AlipayUserCertifyOpenInitializeResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayUserCertifyOpenInitializeResponseModel" /> class.
        /// </summary>
        /// <param name="certifyId">本次申请操作的唯一标识，商户需要记录，后续的操作都需要用到.</param>
        public AlipayUserCertifyOpenInitializeResponseModel(string certifyId = default(string))
        {
            this.CertifyId = certifyId;
        }

        /// <summary>
        /// 本次申请操作的唯一标识，商户需要记录，后续的操作都需要用到
        /// </summary>
        /// <value>本次申请操作的唯一标识，商户需要记录，后续的操作都需要用到</value>
        [DataMember(Name = "certify_id", EmitDefaultValue = false)]
        public string CertifyId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayUserCertifyOpenInitializeResponseModel {\n");
            sb.Append("  CertifyId: ").Append(CertifyId).Append("\n");
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
            return this.Equals(input as AlipayUserCertifyOpenInitializeResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayUserCertifyOpenInitializeResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayUserCertifyOpenInitializeResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayUserCertifyOpenInitializeResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.CertifyId == input.CertifyId ||
                    (this.CertifyId != null &&
                    this.CertifyId.Equals(input.CertifyId))
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
                if (this.CertifyId != null)
                {
                    hashCode = (hashCode * 59) + this.CertifyId.GetHashCode();
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
