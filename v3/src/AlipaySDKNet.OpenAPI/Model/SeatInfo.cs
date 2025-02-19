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
    /// SeatInfo
    /// </summary>
    [DataContract(Name = "SeatInfo")]
    public partial class SeatInfo : IEquatable<SeatInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SeatInfo" /> class.
        /// </summary>
        /// <param name="seatClass">座位等级.</param>
        /// <param name="seatNo">座位号.</param>
        public SeatInfo(string seatClass = default(string), string seatNo = default(string))
        {
            this.SeatClass = seatClass;
            this.SeatNo = seatNo;
        }

        /// <summary>
        /// 座位等级
        /// </summary>
        /// <value>座位等级</value>
        [DataMember(Name = "seat_class", EmitDefaultValue = false)]
        public string SeatClass { get; set; }

        /// <summary>
        /// 座位号
        /// </summary>
        /// <value>座位号</value>
        [DataMember(Name = "seat_no", EmitDefaultValue = false)]
        public string SeatNo { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class SeatInfo {\n");
            sb.Append("  SeatClass: ").Append(SeatClass).Append("\n");
            sb.Append("  SeatNo: ").Append(SeatNo).Append("\n");
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
            return this.Equals(input as SeatInfo);
        }

        /// <summary>
        /// Returns true if SeatInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of SeatInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(SeatInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.SeatClass == input.SeatClass ||
                    (this.SeatClass != null &&
                    this.SeatClass.Equals(input.SeatClass))
                ) && 
                (
                    this.SeatNo == input.SeatNo ||
                    (this.SeatNo != null &&
                    this.SeatNo.Equals(input.SeatNo))
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
                if (this.SeatClass != null)
                {
                    hashCode = (hashCode * 59) + this.SeatClass.GetHashCode();
                }
                if (this.SeatNo != null)
                {
                    hashCode = (hashCode * 59) + this.SeatNo.GetHashCode();
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
