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
    /// VoucherValidPeriod
    /// </summary>
    [DataContract(Name = "VoucherValidPeriod")]
    public partial class VoucherValidPeriod : IEquatable<VoucherValidPeriod>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="VoucherValidPeriod" /> class.
        /// </summary>
        /// <param name="type">券有效期类型.</param>
        /// <param name="validBeginTime">券可使用的开始时间。格式为：yyyy-MM-dd HH:mm:ss.</param>
        /// <param name="validDaysAfterReceive">券生效后N天内可以使用。可以配合wait_days_after_receive字段使用。.</param>
        /// <param name="validEndTime">券可使用的结束时间。格式为yyyy-MM-dd HH:mm:ss.</param>
        /// <param name="waitDaysAfterReceive">用户领券后需要等待N天，券才可以生效。如果该字段填入0或者不填写，则用户领券后立刻生效。.</param>
        public VoucherValidPeriod(string type = default(string), string validBeginTime = default(string), int validDaysAfterReceive = default(int), string validEndTime = default(string), int waitDaysAfterReceive = default(int))
        {
            this.Type = type;
            this.ValidBeginTime = validBeginTime;
            this.ValidDaysAfterReceive = validDaysAfterReceive;
            this.ValidEndTime = validEndTime;
            this.WaitDaysAfterReceive = waitDaysAfterReceive;
        }

        /// <summary>
        /// 券有效期类型
        /// </summary>
        /// <value>券有效期类型</value>
        [DataMember(Name = "type", EmitDefaultValue = false)]
        public string Type { get; set; }

        /// <summary>
        /// 券可使用的开始时间。格式为：yyyy-MM-dd HH:mm:ss
        /// </summary>
        /// <value>券可使用的开始时间。格式为：yyyy-MM-dd HH:mm:ss</value>
        [DataMember(Name = "valid_begin_time", EmitDefaultValue = false)]
        public string ValidBeginTime { get; set; }

        /// <summary>
        /// 券生效后N天内可以使用。可以配合wait_days_after_receive字段使用。
        /// </summary>
        /// <value>券生效后N天内可以使用。可以配合wait_days_after_receive字段使用。</value>
        [DataMember(Name = "valid_days_after_receive", EmitDefaultValue = false)]
        public int ValidDaysAfterReceive { get; set; }

        /// <summary>
        /// 券可使用的结束时间。格式为yyyy-MM-dd HH:mm:ss
        /// </summary>
        /// <value>券可使用的结束时间。格式为yyyy-MM-dd HH:mm:ss</value>
        [DataMember(Name = "valid_end_time", EmitDefaultValue = false)]
        public string ValidEndTime { get; set; }

        /// <summary>
        /// 用户领券后需要等待N天，券才可以生效。如果该字段填入0或者不填写，则用户领券后立刻生效。
        /// </summary>
        /// <value>用户领券后需要等待N天，券才可以生效。如果该字段填入0或者不填写，则用户领券后立刻生效。</value>
        [DataMember(Name = "wait_days_after_receive", EmitDefaultValue = false)]
        public int WaitDaysAfterReceive { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class VoucherValidPeriod {\n");
            sb.Append("  Type: ").Append(Type).Append("\n");
            sb.Append("  ValidBeginTime: ").Append(ValidBeginTime).Append("\n");
            sb.Append("  ValidDaysAfterReceive: ").Append(ValidDaysAfterReceive).Append("\n");
            sb.Append("  ValidEndTime: ").Append(ValidEndTime).Append("\n");
            sb.Append("  WaitDaysAfterReceive: ").Append(WaitDaysAfterReceive).Append("\n");
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
            return this.Equals(input as VoucherValidPeriod);
        }

        /// <summary>
        /// Returns true if VoucherValidPeriod instances are equal
        /// </summary>
        /// <param name="input">Instance of VoucherValidPeriod to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(VoucherValidPeriod input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Type == input.Type ||
                    (this.Type != null &&
                    this.Type.Equals(input.Type))
                ) && 
                (
                    this.ValidBeginTime == input.ValidBeginTime ||
                    (this.ValidBeginTime != null &&
                    this.ValidBeginTime.Equals(input.ValidBeginTime))
                ) && 
                (
                    this.ValidDaysAfterReceive == input.ValidDaysAfterReceive ||
                    this.ValidDaysAfterReceive.Equals(input.ValidDaysAfterReceive)
                ) && 
                (
                    this.ValidEndTime == input.ValidEndTime ||
                    (this.ValidEndTime != null &&
                    this.ValidEndTime.Equals(input.ValidEndTime))
                ) && 
                (
                    this.WaitDaysAfterReceive == input.WaitDaysAfterReceive ||
                    this.WaitDaysAfterReceive.Equals(input.WaitDaysAfterReceive)
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
                if (this.Type != null)
                {
                    hashCode = (hashCode * 59) + this.Type.GetHashCode();
                }
                if (this.ValidBeginTime != null)
                {
                    hashCode = (hashCode * 59) + this.ValidBeginTime.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.ValidDaysAfterReceive.GetHashCode();
                if (this.ValidEndTime != null)
                {
                    hashCode = (hashCode * 59) + this.ValidEndTime.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.WaitDaysAfterReceive.GetHashCode();
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
